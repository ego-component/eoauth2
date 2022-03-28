package ssostorage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ego-component/eoauth2/server"
	"github.com/ego-component/eoauth2/storage/dao"
	"github.com/ego-component/eoauth2/storage/dto"
	"github.com/gotomicro/ego-component/egorm"
	"github.com/gotomicro/ego-component/eredis"
	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/cast"
)

type Storage struct {
	db          *egorm.Component
	logger      *elog.Component
	tokenServer *tokenServer
	config      *config
	redis       *eredis.Component
}

// NewStorage returns a new redis Storage instance.
func NewStorage(db *egorm.Component, redis *eredis.Component, logger *elog.Component, options ...Option) *Storage {
	container := &Storage{
		db:     db,
		logger: logger,
		config: defaultConfig(),
	}
	for _, option := range options {
		option(container)
	}
	tSrv := initTokenServer(container.config, redis)
	container.tokenServer = tSrv
	container.redis = redis
	return container
}

// Clone the Storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *Storage) Clone() server.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {
}

// CreateClient create client
func (s *Storage) CreateClient(ctx context.Context, app *dao.App) (err error) {
	err = dao.CreateApp(s.db.WithContext(ctx), app)
	if err != nil {
		return fmt.Errorf("sso storage CreateClient failed, err: %w", err)
	}
	client := &clientInfo{
		Id:          app.ClientId,
		Secret:      app.Secret,
		RedirectUri: app.RedirectUri,
	}
	err = s.redis.HSet(ctx, s.config.storeClientInfoKey, app.ClientId, client.Marshal())
	if err != nil {
		return fmt.Errorf("sso storage CreateClient failed2, err: %w", err)
	}
	return nil
}

// GetClient loads the client by id
func (s *Storage) GetClient(ctx context.Context, clientId string) (c server.Client, err error) {
	infoBytes, err := s.redis.Client().HGet(ctx, s.config.storeClientInfoKey, clientId).Bytes()
	if err != nil {
		err = fmt.Errorf("sso storage GetClient redis get failed, err: %w", err)
		return
	}
	client := &clientInfo{}
	err = client.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("sso storage GetClient unmarshal failed, err: %w", err)
		return
	}
	info := server.DefaultClient{
		Id:          client.Id,
		Secret:      client.Secret,
		RedirectUri: client.RedirectUri,
	}
	return &info, nil
}

// SaveAuthorize saves authorize data.
// 单点登录，会多出一个parent token
func (s *Storage) SaveAuthorize(ctx context.Context, data *server.AuthorizeData) (err error) {
	store := &authorizeData{
		ClientId:    data.Client.GetId(),
		Code:        data.Code,
		Ptoken:      data.SsoData.ParentToken.Token,
		ExpiresIn:   data.ExpiresIn,
		Scope:       data.Scope,
		RedirectUri: data.RedirectUri,
		State:       data.State,
		Ctime:       data.CreatedAt.Unix(),
		Extra:       cast.ToString(data.UserData),
	}
	err = s.redis.SetEX(ctx, fmt.Sprintf(s.config.storeAuthorizeKey, data.Code), store.Marshal(), time.Duration(data.ExpiresIn)*time.Second)
	if err != nil {
		err = fmt.Errorf("sso storage SaveAuthorize failed, err: %w", err)
		return
	}
	// 创建父级Token
	err = s.tokenServer.createParentToken(ctx, data.SsoData.ParentToken, data.SsoData.Uid, data.SsoData.Platform)
	if err != nil {
		err = fmt.Errorf("sso storage SaveAuthorize createParentToken failed, err: %w", err)
		return
	}
	return
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(ctx context.Context, code string) (*server.AuthorizeData, error) {
	var data server.AuthorizeData
	storeBytes, err := s.redis.GetBytes(ctx, fmt.Sprintf(s.config.storeAuthorizeKey, code))
	if err != nil {
		err = fmt.Errorf("sso storage LoadAuthorize redis get failed, err: %w", err)
		return nil, err
	}
	info := &authorizeData{}
	err = info.Unmarshal(storeBytes)
	if err != nil {
		err = fmt.Errorf("sso storage LoadAuthorize unmarshal failed, err: %w", err)
		return nil, err
	}
	data = server.AuthorizeData{
		Code:        info.Code,
		ExpiresIn:   info.ExpiresIn,
		Scope:       info.Scope,
		RedirectUri: info.RedirectUri,
		State:       info.State,
		CreatedAt:   time.Unix(info.Ctime, 0),
		UserData:    info.Extra,
	}
	c, err := s.GetClient(ctx, info.ClientId)
	if err != nil {
		return nil, err
	}
	data.Client = c
	return &data, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(ctx context.Context, code string) (err error) {
	_, err = s.redis.Del(ctx, fmt.Sprintf(s.config.storeAuthorizeKey, code))
	if err != nil {
		err = fmt.Errorf("sso storage RemoveAuthorize failed, err: %w", err)
		return
	}
	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *Storage) SaveAccess(ctx context.Context, data *server.AccessData) (err error) {
	prevToken := ""
	authorizeDataInfo := &server.AuthorizeData{}

	// 之前的access token
	// 如果是authorize token，那么该数据为空
	// 如果是refresh token，有这个数据
	if data.AccessData != nil {
		prevToken = data.AccessData.AccessToken
	}

	// 如果是authorize token，有这个数据
	// 如果是refresh token，那么该数据为空
	if data.AuthorizeData != nil {
		authorizeDataInfo = data.AuthorizeData
	}

	pToken := ""
	// 这种是在authorize token的时候，会有code信息
	if authorizeDataInfo.Code != "" {
		// 根据之前code码，取出parent token信息
		storeBytes, err := s.redis.GetBytes(ctx, fmt.Sprintf(s.config.storeAuthorizeKey, authorizeDataInfo.Code))
		if err != nil {
			err = fmt.Errorf("sso storage redis GetBytes failed, err: %w", err)
			return
		}
		info := &authorizeData{}
		err = info.Unmarshal(storeBytes)
		if err != nil {
			err = fmt.Errorf("sso storage SaveAccess unmarshal failed, err: %w", err)
			return
		}
		pToken = info.Ptoken

		// refresh token的时候，没有该信息
		// 1 拿到原先的sub token，看是否有效
		// 2 再从sub token中找到对应parent token，看是否有效
		// 3 刷新token
		// 从load refresh里拿到老的access token信息，查询到ptoken，并处理老token的逻辑
	} else {
		// todo 老的token是需要将过期时间变短
		pToken, err = s.tokenServer.getParentTokenByToken(ctx, prevToken)
		if err != nil {
			return fmt.Errorf("pToken not found2, err: %w", err)
		}
	}
	if pToken == "" {
		return fmt.Errorf("ptoken is empty")
	}

	if data.Client == nil {
		return errors.New("data.Client must not be nil")
	}

	storeData := &accessData{
		ClientId: data.Client.GetId(),
		//Authorize:    authorizeDataInfo.Code,
		Previous:    prevToken,
		AccessToken: data.AccessToken,
		//RefreshToken: data.RefreshToken,
		ExpiresIn:   data.ExpiresIn,
		Scope:       data.Scope,
		RedirectUri: data.RedirectUri,
		Ctime:       data.CreatedAt.Unix(),
	}

	// 单点登录下，refresh token，其实可以不需要，因为
	err = s.tokenServer.createToken(ctx, data.Client.GetId(), dto.Token{
		Token:     data.AccessToken,
		AuthAt:    time.Now().Unix(),
		ExpiresIn: s.config.parentAccessExpiration,
	}, pToken, storeData)
	if err != nil {
		return fmt.Errorf("设置redis token失败, err:%w", err)
	}
	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadAccess(ctx context.Context, token string) (*server.AccessData, error) {
	var result server.AccessData
	info, err := s.tokenServer.getAccess(ctx, token)
	if err != nil {
		return nil, err
	}

	result.AccessToken = info.AccessToken
	//result.RefreshToken = info.RefreshToken
	result.ExpiresIn = info.ExpiresIn
	result.Scope = info.Scope
	result.RedirectUri = info.RedirectUri
	result.CreatedAt = time.Unix(info.Ctime, 0)
	client, err := s.GetClient(ctx, info.ClientId)
	if err != nil {
		return nil, err
	}
	result.Client = client
	return &result, nil
}

// RemoveAccess revokes or deletes an AccessData.
// 用于删除上一个token信息
func (s *Storage) RemoveAccess(ctx context.Context, token string) (err error) {
	s.tokenServer.removeToken(ctx, token)
	return
}

// RemoveAllAccess 通过token，删除自己的token，以及父token
func (s *Storage) RemoveAllAccess(ctx context.Context, token string) (err error) {
	pToken, err := s.tokenServer.getParentTokenByToken(ctx, token)
	if err != nil {
		return err
	}

	// 删除redis token
	return s.tokenServer.removeParentToken(ctx, pToken)
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// 原本的load refresh，是使用refresh token来换取新的token，但是在单点登录下，可以简单操作。
// 1 拿到原先的sub token，看是否有效
// 2 再从sub token中找到对应parent token，看是否有效
// 3 刷新token
// 必须要这个信息用于给予access token，告诉oauth2老的token，用于在save access的时候，查询到ptoken，并处理老token的逻辑
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired
func (s *Storage) LoadRefresh(ctx context.Context, token string) (*server.AccessData, error) {
	return s.LoadAccess(ctx, token)
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *Storage) RemoveRefresh(ctx context.Context, code string) (err error) {
	//err = dao.DeleteRefreshByToken(s.db.WithContext(ctx), code)
	return
}

// RenewParentToken 续期父级token
func (s *Storage) RenewParentToken(ctx context.Context, pToken dto.Token) (err error) {
	return s.tokenServer.renewParentToken(ctx, pToken)
}

func (s *Storage) GetUidByParentToken(ctx context.Context, token string) (uid int64, err error) {
	return s.tokenServer.getUidByParentToken(ctx, token)
}

func (s *Storage) RemoveParentToken(ctx context.Context, pToken string) (err error) {
	return s.tokenServer.removeParentToken(ctx, pToken)
}

func (s *Storage) GetUidByToken(ctx context.Context, token string) (uid int64, err error) {
	return s.tokenServer.getUidByToken(ctx, token)
}
