package ssostorage

import (
	"context"
	"errors"
	"fmt"

	"github.com/ego-component/eoauth2/server"
	"github.com/ego-component/eoauth2/storage/dao"
	"github.com/go-redis/redis/v8"
	"github.com/gotomicro/ego-component/egorm"
	"github.com/gotomicro/ego-component/eredis"
	"github.com/gotomicro/ego/core/elog"
)

type API struct {
	redis             *eredis.Component
	db                *egorm.Component
	config            *config
	logger            *elog.Component
	uidMapParentToken *userToken
	parentToken       *parentToken
	subToken          *subToken
}

func newAPI(config *config, logger *elog.Component, db *egorm.Component, redis *eredis.Component, uidMapParentToken *userToken, parentToken *parentToken, subToken *subToken) *API {
	return &API{
		config:            config,
		redis:             redis,
		db:                db,
		logger:            logger,
		uidMapParentToken: uidMapParentToken,
		parentToken:       parentToken,
		subToken:          subToken,
	}
}

// CreateClient create client
func (s *API) CreateClient(ctx context.Context, app *dao.App) (err error) {
	err = dao.CreateApp(s.db.WithContext(ctx), app)
	if err != nil {
		return fmt.Errorf("sso storage CreateClient failed, err: %w", err)
	}
	client := &ClientInfo{
		ClientId:    app.ClientId,
		Secret:      app.Secret,
		RedirectUri: app.RedirectUri,
	}
	err = s.redis.HSet(ctx, s.config.storeClientInfoKey, app.ClientId, client.Marshal())
	if err != nil {
		return fmt.Errorf("sso storage CreateClient failed2, err: %w", err)
	}
	return nil
}

func (s *API) UpdateClient(ctx context.Context, clientId string, updates map[string]interface{}) (err error) {
	err = dao.UpdateApp(s.db.WithContext(ctx), clientId, updates)
	if err != nil {
		return fmt.Errorf("sso storage UpdateClient failed, err: %w", err)
	}
	// todo 判断
	info, err := dao.GetAppInfoByClientId(s.db.WithContext(ctx), clientId)
	if err != nil {
		return fmt.Errorf("sso storage UpdateClient get info failed, err: %w", err)
	}
	client := &ClientInfo{
		ClientId:    info.ClientId,
		Secret:      info.Secret,
		RedirectUri: info.RedirectUri,
	}
	err = s.redis.HSet(ctx, s.config.storeClientInfoKey, clientId, client.Marshal())
	if err != nil {
		return fmt.Errorf("sso storage UpdateClient failed2, err: %w", err)
	}
	return nil
}

func (s *API) DeleteClient(ctx context.Context, clientId string) (err error) {
	err = dao.DeleteApp(s.db.WithContext(ctx), clientId)
	if err != nil {
		return fmt.Errorf("sso storage DeleteClient failed, err: %w", err)
	}

	err = s.redis.HDel(ctx, s.config.storeClientInfoKey, clientId)
	if err != nil {
		return fmt.Errorf("sso storage DeleteClient failed2, err: %w", err)
	}
	return nil
}

// GetClient hgetall sso:client
func (s *API) GetClient(ctx context.Context, clientId string) (info *ClientInfo, err error) {
	infoBytes, err := s.redis.Client().HGet(ctx, s.config.storeClientInfoKey, clientId).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		err = fmt.Errorf("sso storage GetClient redis get failed, err: %w", err)
		return
	}

	if errors.Is(err, redis.Nil) {
		err = fmt.Errorf("redis not found,err: %w", server.ErrNotFound)
		return
	}

	client := &ClientInfo{}
	err = client.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("sso storage GetClient unmarshal failed, err: %w", err)
		return
	}
	return
}

func (s *API) GetAllByParentToken(ctx context.Context, pToken string) (tokenInfo *ParentTokenStore, err error) {
	return s.parentToken.getAll(ctx, pToken)
}

func (s *API) GetAllByUser(ctx context.Context, uid int64) (output *UserStore, err error) {
	return s.uidMapParentToken.getAll(ctx, uid)
}

func (s *API) GetAllBySubToken(ctx context.Context, token string) (output *SubTokenStore, err error) {
	return s.subToken.getAll(ctx, token)
}
