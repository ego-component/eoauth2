package ssostorage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ego-component/eoauth2/server/model"
	"github.com/go-redis/redis/v8"
	"github.com/gotomicro/ego-component/eredis"
)

type config struct {
	enableMultipleAccounts bool // 开启多账号，默认false
	/*
		    hashmap
			key: sso:uid:{uid}
			expiration: 最大的过期时间
			value:
				expireList:                [{"clientType1|parentToken":"ctime"}]
				expireTime:                最大过期时间
				{clientType1|parentToken}: parentTokenJsonInfo
				{clientType2|parentToken}: parentTokenJsonInfo
	*/
	uidMapParentTokenKey      string // 存储token信息的hash map
	uidMapParentTokenFieldKey string // 存储token信息的hash map的field key  {clientType1|parentToken}
	/*
				     hashmap
					 key: sso:ptk:{parentToken}
		  			 expiration: 最大的过期时间
					 value:
						uid:                   uid
						tokenInfo:             tokenInfo
						expireList:             [{"subTokenClientId1":"ctime"}]
						expireTime:            最大过期时间
						{subTokenClientId1}:   tokenJsonInfo
						{subTokenClientId2}:   tokenJsonInfo
						{subTokenClientId3}:   tokenJsonInfo
					 ttl: 3600
	*/
	parentTokenMapSubTokenKey string // 存储token信息的hash map
	// key token value ptoken
	/*
		hashmap
		key: sso:stk:{subToken}
		value:
			parentToken: {parentToken}
			clientId:    {subTokenClientId}
			tokenInfo:   {tokenJsonInfo}
		ttl: 3600
	*/
	subTokenMapParentTokenKey string // token与父级token的映射关系
	storeClientInfoKey        string // 存储sso client的信息
	storeAuthorizeKey         string // 存储sso authorize的信息
	//clientType                []string // 支持的客户端类型，web、andorid、ios，用于设置一个客户端，可以登录几个parent token。
}

func defaultConfig() *config {
	return &config{
		enableMultipleAccounts:    false,
		uidMapParentTokenKey:      "sso:uid:%d",  // uid map parent token type
		uidMapParentTokenFieldKey: "%s|%s",       // uid map parent token type
		parentTokenMapSubTokenKey: "sso:ptk:%s",  //  parent token map
		subTokenMapParentTokenKey: "sso:stk:%s",  // sub token map parent token
		storeClientInfoKey:        "sso:client",  // sso的client信息，使用hash map
		storeAuthorizeKey:         "sso:auth:%s", // 存储auth信息
	}
}

type subToken struct {
	config             *config
	hashKeyParentToken string
	hashKeyClientId    string
	hashKeyTokenInfo   string
	hashKeyCtime       string
	hashKeyAccessInfo  string
	redis              *eredis.Component
}

func newSubToken(config *config, redis *eredis.Component) *subToken {
	return &subToken{
		config:             config,
		hashKeyCtime:       "_c", // create time
		hashKeyParentToken: "_pt",
		hashKeyClientId:    "_id",
		hashKeyTokenInfo:   "_t",
		hashKeyAccessInfo:  "_a",
		redis:              redis,
	}
}

func (s *subToken) getKey(subToken string) string {
	return fmt.Sprintf(s.config.subTokenMapParentTokenKey, subToken)
}

func (s *subToken) create(ctx context.Context, token model.SubToken, parentToken string, clientId string, accessData *accessData) error {
	err := s.redis.HMSet(ctx, s.getKey(token.Token.Token), map[string]interface{}{
		s.hashKeyParentToken: parentToken,
		s.hashKeyClientId:    clientId,
		s.hashKeyCtime:       time.Now().Unix(),
		s.hashKeyAccessInfo:  accessData.Marshal(),
		s.hashKeyTokenInfo:   token.StoreData.Marshal(),
	}, time.Duration(token.Token.ExpiresIn)*time.Second)
	if err != nil {
		return fmt.Errorf("subToken.create token failed, err:%w", err)
	}
	return nil
}

func (s *subToken) getAccess(ctx context.Context, token string) (storeData *accessData, err error) {
	infoBytes, err := s.redis.Client().HGet(ctx, s.getKey(token), s.hashKeyAccessInfo).Bytes()
	info := &accessData{}
	err = info.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("subToken getAccess json unmarshal failed, err: %w", err)
		return
	}
	return info, nil
}

// removeToken 触发这个场景是refresh token操作，给30s时间，避免换token的时间差，prev token过早失效导致的业务问题
func (s *subToken) removeToken(ctx context.Context, token string) (bool, error) {
	return s.redis.Expire(ctx, s.getKey(token), 30*time.Second)
}

// 通过子系统token，获得父节点token
func (s *subToken) getParentToken(ctx context.Context, subToken string) (parentToken string, err error) {
	parentToken, err = s.redis.HGet(ctx, s.getKey(subToken), s.hashKeyParentToken)
	if err != nil {
		err = fmt.Errorf("subToken.getParentToken failed, %w", err)
		return
	}
	return
}

type uidMapParentToken struct {
	config             *config
	redis              *eredis.Component
	hashExpireTimeList string
	hashExpireTime     string
}

func newUidMapParentToken(config *config, redis *eredis.Component) *uidMapParentToken {
	return &uidMapParentToken{
		config:             config,
		redis:              redis,
		hashExpireTimeList: "_etl", // expire time List
		hashExpireTime:     "_et",  // expire time，最大过期时间，unix时间戳，到了时间就会过期被删除
	}
}

func (u *uidMapParentToken) getKey(uid int64) string {
	return fmt.Sprintf(u.config.uidMapParentTokenKey, uid)
}

func (u *uidMapParentToken) getFieldKey(clientType string, parentToken string) string {
	return fmt.Sprintf(u.config.uidMapParentTokenFieldKey, clientType, parentToken)
}

// 并发操作redis情况不考虑，因为一个用户使用多个终端，并发登录极其少见
// 1 先取出这个key里面的数据
//   expireTimeList:            [{"clientType1|parentToken":"expire的时间戳"}]
//	 expireTime:                最大过期时间

func (u *uidMapParentToken) setToken(ctx context.Context, uid int64, platform string, pToken model.Token) error {
	fieldKey := u.getFieldKey(platform, pToken.Token)

	expireTime, err := u.getExpireTime(ctx, uid)
	if err != nil {
		return err
	}
	expireTimeList, err := u.getExpireTimeList(ctx, uid)
	if err != nil {
		return err
	}
	nowTime := time.Now().Unix()
	newExpireTimeList := make(uidTokenExpires, 0)
	// 新数据添加到队列前面，这样方便后续清除数据，或者对数据做一些限制
	newExpireTimeList = append(newExpireTimeList, uidTokenExpire{
		Token:      fieldKey,
		ExpireTime: nowTime + pToken.ExpiresIn,
	})

	// 删除过期的数据
	hdelFields := make([]string, 0)
	for _, value := range expireTimeList {
		// 过期时间小于当前时间，那么需要删除
		if value.ExpireTime <= nowTime {
			hdelFields = append(hdelFields, value.Token)
			continue
		}
		newExpireTimeList = append(newExpireTimeList, value)
	}
	if len(hdelFields) > 0 {
		err = u.redis.HDel(ctx, u.getKey(uid), hdelFields...)
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken HDel expire data failed, error: %w", err)
		}
	}

	err = u.redis.HSet(ctx, u.getKey(uid), u.hashExpireTimeList, newExpireTimeList.Marshal())
	if err != nil {
		return fmt.Errorf("uidMapParentToken setToken HSet expire time failed, error: %w", err)
	}

	// 将parent token信息存入
	pTokenByte, err := pToken.Marshal()
	if err != nil {
		return fmt.Errorf("uidMapParentToken.createToken failed, err: %w", err)
	}

	err = u.redis.HSet(ctx, u.getKey(uid), u.getFieldKey(platform, pToken.Token), pTokenByte)
	if err != nil {
		return fmt.Errorf("uidMapParentToken setToken HSet token info failed, error: %w", err)
	}

	// 如果之前没数据，那么expireTime为0，所以会写入
	// 新的token大于，之前的过期时间，所以需要续期
	if pToken.ExpiresIn+nowTime > expireTime {
		err = u.redis.HSet(ctx, u.getKey(uid), u.hashExpireTime, pToken.ExpiresIn+nowTime)
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken HSet expire time failed, error: %w", err)
		}

		err = u.redis.Client().Expire(ctx, u.getKey(uid), time.Duration(pToken.ExpiresIn)*time.Second).Err()
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken expire error %w", err)
		}
	}

	return nil
}

// 获取过期时间，最新的在最前面。
func (u *uidMapParentToken) getExpireTimeList(ctx context.Context, uid int64) (userInfo uidTokenExpires, err error) {
	// 根据父节点token，获取用户信息
	infoBytes, err := u.redis.Client().HGet(ctx, u.getKey(uid), u.hashExpireTimeList).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		err = fmt.Errorf("uidMapParentToken getExpireTimeList failed, err: %w", err)
		return
	}
	if errors.Is(err, redis.Nil) {
		err = nil
		return
	}

	pUserInfo := &userInfo
	err = pUserInfo.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("uidMapParentToken getExpireTimeList json unmarshal error, %w", err)
		return
	}
	return
}

// 获取过期时间，快过期的在最前面。
func (u *uidMapParentToken) getExpireTime(ctx context.Context, uid int64) (expireTime int64, err error) {
	// 根据父节点token，获取用户信息
	expireTime, err = u.redis.Client().HGet(ctx, u.getKey(uid), u.hashExpireTime).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		err = fmt.Errorf("uidMapParentToken getExpireTime failed, err: %w", err)
		return
	}
	if errors.Is(err, redis.Nil) {
		err = nil
	}
	return
}

type parentToken struct {
	config             *config
	redis              *eredis.Component
	hashKeyCtime       string
	hashKeyUids        string
	hashKeyPlatform    string
	hashExpireTimeList string
	hashKeyUidInfo     string
}

func newParentToken(config *config, redis *eredis.Component) *parentToken {
	return &parentToken{
		config:             config,
		redis:              redis,
		hashKeyCtime:       "_c",     // create time
		hashKeyPlatform:    "_p",     // 类型
		hashKeyUids:        "_u",     // uid
		hashKeyUidInfo:     "_ui:%d", // uid info
		hashExpireTimeList: "_etl",   // expire time List

	}
}

func (p *parentToken) getKey(pToken string) string {
	return fmt.Sprintf(p.config.parentTokenMapSubTokenKey, pToken)
}

func (p *parentToken) create(ctx context.Context, ssoData model.ParentToken) error {
	// 如果没有开启多账号，那么就是单账号，直接set
	if !p.config.enableMultipleAccounts {
		uids := UidsStore{ssoData.StoreData.Uid}
		uids.Marshal()
		err := p.redis.HMSet(ctx, p.getKey(ssoData.Token.Token), map[string]interface{}{
			p.hashKeyCtime: time.Now().Unix(),
			p.hashKeyUids:  uids.Marshal(),
			fmt.Sprintf(p.hashKeyUidInfo, ssoData.StoreData.Uid): ssoData.StoreData.Marshal(),
		}, time.Duration(ssoData.Token.ExpiresIn)*time.Second)
		if err != nil {
			return fmt.Errorf("parentToken.create failed, err:%w", err)
		}
		return nil
	}

	uids, err := p.getUids(ctx, ssoData.Token.Token)
	// 系统错误
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("parentToken.create get key empty, err: %w", err)
	}

	// 如果不存在，那么直接set，创建
	if errors.Is(err, redis.Nil) {
		uids = UidsStore{ssoData.StoreData.Uid}
		uids.Marshal()
		err = p.redis.HMSet(ctx, p.getKey(ssoData.Token.Token), map[string]interface{}{
			p.hashKeyCtime: time.Now().Unix(),
			p.hashKeyUids:  uids.Marshal(),
			fmt.Sprintf(p.hashKeyUidInfo, ssoData.StoreData.Uid): ssoData.StoreData.Marshal(),
		}, time.Duration(ssoData.Token.ExpiresIn)*time.Second)
		if err != nil {
			return fmt.Errorf("parentToken.create failed, err:%w", err)
		}
		return nil
	}
	// 如果存在，那么需要取出之前数据，重新写入新的uid信息
	uids = append(uids, ssoData.StoreData.Uid)
	err = p.redis.HMSet(ctx, p.getKey(ssoData.Token.Token), map[string]interface{}{
		p.hashKeyUids: uids.Marshal(),
		fmt.Sprintf(p.hashKeyUidInfo, ssoData.StoreData.Uid): ssoData.StoreData.Marshal(),
	}, time.Duration(ssoData.Token.ExpiresIn)*time.Second)
	if err != nil {
		return fmt.Errorf("parentToken.create failed, err:%w", err)
	}
	return nil
}

func (p *parentToken) renew(ctx context.Context, pToken model.Token) error {
	err := p.redis.Client().Expire(ctx, p.getKey(pToken.Token), time.Duration(pToken.ExpiresIn)*time.Second).Err()
	if err != nil {
		return fmt.Errorf("parentToken.renew failed, err:%w", err)
	}

	return nil
}

func (p *parentToken) delete(ctx context.Context, pToken string) error {
	_, err := p.redis.Del(ctx, p.getKey(pToken))
	if err != nil {
		return fmt.Errorf("token.removeParentToken: remove token failed, err:%w", err)
	}
	return nil
}

func (p *parentToken) getUids(ctx context.Context, pToken string) (uids UidsStore, err error) {
	uidBytes, err := p.redis.Client().HGet(ctx, p.getKey(pToken), p.hashKeyUids).Bytes()
	// 系统错误
	if err != nil {
		err = fmt.Errorf("getUids failed, err: %w", err)
		return
	}

	err = uids.Unmarshal(uidBytes)
	if err != nil {
		err = fmt.Errorf("parentToken.create unmarshal err: %w", err)
		return
	}
	return
}

func (p *parentToken) getUid(ctx context.Context, pToken string) (uid int64, err error) {
	// 根据父节点token，获取用户信息
	uid, err = p.redis.Client().HGet(ctx, p.getKey(pToken), p.hashKeyUids).Int64()
	if err != nil {
		err = fmt.Errorf("parentToken getUid failed, err: %w", err)
		return
	}
	return
}

func (p *parentToken) setToken(ctx context.Context, pToken string, clientId string, token model.Token) error {
	expireTimeList, err := p.getExpireTimeList(ctx, pToken)
	if err != nil {
		return err
	}
	// 因为authorize阶段创建了parent token，所以如果不存在parent token key是有问题的，需要报错
	_, err = p.redis.HGet(ctx, p.getKey(pToken), p.hashKeyCtime)
	if err != nil {
		return fmt.Errorf("parentToken.createToken get key empty, err: %w", err)
	}

	nowTime := time.Now().Unix()
	newExpireTimeList := make(uidTokenExpires, 0)
	// 新数据添加到队列前面，这样方便后续清除数据，或者对数据做一些限制
	newExpireTimeList = append(newExpireTimeList, uidTokenExpire{
		Token:      clientId,
		ExpireTime: nowTime + token.ExpiresIn,
	})

	// 删除过期的数据
	hdelFields := make([]string, 0)
	for _, value := range expireTimeList {
		// 过期时间小于当前时间，那么需要删除
		if value.ExpireTime <= nowTime {
			hdelFields = append(hdelFields, value.Token)
			continue
		}
		newExpireTimeList = append(newExpireTimeList, value)
	}
	if len(hdelFields) > 0 {
		err = p.redis.HDel(ctx, p.getKey(pToken), hdelFields...)
		if err != nil {
			return fmt.Errorf("uidMapParentToken setToken HDel expire data failed, error: %w", err)
		}
	}

	err = p.redis.HSet(ctx, p.getKey(pToken), p.hashExpireTimeList, newExpireTimeList.Marshal())
	if err != nil {
		return fmt.Errorf("uidMapParentToken setToken HSet expire time failed, error: %w", err)
	}

	tokenJsonInfo, err := token.Marshal()
	if err != nil {
		return fmt.Errorf("parentToken.createToken json marshal failed, err: %w", err)
	}

	err = p.redis.HSet(ctx, p.getKey(pToken), clientId, tokenJsonInfo)
	if err != nil {
		return fmt.Errorf("parentToken.createToken hset failed, err:%w", err)
	}
	return nil
}

// 获取过期时间，最新的在最前面。
func (p *parentToken) getExpireTimeList(ctx context.Context, pToken string) (userInfo uidTokenExpires, err error) {
	// 根据父节点token，获取用户信息
	infoBytes, err := p.redis.Client().HGet(ctx, p.getKey(pToken), p.hashExpireTimeList).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		err = fmt.Errorf("parentToken getExpireTimeList failed, err: %w", err)
		return
	}
	if errors.Is(err, redis.Nil) {
		err = nil
		return
	}

	pUserInfo := &userInfo
	err = pUserInfo.Unmarshal(infoBytes)
	if err != nil {
		err = fmt.Errorf("parentToken getExpireTimeList json unmarshal error, %w", err)
		return
	}
	return
}

func (p *parentToken) getToken(ctx context.Context, pToken string, clientId string) (tokenInfo model.Token, err error) {
	tokenValue, err := p.redis.HGet(ctx, p.getKey(pToken), clientId)
	if err != nil {
		err = fmt.Errorf("tokgen get redis hmget string error, %w", err)
		return
	}
	pTokenInfo := &tokenInfo
	err = pTokenInfo.Unmarshal([]byte(tokenValue))
	if err != nil {
		err = fmt.Errorf("redis token info json unmarshal errorr, err: %w", err)
		return
	}
	return
}
