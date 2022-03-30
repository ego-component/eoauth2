package ssostorage

import (
	"context"
	"fmt"

	"github.com/ego-component/eoauth2/storage/dto"
	"github.com/gotomicro/ego-component/eredis"
)

type tokenServer struct {
	redis             *eredis.Component
	uidMapParentToken *uidMapParentToken
	parentToken       *parentToken
	subToken          *subToken
	config            *config
}

func initTokenServer(config *config, redis *eredis.Component) *tokenServer {
	return &tokenServer{
		config:            config,
		redis:             redis,
		uidMapParentToken: newUidMapParentToken(config, redis),
		parentToken:       newParentToken(config, redis),
		subToken:          newSubToken(config, redis),
	}
}

// createParentToken sso的父节点token
func (t *tokenServer) createParentToken(ctx context.Context, pToken dto.Token, uid int64, platform string) (err error) {
	// 1 设置uid 到 parent token关系
	err = t.uidMapParentToken.setToken(ctx, uid, platform, pToken)
	if err != nil {
		return fmt.Errorf("token.createParentToken: create token map failed, err:%w", err)
	}

	// 2 创建父级的token信息
	return t.parentToken.create(ctx, pToken, platform, uid)
}

func (t *tokenServer) renewParentToken(ctx context.Context, pToken dto.Token) (err error) {
	// 1 设置uid 到 parent token关系
	err = t.parentToken.renew(ctx, pToken)
	if err != nil {
		return fmt.Errorf("token.createParentToken: create token map failed, err:%w", err)
	}
	return nil
}

// createToken 创建TOKEN信息，并且存入access信息
func (t *tokenServer) createToken(ctx context.Context, clientId string, token dto.Token, pToken string, storeData *accessData) (err error) {
	err = t.parentToken.setToken(ctx, pToken, clientId, token)
	if err != nil {
		return fmt.Errorf("tokenServer.createToken failed, err:%w", err)
	}
	// setTTL new token
	err = t.subToken.create(ctx, token, pToken, clientId, storeData)
	return
}

func (t *tokenServer) getAccess(ctx context.Context, token string) (storeData *accessData, err error) {
	return t.subToken.getAccess(ctx, token)
}

func (t *tokenServer) removeToken(ctx context.Context, token string) (bool, error) {
	return t.subToken.removeToken(ctx, token)
}

func (t *tokenServer) removeParentToken(ctx context.Context, pToken string) (err error) {
	return t.parentToken.delete(ctx, pToken)
}

func (t *tokenServer) getUidsByParentToken(ctx context.Context, pToken string) (uids []int64, err error) {
	return t.parentToken.getUids(ctx, pToken)
}

func (t *tokenServer) getParentTokenByToken(ctx context.Context, token string) (pToken string, err error) {
	// 通过子系统token，获得父节点token
	pToken, err = t.subToken.getParentToken(ctx, token)
	return
}

func (t *tokenServer) getUidsByToken(ctx context.Context, token string) (uid []int64, err error) {
	// 通过子系统token，获得父节点token
	pToken, err := t.getParentTokenByToken(ctx, token)
	if err != nil {
		return
	}
	return t.getUidsByParentToken(ctx, pToken)
}
