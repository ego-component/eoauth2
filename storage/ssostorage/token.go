package ssostorage

import (
	"context"
	"fmt"

	"github.com/ego-component/eoauth2/server/model"
)

type tokenServer struct {
	uidMapParentToken *uidMapParentToken
	parentToken       *parentToken
	subToken          *subToken
	config            *config
}

func initTokenServer(config *config, uidMapParentToken *uidMapParentToken, parentToken *parentToken, subToken *subToken) *tokenServer {
	return &tokenServer{
		config:            config,
		uidMapParentToken: uidMapParentToken,
		parentToken:       parentToken,
		subToken:          subToken,
	}
}

// createParentToken sso的父节点token
func (t *tokenServer) createParentToken(ctx context.Context, ssoData model.ParentToken) (err error) {
	// 1 设置uid 到 parent token关系
	err = t.uidMapParentToken.setToken(ctx, ssoData.Uid, ssoData.StoreData.Platform, ssoData.Token)
	if err != nil {
		return fmt.Errorf("token.createParentToken: create token map failed, err:%w", err)
	}

	// 2 创建父级的token信息
	return t.parentToken.create(ctx, ssoData)
}

//
//func (t *tokenServer) renewParentToken(ctx context.Context, pToken model.Token) (err error) {
//	// 1 设置uid 到 parent token关系
//	err = t.parentToken.renew(ctx, pToken)
//	if err != nil {
//		return fmt.Errorf("token.createParentToken: create token map failed, err:%w", err)
//	}
//	return nil
//}

// createToken 创建TOKEN信息，并且存入access信息
func (t *tokenServer) createToken(ctx context.Context, clientId string, token model.SubToken, pToken string, storeData *AccessData) (err error) {
	err = t.parentToken.setToken(ctx, pToken, clientId, token.Token)
	if err != nil {
		return fmt.Errorf("tokenServer.createToken failed, err:%w", err)
	}
	// setTTL new token
	err = t.subToken.create(ctx, token, pToken, clientId, storeData)
	return
}

func (t *tokenServer) getAccess(ctx context.Context, token string) (storeData *AccessData, err error) {
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
