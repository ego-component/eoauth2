package ssostorage

import (
	"context"

	"github.com/ego-component/eoauth2/server"
	"github.com/gotomicro/ego-component/egorm"
	"github.com/gotomicro/ego-component/eredis"
	"github.com/gotomicro/ego/core/elog"
)

type Component struct {
	api         *API
	storage     *Storage
	db          *egorm.Component
	logger      *elog.Component
	tokenServer *tokenServer
	config      *config
	redis       *eredis.Component
}

// NewComponent returns a new instance.
func NewComponent(db *egorm.Component, redis *eredis.Component, options ...Option) *Component {
	container := &Component{
		db:     db,
		logger: elog.EgoLogger.With(elog.FieldComponent("oauth2.storage")),
		config: defaultConfig(),
	}
	for _, option := range options {
		option(container)
	}

	uidMapParentTokenObj := newUidMapParentToken(container.config, redis)
	parentTokenObj := newParentToken(container.config, redis)
	subTokenObj := newSubToken(container.config, redis)

	tSrv := initTokenServer(container.config, uidMapParentTokenObj, parentTokenObj, subTokenObj)
	container.tokenServer = tSrv
	container.redis = redis
	container.storage = newStorage(container.config, container.logger, db, redis, tSrv)
	container.api = newAPI(container.config, container.logger, db, redis, uidMapParentTokenObj, parentTokenObj, subTokenObj)
	return container
}

func (s *Component) GetStorage() server.Storage {
	return s.storage
}

func (s *Component) GetAPI() *API {
	return s.api
}

// RemoveAllAccess 通过token，删除自己的token，以及父token
func (s *Component) RemoveAllAccess(ctx context.Context, token string) (err error) {
	pToken, err := s.tokenServer.getParentTokenByToken(ctx, token)
	if err != nil {
		return err
	}
	// 删除redis token
	return s.tokenServer.removeParentToken(ctx, pToken)
}

// GetUidByParentToken 用于单账号
func (s *Component) GetUidByParentToken(ctx context.Context, token string) (uid int64, err error) {
	uids, err := s.tokenServer.getUidsByParentToken(ctx, token)
	if err != nil {
		return 0, err
	}
	uid = uids[0]
	return
}

// GetUidByToken 用于单账号
func (s *Component) GetUidByToken(ctx context.Context, token string) (uid int64, err error) {
	uids, err := s.tokenServer.getUidsByToken(ctx, token)
	if err != nil {
		return 0, err
	}
	uid = uids[0]
	return
}

// GetUidsByParentToken 用于多账号
func (s *Component) GetUidsByParentToken(ctx context.Context, token string) (uids []int64, err error) {
	return s.tokenServer.getUidsByParentToken(ctx, token)
}

// GetUidsByToken 用于多账号
func (s *Component) GetUidsByToken(ctx context.Context, token string) (uid []int64, err error) {
	return s.tokenServer.getUidsByToken(ctx, token)
}

func (s *Component) RemoveParentToken(ctx context.Context, pToken string) (err error) {
	return s.tokenServer.removeParentToken(ctx, pToken)
}

// todo 后期再说 RenewParentToken 续期父级token
//func (s *Component) RenewParentToken(ctx context.Context, pToken model.Field) (err error) {
//	return s.tokenServer.renewParentToken(ctx, pToken)
//}
