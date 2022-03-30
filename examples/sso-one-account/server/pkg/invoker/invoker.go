package invoker

import (
	ssoserver "github.com/ego-component/eoauth2/server"
	"github.com/ego-component/eoauth2/storage/ssostorage"
	"github.com/gotomicro/ego-component/egorm"
	"github.com/gotomicro/ego-component/eredis"
)

var (
	SsoComponent *ssoserver.Component
	TokenStorage *ssostorage.Storage
	Db           *egorm.Component
)

func Init() error {
	Db = egorm.Load("mysql").Build()
	Redis := eredis.Load("redis").Build()
	TokenStorage = ssostorage.NewStorage(
		Db,
		Redis,
		ssostorage.WithParentAccessExpiration(86400*7),
	)
	SsoComponent = ssoserver.Load("sso").Build(ssoserver.WithStorage(TokenStorage))
	return nil
}
