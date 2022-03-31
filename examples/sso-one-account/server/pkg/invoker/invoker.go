package invoker

import (
	ssoserver "github.com/ego-component/eoauth2/server"
	"github.com/ego-component/eoauth2/storage/ssostorage"
	"github.com/gotomicro/ego-component/egorm"
	"github.com/gotomicro/ego-component/eredis"
)

var (
	SsoComponent *ssoserver.Component
	TokenStorage *ssostorage.Component
	Db           *egorm.Component
)

func Init() error {
	Db = egorm.Load("mysql").Build()
	Redis := eredis.Load("redis").Build()
	TokenStorage = ssostorage.NewComponent(
		Db,
		Redis,
	)
	SsoComponent = ssoserver.Load("sso").Build(ssoserver.WithStorage(TokenStorage.GetStorage()))
	return nil
}
