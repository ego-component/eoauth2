package invoker

import (
	"github.com/ego-component/egorm"
	ssoserver "github.com/ego-component/eoauth2/server"
	"github.com/ego-component/eoauth2/storage/ssostorage"
	"github.com/ego-component/eredis"
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
