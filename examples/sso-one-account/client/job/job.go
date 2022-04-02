package job

import (
	"fmt"

	"github.com/ego-component/eoauth2/examples/sso-one-account/server/pkg/invoker"
	"github.com/ego-component/eoauth2/storage/dao"
	"github.com/gotomicro/ego/core/econf"
	"github.com/gotomicro/ego/task/ejob"
)

func InitAdminData(ctx ejob.Context) (err error) {
	models := []interface{}{
		&dao.App{},
	}
	gormdb := invoker.Db
	err = gormdb.Set("gorm:table_options", "ENGINE=InnoDB").AutoMigrate(models...)
	if err != nil {
		return err
	}
	fmt.Println("create table ok")
	err = invoker.TokenStorage.CreateClient(ctx.Ctx, &dao.App{
		ClientId:    "1234",
		Name:        "sso-client",
		Secret:      "5678",
		RedirectUri: econf.GetString("client.codeUrl"),
		Status:      1,
	})
	if err != nil {
		return
	}
	return nil
}
