package main

import (
	"github.com/ego-component/eoauth2/examples/sso-one-account/client/pkg/invoker"
	"github.com/ego-component/eoauth2/examples/sso-one-account/client/pkg/server"
	"github.com/gotomicro/ego"
	"github.com/gotomicro/ego/core/elog"
)

//  export EGO_DEBUG=true && go run main.go
func main() {
	err := ego.New().
		Invoker(invoker.Init).
		Serve(
			server.ServeHttp(),
		).Run()
	if err != nil {
		elog.Panic("startup", elog.FieldErr(err))
	}
}
