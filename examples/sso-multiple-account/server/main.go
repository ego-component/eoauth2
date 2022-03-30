package main

import (
	"github.com/ego-component/eoauth2/examples/sso-multiple-account/server/job"
	"github.com/ego-component/eoauth2/examples/sso-multiple-account/server/pkg/invoker"
	"github.com/ego-component/eoauth2/examples/sso-multiple-account/server/pkg/server"
	"github.com/gotomicro/ego"
	"github.com/gotomicro/ego/core/elog"
	"github.com/gotomicro/ego/task/ejob"
)

//  export EGO_DEBUG=true && go run main.go
func main() {
	err := ego.New().
		Invoker(invoker.Init).
		Job(ejob.Job("init_data", job.InitAdminData)).
		Serve(
			server.ServeHttp(),
			server.ServeGrpc(),
		).Run()
	if err != nil {
		elog.Panic("startup", elog.FieldErr(err))
	}
}
