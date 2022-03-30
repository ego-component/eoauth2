# eoauth2 组件使用指南
## 简介 
- 根据开源项目 [https://github.com/openshift/osin](https://github.com/openshift/osin) 做了改造
- 支持http oauth2 server
- 支持grpc oauth2 server
- 方便改造为多客户端的sso服务


## Example
### Oauth2登录
```bash
cd examples/simple && EGO_DEBUG=true && go run main.go
// 访问 http://127.0.0.1:9090/app
```
### 单点登录
* [单点登录文档](./examples/sso/readme.md)
* [单点登录Examples](./examples/sso/makefile)

## Example Server
```go
type ReqOauthLogin struct {
    RedirectUri  string `json:"redirect_uri" form:"redirect_uri"` // redirect by backend
    ClientId     string `json:"client_id" form:"client_id"`
    ResponseType string `json:"response_type" form:"response_type"`
    State        string `json:"state" form:"state"`
    Scope        string `json:"scope" form:"scope"`
}

type ReqToken struct {
    GrantType     string `json:"grant_type" form:"grant_type"`
    Code          string `json:"code" form:"code"`
    ClientId      string `json:"client_id" form:"client_id"`
    ClientSecret  string `json:"client_secret" form:"client_secret"`
    RedirectUri   string `json:"redirect_uri" form:"redirect_uri"`
}

ego.New().Serve(func() *egin.Component {
    oauth2 := server.DefaultContainer().Build(server.WithStorage(examples.NewTestStorage()))
    router := egin.DefaultContainer().Build()
    router.Any("/authorize", func(c *gin.Context) {
        reqView := ReqOauthLogin{}
        // 1 解析参数
        err := c.Bind(&reqView)
        if err != nil {
            c.JSON(401, "参数错误")
            return
        }
        // 2 设置oauth2的请求
        ar := oauth2.HandleAuthorizeRequest(c.Request.Context(), server.AuthorizeRequestParam{
            ClientId:     reqView.ClientId,
            RedirectUri:  reqView.RedirectUri,
            Scope:        reqView.Scope,
            State:        reqView.State,
            ResponseType: reqView.ResponseType,
        })
        if ar.IsError() {
            c.JSON(401, ar.GetAllOutput())
            return
        }
		
		// 3 处理登录页面
        if !HandleLoginPage(ar, c.Writer, c.Request) {
            return
        }
        
		// 4 处理授权
        err = ar.Build(
            server.WithAuthorizeRequestAuthorized(true),
            server.WithAuthorizeRequestUserData("{uid:1}"),
        )
        if err != nil {
            c.JSON(401, err.Error())
            return
        }
        // 5 跳转登录
        redirectUri, err := ar.GetRedirectUrl()
        if err != nil {
            c.JSON(401, "获取重定向地址失败")
            return
        }
        c.Redirect(302, redirectUri)
        return
    })

    // Authorize token endpoint
    router.POST("/token", func(c *gin.Context) {
        var ar *server.AccessRequest
        reqView := ReqToken{}
        err := c.Bind(&reqView)
        if err != nil {
            c.JSON(401, "参数错误")
            return
        }
        auth := c.GetHeader("Authorization")
        ar = oauth2.HandleAccessRequest(c.Request.Context(), server.ParamAccessRequest{
            Method:    "POST",
            GrantType: reqView.GrantType,
            AccessRequestParam: server.AccessRequestParam{
                Code: reqView.Code,
                ClientAuthParam: server.ClientAuthParam{
                    Authorization: auth,
                },
                RedirectUri: reqView.RedirectUri,
            },
        })

        if ar.IsError() {
            c.JSON(401, ar.GetAllOutput())
            return
        }
        err = ar.Build(server.WithAccessRequestAuthorized(true))
        if err != nil {
            c.JSON(401, err.Error())
            return
        }

        c.JSON(200, ar.GetAllOutput())
    })

    // ClientId, ClientSecret token endpoint
    router.GET("/token", func(c *gin.Context) {
        var ar *server.AccessRequest
        reqView := ReqToken{}
        err := c.Bind(&reqView)
        if err != nil {
            c.JSON(401, "参数错误")
            return
        }
        // 默认没开启GET参数访问，所以这里要注意安全问题，建议不要开启，这里为了演示，其实是给的POST，模拟的GET
        ar = oauth2.HandleAccessRequest(c.Request.Context(), server.ParamAccessRequest{
            Method:    "POST",
            GrantType: reqView.GrantType,
            AccessRequestParam: server.AccessRequestParam{
                Code: reqView.Code,
                ClientAuthParam: server.ClientAuthParam{
                    ClientId:     reqView.ClientId,
                    ClientSecret: reqView.ClientSecret,
                },
                RedirectUri: reqView.RedirectUri,
            },
        })
        if ar.IsError() {
            c.JSON(401, ar.GetAllOutput())
            return
        }
        err = ar.Build(server.WithAccessRequestAuthorized(true))
        if err != nil {
            c.JSON(401, err.Error())
            return
        }

        c.JSON(200, ar.GetAllOutput())
    })
    return router
}()).Run()
```

## 原理
### 单点登录系统
* 客户端服务端写入state信息，并生成url
* 通过浏览器请求sso，sso返回给浏览器code信息
* code信息回传给客户端的服务端，请求sso服务，获得token
* 将token存入到浏览器的http only的cookie里
* 所有接口都可以通过该token，grpc获取用户信息

## 流程
### Authorize
* 写入authorize表，生成code码
* 写入authorize过期时间

### Token
* 第一次保存token
    * save access token
    * remove authorization token
* 刷新token
    * save access token
    * remove previous access token
    
### 文献
* https://blog.lishunyang.com/2020/05/sso-summary.html