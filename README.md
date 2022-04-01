# eoauth2 组件使用指南

## 简介

- 根据开源项目 [https://github.com/openshift/osin](https://github.com/openshift/osin) 做了大量改造
- 支持http oauth2 server
- 支持grpc oauth2 server
- 支持多客户端的sso服务
- 支持类似notion，多账户登录同一个网页
- 支持后台踢掉某个终端登录态
- 支持配置终端个数，挤下线
- 支持查看token信息，例如UA，client ip, platform

## Example

### Oauth2登录

```bash
cd examples/simple && EGO_DEBUG=true && go run main.go
// 访问 http://127.0.0.1:9090/app
```

### 单点登录

* [单点登录文档](./examples/sso-one-account/readme.md)
* [单点登录Examples](./examples/sso-one-account/makefile)

## Example Oauth2 Server

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
router.Any("/authorize", func (c *gin.Context) {
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
router.POST("/token", func (c *gin.Context) {
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
router.GET("/token", func (c *gin.Context) {
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

## 单点登录

### 流程

* 客户端服务端写入state信息，并生成url
* 通过浏览器请求sso，sso返回给浏览器code信息
* code信息回传给客户端的服务端，请求sso服务，获得token
* 将token存入到浏览器的http only的cookie里
* 所有接口都可以通过该token，grpc获取用户信息

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

### SDK API说明

```go
// 获取sso的用户信息
router.GET("/user", func (c *gin.Context) {
info, err := invoker.TokenStorage.GetAPI().GetAllByUser(c.Request.Context(), cast.ToInt64(c.Query("uid")))
if err != nil {
c.JSON(200, err.Error())
return
}
c.JSON(200, info)
})

// 获取sso的长token信息
router.GET("/parentToken", func (c *gin.Context) {
info, err := invoker.TokenStorage.GetAPI().GetAllByParentToken(c.Request.Context(), c.Query("token"))
if err != nil {
c.JSON(200, err.Error())
return
}
c.JSON(200, info)
})

// 获取sso的短token信息
router.GET("/subToken", func (c *gin.Context) {
info, err := invoker.TokenStorage.GetAPI().GetAllBySubToken(c.Request.Context(), c.Query("token"))
if err != nil {
c.JSON(200, err.Error())
return
}
c.JSON(200, info)
})
```

#### 获取sso的用户信息

```json
{
  "ctime": 0,
  "clients": {
    "j14vJUQAQlCKA8D0TMIG4w": {
      "token": "j14vJUQAQlCKA8D0TMIG4w",
      "authAt": 1648802442,
      "expiresIn": 2592000
    }
  },
  "expireTimeList": [
    {
      "field": "_c:j14vJUQAQlCKA8D0TMIG4w",
      "expireTime": 1651394442
    }
  ],
  "ttl": 2591922
}
```

#### 获取sso的长token信息

```json
{
  "ctime": 1648802442,
  "uids": [
    1
  ],
  "clients": {
    "ebZJXwzXSQmJmAKOX8-gKQ": {
      "token": "ebZJXwzXSQmJmAKOX8-gKQ",
      "authAt": 1648802442,
      "expiresIn": 86400
    }
  },
  "users": {
    "1": {
      "ctime": 1648802442,
      "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36",
      "clientIp": "::1",
      "platform": "web"
    }
  },
  "expireTimeList": [
    {
      "field": "_c:ebZJXwzXSQmJmAKOX8-gKQ",
      "expireTime": 1648888842
    }
  ],
  "ttl": 2591978
}
```

#### 获取sso的短token信息

```json
{
  "ctime": 1648802442,
  "parentToken": "j14vJUQAQlCKA8D0TMIG4w",
  "clientId": "1234",
  "tokenInfo": {
    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36",
    "clientIP": "::1"
  },
  "accessInfo": {
    "clientId": "1234",
    "previous": "",
    "accessToken": "ebZJXwzXSQmJmAKOX8-gKQ",
    "expiresIn": 86400,
    "scope": "",
    "redirectUri": "http://localhost:29001/oauth/code",
    "ctime": 1648802442
  },
  "ttl": 86361
}
```

#### SSO Redis key配置说明

```makefile
获取parent token信息
hgetall sso:ptk:_xryboGNQU-490RpAOBMYQ

获取sub token信息
hgetall sso:stk:n3lgZ-jbR9OlVAfQxh2Hnw

获取uid信息
hgetall sso:uid:1
```

### 文献

* https://blog.lishunyang.com/2020/05/sso-summary.html