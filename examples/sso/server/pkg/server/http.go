package server

import (
	"fmt"
	"net/http"

	"github.com/ego-component/eoauth2/examples/sso/server/pkg/invoker"
	"github.com/ego-component/eoauth2/server"
	oauth2dto "github.com/ego-component/eoauth2/storage/dto"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/econf"
	"github.com/gotomicro/ego/server/egin"
)

type ReqOauthLogin struct {
	RedirectUri  string `json:"redirect_uri" form:"redirect_uri"` // redirect by backend
	ClientId     string `json:"client_id" form:"client_id"`
	ResponseType string `json:"response_type" form:"response_type"`
	State        string `json:"state" form:"state"`
	Scope        string `json:"scope" form:"scope"`
}

type ReqToken struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	ClientId     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	RedirectUri  string `json:"redirect_uri" form:"redirect_uri"`
}

func ServeHttp() *egin.Component {
	router := egin.Load("server.http").Build()
	router.Any("/authorize", checkToken(), func(c *gin.Context) {
		reqView := ReqOauthLogin{}
		err := c.Bind(&reqView)
		if err != nil {
			c.JSON(401, "参数错误")
			return
		}
		ar := invoker.SsoComponent.HandleAuthorizeRequest(c.Request.Context(), server.AuthorizeRequestParam{
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

		if !HandleLoginPage(ar, c.Writer, c.Request) {
			return
		}

		ssoServer(c, ar, 1)
		return
	})
	return router
}

// checkToken 判断是否已经有登录态
func checkToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		reqView := ReqOauthLogin{
			ResponseType: "code",
		}
		err := ctx.Bind(&reqView)
		if err != nil {
			ctx.Next()
			return
		}

		ar := invoker.SsoComponent.HandleAuthorizeRequest(ctx.Request.Context(), server.AuthorizeRequestParam{
			ClientId:     reqView.ClientId,
			RedirectUri:  reqView.RedirectUri,
			Scope:        reqView.Scope,
			State:        reqView.State,
			ResponseType: reqView.ResponseType,
		})
		if ar.IsError() {
			ctx.JSON(401, ar.GetAllOutput())
			return
		}

		token, err := ctx.Cookie(econf.GetString("sso.tokenCookieName"))
		if err != nil {
			ctx.Next()
			return
		}

		uid, err := invoker.TokenStorage.GetUidByParentToken(ctx.Request.Context(), token)
		if err != nil {
			ctx.Next()
			return
		}
		ssoServer(ctx, ar, uid)
	}
}

func ssoServer(c *gin.Context, ar *server.AuthorizeRequest, uid int64) {
	accessToken := oauth2dto.NewToken(86400 * 7)
	err := ar.Build(
		server.WithAuthorizeRequestAuthorized(true),
		server.WithAuthorizeRequestUserData(`{"uid"":1,"nickname":"askuy"}`),
		server.WithSsoData(server.SsoData{
			ParentToken: accessToken,
			Uid:         uid,
			Platform:    "web",
		}),
	)

	if err != nil {
		c.JSON(401, err.Error())
		return
	}

	// Output redirect with parameters
	redirectUri, err := ar.GetRedirectUrl()
	if err != nil {
		c.JSON(401, "获取重定向地址失败")
		return
	}

	// 种上单点登录cookie
	c.SetCookie(econf.GetString("sso.tokenCookieName"), accessToken.Token, int(accessToken.ExpiresIn), "/", econf.GetString("sso.tokenDomain"), econf.GetBool("sso.tokenSecure"), true)
	c.Redirect(302, redirectUri)
}

func HandleLoginPage(ar *server.AuthorizeRequest, w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	if r.Method == "POST" && r.FormValue("login") == "askuy" && r.FormValue("password") == "123456" {
		return true
	}

	w.Write([]byte("<html><body>"))

	w.Write([]byte(fmt.Sprintf("LOGIN %s (use askuy/123456)<br/>", ar.Client.GetId())))
	w.Write([]byte(fmt.Sprintf("<form action=\"/authorize?%s\" method=\"POST\">", r.URL.RawQuery)))

	w.Write([]byte("Login: <input type=\"text\" name=\"login\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<input type=\"submit\"/>"))

	w.Write([]byte("</form>"))

	w.Write([]byte("</body></html>"))
	return false
}
