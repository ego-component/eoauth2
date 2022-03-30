package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ego-component/eoauth2/examples/sso-multiple-account/server/pkg/invoker"
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
	router.Any("/authorize", func(c *gin.Context) {
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

		uid := HandleLoginPage(ar, c.Writer, c.Request)
		if uid == 0 {
			return
		}

		ssoServer(c, ar, uid)
		return
	})
	return router
}

func ssoServer(c *gin.Context, ar *server.AuthorizeRequest, uid int64) {
	accessToken := oauth2dto.Token{}
	token, err := c.Cookie(econf.GetString("sso.tokenCookieName"))
	if err != nil {
		accessToken = oauth2dto.NewToken(86400 * 7)
	} else {
		accessToken.Token = token
		accessToken.AuthAt = time.Now().Unix()
		accessToken.ExpiresIn = 86400 * 7
	}

	err = ar.Build(
		server.WithAuthorizeRequestAuthorized(true),
		server.WithSsoData(server.SsoData{
			ParentToken: accessToken,
			Uid:         uid,
			Platform:    "web",
		}),
	)

	if err != nil {
		c.JSON(401, err.Error())
		c.Abort()
		return
	}

	// Output redirect with parameters
	redirectUri, err := ar.GetRedirectUrl()
	if err != nil {
		c.JSON(401, "获取重定向地址失败")
		c.Abort()
		return
	}

	// 种上单点登录cookie
	c.SetCookie(econf.GetString("sso.tokenCookieName"), accessToken.Token, int(accessToken.ExpiresIn), "/", econf.GetString("sso.tokenDomain"), econf.GetBool("sso.tokenSecure"), true)
	c.Redirect(302, redirectUri)
}

func HandleLoginPage(ar *server.AuthorizeRequest, w http.ResponseWriter, r *http.Request) int64 {
	r.ParseForm()
	if r.Method == "POST" && r.FormValue("login") == "askuy1" && r.FormValue("password") == "123456" {
		return 1
	}

	if r.Method == "POST" && r.FormValue("login") == "askuy2" && r.FormValue("password") == "123456" {
		return 2
	}

	w.Write([]byte("<html><body>"))

	w.Write([]byte(fmt.Sprintf("LOGIN %s (use askuy1/123456)<br/>", ar.Client.GetId())))
	w.Write([]byte(fmt.Sprintf("LOGIN %s (use askuy2/123456)<br/>", ar.Client.GetId())))
	w.Write([]byte(fmt.Sprintf("<form action=\"/authorize?%s\" method=\"POST\">", r.URL.RawQuery)))

	w.Write([]byte("Login: <input type=\"text\" name=\"login\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<input type=\"submit\"/>"))

	w.Write([]byte("</form>"))

	w.Write([]byte("</body></html>"))
	return 0
}
