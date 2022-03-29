package server

import (
	"fmt"
	"net/http"

	"github.com/ego-component/eoauth2/examples/sso/server/pkg/invoker"
	"github.com/ego-component/eoauth2/server"
	oauth2dto "github.com/ego-component/eoauth2/storage/dto"
	"github.com/gin-gonic/gin"
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

		if !HandleLoginPage(ar, c.Writer, c.Request) {
			return
		}
		accessToken := oauth2dto.NewToken(86400 * 7)

		err = ar.Build(
			server.WithAuthorizeRequestAuthorized(true),
			server.WithAuthorizeRequestUserData(`{"uid"":1,"nickname":"askuy"}`),
			server.WithSsoData(server.SsoData{
				ParentToken: accessToken,
				Uid:         1,
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
		c.Redirect(302, redirectUri)
		return
	})
	return router
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
