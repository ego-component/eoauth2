package main

// Open url in browser:
// http://localhost:9090/app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ego-component/eoauth2/examples"
	"github.com/ego-component/eoauth2/server"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego"
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

func main() {
	ego.New().Serve(func() *egin.Component {
		oauth2 := server.DefaultContainer().Build(server.WithStorage(examples.NewTestStorage()))
		router := egin.DefaultContainer().Build()
		router.GET("/app", func(c *gin.Context) {
			c.Writer.Write([]byte("<html><body>"))
			c.Writer.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Login</a><br/>", url.QueryEscape("http://localhost:9090/appauth/code"))))
			c.Writer.Write([]byte("</body></html>"))
			return
		})

		router.Any("/authorize", func(c *gin.Context) {
			reqView := ReqOauthLogin{}
			err := c.Bind(&reqView)
			if err != nil {
				c.JSON(401, "参数错误")
				return
			}
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

			if !HandleLoginPage(ar, c.Writer, c.Request) {
				return
			}

			err = ar.Build(
				server.WithAuthorizeRequestAuthorized(true),
				server.WithAuthorizeRequestUserData("{userInfo:1}"),
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

		// Application destination - CODE
		router.Any("/appauth/code", func(c *gin.Context) {
			r := c.Request
			w := c.Writer
			r.ParseForm()

			code := r.FormValue("code")

			w.Write([]byte("<html><body>"))
			w.Write([]byte("APP AUTH - CODE<br/>"))
			defer w.Write([]byte("</body></html>"))

			if code == "" {
				w.Write([]byte("Nothing to do"))
				return
			}

			jr := make(map[string]interface{})
			// build access code url
			aurl := fmt.Sprintf("/token?grant_type=authorization_code&client_id=1234&client_secret=aabbccdd&state=xyz&redirect_uri=%s&code=%s",
				url.QueryEscape("http://localhost:9090/appauth/code"), url.QueryEscape(code))

			// if parse, download and parse json
			if r.FormValue("doparse") == "1" {
				err := DownloadAccessToken(fmt.Sprintf("http://localhost:9090%s", aurl),
					&server.BasicAuth{"1234", "aabbccdd"}, jr)
				if err != nil {
					w.Write([]byte(err.Error()))
					w.Write([]byte("<br/>"))
				}
			}

			// show json error
			if erd, ok := jr["error"]; ok {
				w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
			}

			// show json access token
			if at, ok := jr["access_token"]; ok {
				w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
			}

			w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

			// output links
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))

			cururl := *r.URL
			curq := cururl.Query()
			curq.Add("doparse", "1")
			cururl.RawQuery = curq.Encode()
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
			return
		})

		// Access token endpoint
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
}

func HandleLoginPage(ar *server.AuthorizeRequest, w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	if r.Method == "POST" && r.FormValue("login") == "test" && r.FormValue("password") == "test" {
		return true
	}

	w.Write([]byte("<html><body>"))

	w.Write([]byte(fmt.Sprintf("LOGIN %s (use test/test)<br/>", ar.Client.GetId())))
	w.Write([]byte(fmt.Sprintf("<form action=\"/authorize?%s\" method=\"POST\">", r.URL.RawQuery)))

	w.Write([]byte("Login: <input type=\"text\" name=\"login\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<input type=\"submit\"/>"))

	w.Write([]byte("</form>"))

	w.Write([]byte("</body></html>"))

	return false
}

func DownloadAccessToken(url string, auth *server.BasicAuth, output map[string]interface{}) error {
	// download access token
	preq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	if auth != nil {
		preq.SetBasicAuth(auth.Username, auth.Password)
	}

	pclient := &http.Client{}
	presp, err := pclient.Do(preq)
	if err != nil {
		return err
	}
	defer presp.Body.Close()

	if presp.StatusCode != 200 {
		return fmt.Errorf("Invalid status code")
	}

	jdec := json.NewDecoder(presp.Body)
	err = jdec.Decode(&output)
	return err
}
