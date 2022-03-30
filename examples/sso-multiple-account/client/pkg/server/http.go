package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ego-component/eoauth2/examples/sso-multiple-account/client/pkg/invoker"
	ssov1 "github.com/ego-component/eoauth2/examples/sso-multiple-account/proto"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/gotomicro/ego/server/egin"
	"github.com/spf13/cast"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// OauthState base 64 编码 referer和state信息
type OauthState struct {
	State   string `json:"state"`
	Referer string `json:"referer"`
}

var (
	AuthKey = "auth_key"
)

func ServeHttp() *egin.Component {
	router := egin.Load("server.http").Build()
	router.GET("/", checkToken(), func(ctx *gin.Context) {
		user, exists := ctx.Get(AuthKey)
		if !exists {
			ctx.Writer.Write([]byte("<html><body>"))
			ctx.Writer.Write([]byte("<a href=\"/login\">Login</a><br/>"))
			ctx.Writer.Write([]byte("</body></html>"))
			return
		}

		token, _ := ctx.Cookie(invoker.OauthConfig.TokenCookieName)
		userInfos := user.([]*ssov1.User)
		ctx.Writer.Write([]byte("<html><body><br>"))
		for _, userInfo := range userInfos {
			ctx.Writer.Write([]byte("uid:" + cast.ToString(userInfo.Uid) + ",nickname:" + userInfo.Nickname + "<br>"))
		}
		ctx.Writer.Write([]byte("token:" + token + "<br>"))
		ctx.Writer.Write([]byte("<a href=\"/login\" target=\"/_blank\">Login</a><br/>"))
		ctx.Writer.Write([]byte("<a href=\"/logout\" target=\"/_blank\">Logout</a><br/>"))
		ctx.Writer.Write([]byte("<a href=\"/refreshToken\" target=\"/_blank\">refresh token</a><br/>"))
		ctx.Writer.Write([]byte("</body></html>"))
		return
	})

	router.GET("/login", func(ctx *gin.Context) {
		// todo 安全验证来源
		referer := "/"
		refererQuery := ctx.Query("referer")
		if refererQuery != "" {
			referer = refererQuery
		}
		// 安全验证，生成随机state，防止获取系统的url，登录该系统
		state, err := genRandState()
		if err != nil {
			ctx.JSON(401, "生成随机state信息失败"+err.Error())
			return
		}
		oauthState := OauthState{
			State:   state,
			Referer: referer,
		}
		oauthStateStr, err := json.Marshal(oauthState)
		if err != nil {
			ctx.JSON(401, "编码state信息失败"+err.Error())
			return
		}
		sEnc := base64.RawURLEncoding.EncodeToString(oauthStateStr)
		// 使用密钥加密，后面在/oauth/code，拿到state信息后，会做一次验证，看state是否伪造
		hashedState := hashStateCode(state)
		// 最大300s
		ctx.SetCookie(invoker.OauthConfig.StateCookieName, url.QueryEscape(hashedState), 300, "/", invoker.OauthConfig.Domain, false, true)
		ctx.Redirect(http.StatusFound, invoker.Oauth2.AuthCodeURL(sEnc, oauth2.AccessTypeOnline))
		return
	})

	router.GET("/oauth/code", func(ctx *gin.Context) {
		r := ctx.Request
		code := r.FormValue("code")
		stateBase64 := r.FormValue("state")
		resBytes, err := base64.RawURLEncoding.DecodeString(stateBase64)
		if err != nil {
			ctx.JSON(401, "base64解码state信息失败: "+err.Error())
			return
		}
		oauthState := OauthState{}
		err = json.Unmarshal(resBytes, &oauthState)
		if err != nil {
			ctx.JSON(401, "json解码state信息失败: "+err.Error())
			return
		}

		cookieState, err := ctx.Cookie(invoker.OauthConfig.StateCookieName)
		if err != nil {
			// 找不到OauthStateCookieName，则重新跳转到业务根路径
			elog.Error("cookie not found", zap.String("code", code), zap.String("state", oauthState.State))
			ctx.Redirect(http.StatusFound, parseHost(invoker.OauthConfig.RedirectURL))
			return
		}

		// delete cookie
		ctx.SetCookie(invoker.OauthConfig.StateCookieName, "", -1, "/", "", false, true)
		if cookieState == "" {
			ctx.JSON(401, "login oauth state miss")
			return
		}

		queryState := hashStateCode(oauthState.State)
		elog.Info("state check", zap.Any("queryState", queryState), zap.Any("cookieState", cookieState))
		// 使用密钥加密，拿到state信息后，做一次验证，看state是否伪造
		if cookieState != queryState {
			ctx.JSON(401, "state mismatch")
			return
		}

		newCtx, _ := context.WithTimeout(ctx.Request.Context(), 3*time.Second)

		// access info
		accessInfo, err := invoker.SsoGrpc.GetToken(newCtx, &ssov1.GetTokenRequest{
			Code:          code,
			Authorization: "Basic " + basicAuth(invoker.OauthConfig.ClientId, invoker.OauthConfig.ClientSecret),
		})
		if err != nil {
			ctx.JSON(401, "获取access token信息失败"+err.Error())
			return
		}
		//userResp, err := invoker.SsoGrpc.GetUserByToken(ctx, &ssov1.GetUserByTokenRequest{
		//	Token: accessInfo.Token,
		//})
		//
		//if err != nil {
		//	ctx.JSON(401, "获取用户信息失败"+err.Error())
		//	return
		//}
		ctx.SetCookie(invoker.OauthConfig.TokenCookieName, accessInfo.Token, int(accessInfo.ExpiresIn), "/", "", false, true)
		ctx.Redirect(http.StatusFound, oauthState.Referer)
	})

	router.GET("/refreshToken", func(ctx *gin.Context) {
		token, err := ctx.Cookie(invoker.OauthConfig.TokenCookieName)
		if err != nil {
			ctx.JSON(401, "获取登录态token失败: "+err.Error())
			return
		}
		newCtx, _ := context.WithTimeout(ctx.Request.Context(), 3*time.Second)
		// access info
		accessInfo, err := invoker.SsoGrpc.RefreshToken(newCtx, &ssov1.RefreshTokenRequest{
			Code:          token,
			Authorization: "Basic " + basicAuth(invoker.OauthConfig.ClientId, invoker.OauthConfig.ClientSecret),
		})
		if err != nil {
			ctx.JSON(401, "获取access token信息失败"+err.Error())
			return
		}
		ctx.SetCookie(invoker.OauthConfig.TokenCookieName, accessInfo.Token, int(accessInfo.ExpiresIn), "/", "", false, true)
	})

	router.GET("/logout", func(ctx *gin.Context) {
		token, err := ctx.Cookie(invoker.OauthConfig.TokenCookieName)
		if err != nil {
			ctx.JSON(401, "获取登录态token失败: "+err.Error())
			return
		}

		_, err = invoker.SsoGrpc.RemoveToken(ctx, &ssov1.RemoveTokenRequest{
			Token: token,
		})
		if err != nil {
			ctx.JSON(401, "获取remove access token信息失败"+err.Error())
			return
		}
		ctx.SetCookie(invoker.OauthConfig.TokenCookieName, "", -1, "/", invoker.OauthConfig.Domain, false, true)
		ctx.JSON(200, "清除成功")
	})
	return router
}

func checkToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, err := ctx.Cookie(invoker.OauthConfig.TokenCookieName)
		if err != nil {
			ctx.Next()
			return
		}
		userByToken, err := invoker.SsoGrpc.GetUsersByToken(ctx, &ssov1.GetUsersByTokenRequest{
			Token: token,
		})
		if err != nil {
			ctx.Next()
			return
		}
		ctx.Set(AuthKey, userByToken.GetUser())
		ctx.Next()
	}
}

func genRandState() (string, error) {
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		elog.Error("failed to generate state string", zap.Error(err))
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rnd), nil
}

func hashStateCode(code string) string {
	hashBytes := sha256.Sum256([]byte(code + invoker.OauthConfig.ClientSecret))
	return hex.EncodeToString(hashBytes[:])
}

// parseHost 从url解析出协议和域名
func parseHost(u string) string {
	res, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", res.Scheme, res.Host)
}

// See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64
// encoded string in the credentials."
// It is not meant to be urlencoded.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
