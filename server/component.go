package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/ego-component/eoauth2/server/model"
	"github.com/gotomicro/ego/core/elog"
	"github.com/pborman/uuid"
)

// Component ...
type Component struct {
	name   string
	config *Config
	logger *elog.Component
}

func newComponent(name string, config *Config, logger *elog.Component) *Component {
	cron := &Component{
		config: config,
		name:   name,
		logger: logger,
	}
	return cron
}

type AuthorizeRequestParam struct {
	ClientId            string
	RedirectUri         string
	Scope               string
	State               string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
}

// HandleAuthorizeRequest for handling
func (c *Component) HandleAuthorizeRequest(ctx context.Context, param AuthorizeRequestParam) *AuthorizeRequest {
	ret := &AuthorizeRequest{
		State: param.State,
		Scope: param.Scope,
		Context: &Context{
			Ctx:    ctx,
			logger: c.logger,
			output: make(ResponseData),
		},
		storage:               c.config.storage,
		config:                c.config,
		ParentTokenExpiration: c.config.ParentTokenExpiration,
	}

	if c.config.EnableAccessInterceptor {
		c.logger.Info("HandleAuthorizeRequest access", elog.FieldCtxTid(ctx), elog.FieldValueAny(param))
	}

	requestType := AuthorizeRequestType(param.ResponseType)
	// 如果不存在该类型，直接返回错误，默认支持 code、login类型
	if !c.config.AllowedAuthorizeTypes.Exists(requestType) {
		ret.setError(E_UNSUPPORTED_RESPONSE_TYPE, nil, "HandleAuthorizeRequest", "response type invalid")
		return ret
	}

	// 如果是直接登录，那么就不需要任何校验
	if requestType == LOGIN {
		ret.Type = LOGIN
		ret.Client = &DefaultClient{} // 直接登录，不需要这个数据，但是有的地方会取id号，所以默认给一个
		ret.Expiration = c.config.TokenExpiration
		return ret
	}

	if param.ClientId == "" {
		ret.setError(E_UNAUTHORIZED_CLIENT, fmt.Errorf("client is empty"), "HandleAuthorizeRequest", "client is empty")
		return ret
	}

	ret.Context.SetOutput("state", param.State)

	// create the authorization request
	unescapedUri, err := url.QueryUnescape(param.RedirectUri)
	if err != nil {
		ret.setError(E_INVALID_REQUEST, err, "HandleAuthorizeRequest", "unescapedUri error")
		return ret
	}

	ret.redirectUri = unescapedUri

	// must have a valid client
	ret.Client, err = ret.storage.GetClient(ctx, param.ClientId)
	if errors.Is(err, ErrNotFound) {
		ret.setError(E_UNAUTHORIZED_CLIENT, err, "HandleAuthorizeRequest", "client not found")
		return ret
	}
	if err != nil {
		ret.setError(E_SERVER_ERROR, err, "HandleAuthorizeRequest", "get client error")
		return ret
	}
	if ret.Client == nil {
		ret.setError(E_UNAUTHORIZED_CLIENT, nil, "HandleAuthorizeRequest", "client is empty")
		return ret
	}
	if ret.Client.GetRedirectUri() == "" {
		ret.setError(E_UNAUTHORIZED_CLIENT, nil, "HandleAuthorizeRequest", "redirect uri is empty")
		return ret
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if ret.redirectUri == "" && FirstUri(ret.Client.GetRedirectUri(), c.config.RedirectUriSeparator) == ret.Client.GetRedirectUri() {
		ret.redirectUri = FirstUri(ret.Client.GetRedirectUri(), c.config.RedirectUriSeparator)
	}

	if realRedirectUri, err := ValidateUriList(ret.Client.GetRedirectUri(), ret.redirectUri, c.config.RedirectUriSeparator); err != nil {
		ret.setError(E_INVALID_REQUEST, err, "HandleAuthorizeRequest", "validate uri error")
		return ret
	} else {
		ret.redirectUri = realRedirectUri
	}

	switch requestType {
	case CODE:
		ret.Type = CODE
		ret.Expiration = c.config.AuthorizationExpiration
		codeChallenge := param.CodeChallenge
		if len(codeChallenge) != 0 {
			codeChallengeMethod := param.CodeChallengeMethod
			// allowed values are "plain" (default) and "S256", per https://tools.ietf.org/html/rfc7636#section-4.3
			if len(codeChallengeMethod) == 0 {
				codeChallengeMethod = PKCE_PLAIN
			}
			if codeChallengeMethod != PKCE_PLAIN && codeChallengeMethod != PKCE_S256 {
				// https://tools.ietf.org/html/rfc7636#section-4.4.1
				ret.setError(E_INVALID_REQUEST, fmt.Errorf("code_challenge_method transform algorithm not supported (rfc7636)"), "HandleAuthorizeRequest", "PKCE error")
				return ret
			}

			// https://tools.ietf.org/html/rfc7636#section-4.2
			if matched := pkceMatcher.MatchString(codeChallenge); !matched {
				ret.setError(E_INVALID_REQUEST, fmt.Errorf("code_challenge invalid (rfc7636)"), "HandleAuthorizeRequest", "pkceMatcher invalid")
				return ret
			}

			ret.CodeChallenge = codeChallenge
			ret.CodeChallengeMethod = codeChallengeMethod
			return ret
		}

		// Optional PKCE support (https://tools.ietf.org/html/rfc7636)
		if c.config.RequirePKCEForPublicClients && CheckClientSecret(ret.Client, "") {
			// https://tools.ietf.org/html/rfc7636#section-4.4.1
			ret.setError(E_INVALID_REQUEST, fmt.Errorf("code_challenge (rfc7636) required for public clients"), "HandleAuthorizeRequest", "CheckClientSecret invalid")
			return ret
		}
	case TOKEN:
		ret.Type = TOKEN
		ret.Expiration = c.config.TokenExpiration
	}
	return ret

}

// Build 处理authorize请求
func (r *AuthorizeRequest) Build(options ...AuthorizeRequestOption) error {
	// don't process if is already an error
	if r.IsError() {
		return fmt.Errorf("AuthorizeRequestBuild failed1, err: %w", r.responseErr)
	}

	for _, option := range options {
		option(r)
	}

	// 设置跳转地址
	r.setRedirect(r.redirectUri)

	if !r.authorized {
		// redirect with error
		r.setError(E_ACCESS_DENIED, nil, "AuthorizeRequestBuild", "authorize invalid")
		return fmt.Errorf("AuthorizeRequestBuild failed2, err: %w", r.responseErr)
	}

	switch r.Type {
	// todo 未验证过
	case TOKEN:
		// generate token directly
		ret := &AccessRequest{
			Type:            IMPLICIT,
			Code:            "",
			Client:          r.Client,
			RedirectUri:     r.redirectUri,
			Scope:           r.Scope,
			GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
			authorized:      true,
			TokenExpiration: r.Expiration,
			userData:        r.userData,
			Context:         r.Context,
			config:          r.config,
		}
		ret.setRedirectFragment(true)
		ret.Build()
		return nil
	case CODE:
		// 根据可选参数，生成sso data数据
		r.generateSsoData()
		// 已验证过
		// generate authorization token
		ret := &AuthorizeData{
			Client:               r.Client,
			CreatedAt:            time.Now(),
			ExpiresIn:            r.Expiration,
			ParentTokenExpiresIn: r.ParentTokenExpiration,
			RedirectUri:          r.redirectUri,
			State:                r.State,
			Scope:                r.Scope,
			UserData:             r.userData,
			// Optional PKCE challenge
			CodeChallenge:       r.CodeChallenge,
			CodeChallengeMethod: r.CodeChallengeMethod,
			Context:             r.Context,
			storage:             r.storage,
			SsoData:             r.ssoData,
		}

		var err error
		// generate token code
		ret.Code = base64.RawURLEncoding.EncodeToString(uuid.NewRandom())

		// save authorization token
		if err = ret.storage.SaveAuthorize(r.Ctx, ret); err != nil {
			ret.setError(E_SERVER_ERROR, err, "AuthorizeRequestBuild", "SaveAuthorize error")
			return fmt.Errorf("build error4, err: %w", r.responseErr)
		}

		r.setParentToken(ret.SsoData.Token)
		// redirect with code
		r.SetOutput("code", ret.Code)
		r.SetOutput("state", ret.State)
		return nil
	case LOGIN:
		// 根据可选参数，生成sso data数据
		r.generateSsoData()
		// generate authorization token
		ret := &AuthorizeData{
			Client:               r.Client,
			CreatedAt:            time.Now(),
			ExpiresIn:            r.Expiration,
			ParentTokenExpiresIn: r.ParentTokenExpiration,
			RedirectUri:          r.redirectUri,
			State:                r.State,
			Scope:                r.Scope,
			Context:              r.Context,
			storage:              r.storage,
			SsoData:              r.ssoData,
		}

		var err error
		// save authorization token
		if err = ret.storage.SaveAuthorize(r.Ctx, ret); err != nil {
			ret.setError(E_SERVER_ERROR, err, "AuthorizeRequestBuild", "SaveAuthorize error")
			return fmt.Errorf("build error4, err: %w", r.responseErr)
		}
		r.setParentToken(ret.SsoData.Token)
		return nil
	}
	return fmt.Errorf("not exist type")
}

func (r *AuthorizeRequest) generateSsoData() {
	ssoParentToken := model.NewToken(r.ParentTokenExpiration)
	// 如果自己设置了sso ptoken，那么使用用户定义的，因为可能是多账号登录
	if r.ssoParentToken != "" {
		ssoParentToken.Token = r.ssoParentToken
	}
	r.ssoData = model.ParentToken{
		Token: ssoParentToken,
		Uid:   r.ssoUid,
		StoreData: model.ParentTokenData{
			Ctime:    time.Now().Unix(),
			Platform: r.ssoPlatform,
			ClientIP: r.ssoClientIP,
			UA:       r.ssoUA,
		},
	}

}

type ParamAccessRequest struct {
	Method    string
	GrantType string
	AccessRequestParam
}

// HandleAccessRequest is the http.HandlerFunc for handling access token requests
func (c *Component) HandleAccessRequest(ctx context.Context, param ParamAccessRequest) *AccessRequest {
	ret := &AccessRequest{
		Context: &Context{
			Ctx:    ctx,
			logger: c.logger,
			output: make(ResponseData),
		},
		config: c.config,
	}

	if c.config.EnableAccessInterceptor {
		c.logger.Info("HandleAccessRequest access", elog.FieldCtxTid(ctx), elog.FieldAddr(param.ClientId))
	}

	// Only allow GET or POST
	if param.Method == "GET" {
		if !c.config.AllowGetAccessRequest {
			ret.setError(E_INVALID_REQUEST, errors.New("Request must be POST"), "HandleAccessRequest", "GET request not allowed")
			return ret
		}
	} else if param.Method != "POST" {
		ret.setError(E_INVALID_REQUEST, errors.New("Request must be POST"), "HandleAccessRequest", "request must be POST")
		return ret
	}

	grantType := AccessRequestType(param.GrantType)
	if !c.config.AllowedAccessTypes.Exists(grantType) {
		ret.setError(E_UNSUPPORTED_GRANT_TYPE, nil, "HandleAccessRequest", "unknown grant type, type="+string(grantType))
		return ret
	}
	switch grantType {
	case AUTHORIZATION_CODE:
		return ret.handleAuthorizationCodeRequest(ctx, param.AccessRequestParam)
	case REFRESH_TOKEN:
		return ret.handleRefreshTokenRequest(ctx, param.AccessRequestParam)
		//case PASSWORD:
		//	return s.handlePasswordRequest(w, r)
		//case CLIENT_CREDENTIALS:
		//	return s.handleClientCredentialsRequest(w, r)
		//case ASSERTION:
		//	return s.handleAssertionRequest(w, r)
	}
	return ret
}
