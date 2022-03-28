package server

import (
	"github.com/ego-component/eoauth2/storage/dto"
)

// AuthorizeRequestOption 可选项
type AuthorizeRequestOption func(ar *AuthorizeRequest)

type SsoData struct {
	ParentToken dto.Token
	Uid         int64
	Platform    string
}

// WithAuthorizeRequestUserData 设置authorize的user data信息
func WithAuthorizeRequestUserData(userData interface{}) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.userData = userData
	}
}

// WithAuthorizeRequestAuthorized 设置authorize的flag信息
func WithAuthorizeRequestAuthorized(flag bool) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.authorized = flag
	}
}

func WithSsoData(data SsoData) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.ssoData = data
	}
}
