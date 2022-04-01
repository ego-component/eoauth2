package server

// AuthorizeRequestOption 可选项
type AuthorizeRequestOption func(ar *AuthorizeRequest)

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

// WithAuthorizeSsoParentToken 如果为空，那么自动生成，如果存在就使用他的
func WithAuthorizeSsoParentToken(parentToken string) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.ssoParentToken = parentToken
	}
}

func WithAuthorizeSsoUid(uid int64) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.ssoUid = uid
	}
}

func WithAuthorizeSsoPlatform(platform string) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.ssoPlatform = platform
	}
}

func WithAuthorizeSsoClientIP(clientIP string) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.ssoClientIP = clientIP
	}
}

func WithAuthorizeSsoUA(ua string) AuthorizeRequestOption {
	return func(c *AuthorizeRequest) {
		c.ssoUA = ua
	}
}
