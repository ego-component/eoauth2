package server

// AccessRequestOption 可选项
type AccessRequestOption func(ar *AccessRequest)

// WithAccessRequestAuthorized 设置authorized flag
func WithAccessRequestAuthorized(flag bool) AccessRequestOption {
	return func(c *AccessRequest) {
		c.authorized = flag
	}
}

func WithAccessAuthUA(authUA string) AccessRequestOption {
	return func(c *AccessRequest) {
		c.authUA = authUA
	}
}

func WithAccessAuthClientIP(clientIP string) AccessRequestOption {
	return func(c *AccessRequest) {
		c.authClientIP = clientIP
	}
}
