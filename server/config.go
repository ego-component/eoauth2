package server

const PackageName = "component.eoauth2.server"

// Config contains server configuration information
type Config struct {
	EnableAccessInterceptor bool                  // 是否开启，记录请求数据
	EnableMultipleAccount   bool                  // 是否启用多账号
	AuthorizationExpiration int64                 // Authorization token expiration in seconds (default 5 minutes)
	TokenExpiration         int64                 // Sub Token expiration in seconds (default 1 day)
	TokenType               string                // Token type to return
	ParentTokenExpiration   int64                 // Parent Token expiration
	AllowedAuthorizeTypes   AllowedAuthorizeTypes // List of allowed authorize types (only CODE by default)
	AllowedAccessTypes      AllowedAccessTypes    // List of allowed access types (only AUTHORIZATION_CODE by default)
	// HTTP status code to return for errors - default 200
	// Only used if response was created from server
	ErrorStatusCode int
	// If true allows client secret also in params, else only in
	// Authorization header - default true
	AllowClientSecretInParams bool
	// If true allows access request using GET, else only POST - default false
	AllowGetAccessRequest bool
	// Require PKCE for code flows for public OAuth clients - default false
	RequirePKCEForPublicClients bool
	// Separator to support multiple URIs in Client.GetRedirectUri().
	// If blank (the default), don't allow multiple URIs.
	RedirectUriSeparator string
	// RetainTokenAfter Refresh allows the server to retain the access and
	// refresh token for re-use - default false
	RetainTokenAfterRefresh bool
	storage                 Storage
}

// DefaultConfig ...
func DefaultConfig() *Config {
	return &Config{
		AuthorizationExpiration:     300,
		TokenExpiration:             3600 * 24,      // 默认一天
		ParentTokenExpiration:       3600 * 24 * 30, // 默认30天
		TokenType:                   "Bearer",
		AllowedAuthorizeTypes:       AllowedAuthorizeTypes{CODE, LOGIN},
		AllowedAccessTypes:          AllowedAccessTypes{AUTHORIZATION_CODE, REFRESH_TOKEN},
		ErrorStatusCode:             200,
		AllowClientSecretInParams:   true,
		AllowGetAccessRequest:       false,
		RequirePKCEForPublicClients: false,
		RedirectUriSeparator:        "",
		RetainTokenAfterRefresh:     false,
	}
}

// AllowedAuthorizeTypes is a collection of allowed auth request types
type AllowedAuthorizeTypes []AuthorizeRequestType

// Exists returns true if the auth type exists in the list
func (t AllowedAuthorizeTypes) Exists(rt AuthorizeRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// AllowedAccessTypes is a collection of allowed access request types
type AllowedAccessTypes []AccessRequestType

// Exists returns true if the access type exists in the list
func (t AllowedAccessTypes) Exists(rt AccessRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}
