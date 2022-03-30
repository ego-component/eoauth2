package invoker

import (
	ssov1 "github.com/ego-component/eoauth2/examples/sso-one-account/proto"
	"github.com/gotomicro/ego/client/egrpc"
	"github.com/gotomicro/ego/core/econf"
	"golang.org/x/oauth2"
)

var (
	Oauth2      *oauth2.Config
	OauthConfig *oauthConfig
	SsoGrpc     ssov1.SsoClient
)

type oauthConfig struct {
	ClientId        string
	ClientSecret    string
	AuthURL         string
	TokenURL        string
	RedirectURL     string
	StateCookieName string
	TokenCookieName string
	Domain          string
}

func Init() error {
	OauthConfig = &oauthConfig{}
	err := econf.UnmarshalKey("oauth", OauthConfig)
	if err != nil {
		return nil
	}
	SsoGrpc = ssov1.NewSsoClient(egrpc.Load("oauth").Build().ClientConn)
	Oauth2 = &oauth2.Config{
		ClientID:     OauthConfig.ClientId,
		ClientSecret: OauthConfig.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  OauthConfig.AuthURL,
			TokenURL: OauthConfig.TokenURL,
		},
		RedirectURL: OauthConfig.RedirectURL,
	}
	return nil
}
