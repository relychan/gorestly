package authc

import (
	"errors"
	"fmt"

	"github.com/relychan/gorestly/authc/apikey"
	"github.com/relychan/gorestly/authc/authscheme"
	"github.com/relychan/gorestly/authc/basicauth"
	"github.com/relychan/gorestly/authc/httpauth"
	"github.com/relychan/gorestly/authc/mutualtls"
	"github.com/relychan/gorestly/authc/oauth2scheme"
	"github.com/relychan/gorestly/authc/openidscheme"
)

// create an injector from RestlySecurityScheme configuration.
func NewInjectorFromConfig(config RestlyAuthConfig, hasTLS bool) (authscheme.HTTPAuthInjector, error) {
	switch conf := config.SecuritySchemeDefinition.(type) {
	case *apikey.APIKeyAuthConfig:
		return apikey.NewApiKeyCredential(conf)
	case *basicauth.BasicAuthConfig:
		return basicauth.NewBasicCredential(conf)
	case *httpauth.HTTPAuthConfig:
		return httpauth.NewHTTPCredential(conf)
	case *oauth2scheme.OAuth2Config:
		return oauth2scheme.NewOAuth2Client(conf)
	case *openidscheme.OpenIDConnectConfig:
		return openidscheme.NewOpenIDConnectClient(conf)
	case *mutualtls.MutualTLSAuthConfig:
		if !hasTLS {
			return nil, errors.New("tls config is required for mutualTLS authentication")
		}

		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported security scheme: %s", config.SecuritySchemeDefinition.GetType())
	}
}
