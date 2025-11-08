package authc

import (
	"fmt"

	"github.com/relychan/gorestly/authc/authscheme"
	"github.com/relychan/gorestly/authc/basicauth"
	"github.com/relychan/gorestly/authc/httpauth"
	"github.com/relychan/gorestly/authc/oauth2scheme"
)

// NewInjectorFromConfig creates an injector from RestlySecurityScheme configuration.
func NewInjectorFromConfig(config RestlyAuthConfig) (authscheme.HTTPClientAuthInjector, error) {
	switch conf := config.HTTPClientAuthDefinition.(type) {
	case *basicauth.BasicAuthConfig:
		return basicauth.NewBasicCredential(conf)
	case *httpauth.HTTPAuthConfig:
		return httpauth.NewHTTPCredential(conf)
	case *oauth2scheme.OAuth2Config:
		return oauth2scheme.NewOAuth2Client(conf)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedSecurityScheme, config.GetType())
	}
}
