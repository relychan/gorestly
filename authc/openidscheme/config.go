package openidscheme

import (
	"errors"
	"fmt"

	"github.com/relychan/gorestly/authc/authscheme"
	"github.com/relychan/goutils"
)

var (
	ErrOpenIDConnectURLRequired = errors.New("openIdConnectUrl is required for oidc security")
)

// OpenIDConnectConfig contains configurations for [OpenID Connect] API specification
//
// [OpenID Connect]: https://swagger.io/docs/specification/authentication/openid-connect-discovery
type OpenIDConnectConfig struct {
	Type authscheme.SecuritySchemeType `json:"type" yaml:"type" jsonschema:"enum=openIdConnect"`
	// Well-known URL to discover the OpenID-Connect-Discovery provider metadata.
	OpenIDConnectURL string `json:"openIdConnectUrl" yaml:"openIdConnectUrl"`
}

var _ authscheme.SecuritySchemeDefinition = (*OpenIDConnectConfig)(nil)

// NewOpenIDConnectConfig creates a new OpenIDConnectConfig instance.
func NewOpenIDConnectConfig(oidcURL string) *OpenIDConnectConfig {
	return &OpenIDConnectConfig{
		Type:             authscheme.OpenIDConnectScheme,
		OpenIDConnectURL: oidcURL,
	}
}

// GetType get the type of security scheme.
func (ss OpenIDConnectConfig) GetType() authscheme.SecuritySchemeType {
	return ss.Type
}

// Validate if the current instance is valid.
func (ss OpenIDConnectConfig) Validate(strict bool) error {
	if ss.OpenIDConnectURL == "" {
		return ErrOpenIDConnectURLRequired
	}

	if _, err := goutils.ParseRelativeOrHTTPURL(ss.OpenIDConnectURL); err != nil {
		return fmt.Errorf("openIdConnectUrl: %w", err)
	}

	return nil
}
