package httpauth

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/gorestly/authc/authscheme"
)

// HTTPAuthConfig contains configurations for http authentication
// If the scheme is [bearer], the authenticator follows OpenAPI 3 specification.
//
// [bearer]: https://swagger.io/docs/specification/authentication/bearer-authentication
type HTTPAuthConfig struct {
	Type authscheme.HTTPClientAuthType `json:"type" jsonschema:"enum=http" yaml:"type"`
	// Name of the field to validate, for example, Authorization header.
	Header string `json:"header" jsonschema:"default=Authorization" yaml:"header"`
	// The name of the HTTP Authentication scheme to be used in the Authorization header as defined in RFC7235.
	// The values used SHOULD be registered in the IANA Authentication Scheme registry. https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
	// The value is case-insensitive, as defined in RFC7235.
	Scheme string `json:"scheme" jsonschema:"default=bearer" yaml:"scheme"`
	// Value of the access token.
	Value goenvconf.EnvString `json:"value" yaml:"value"`
	// A description for security scheme.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

var _ authscheme.HTTPClientAuthDefinition = (*HTTPAuthConfig)(nil)

// NewHTTPAuthConfig creates a new HTTPAuthConfig instance.
func NewHTTPAuthConfig(scheme string, header string, value goenvconf.EnvString) *HTTPAuthConfig {
	return &HTTPAuthConfig{
		Type:   authscheme.HTTPAuthScheme,
		Header: header,
		Scheme: scheme,
		Value:  value,
	}
}

// Validate if the current instance is valid.
func (ss HTTPAuthConfig) Validate(_ bool) error {
	authType := ss.GetType()

	if ss.Type != authType {
		return authscheme.NewUnmatchedSecuritySchemeError(authType, ss.Type)
	}

	if ss.Scheme == "" {
		return authscheme.NewRequiredSecurityFieldError(authType, "scheme")
	}

	if ss.Header == "" {
		return authscheme.NewRequiredSecurityFieldError(authType, "header")
	}

	return nil
}

// GetType get the type of security scheme.
func (ss HTTPAuthConfig) GetType() authscheme.HTTPClientAuthType {
	return ss.Type
}
