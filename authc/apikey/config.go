package apikey

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/gorestly/authc/authscheme"
)

// APIKeyAuthConfig contains configurations for [apiKey authentication] according to the OpenAPI specification.
//
// [apiKey authentication]: https://swagger.io/docs/specification/authentication/api-keys/
type APIKeyAuthConfig struct {
	authscheme.TokenLocation

	Type  authscheme.SecuritySchemeType `json:"type" yaml:"type" jsonschema:"enum=apiKey"`
	Value goenvconf.EnvString           `json:"value" yaml:"value"`
	// A description for security scheme.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

var _ authscheme.SecuritySchemeDefinition = (*APIKeyAuthConfig)(nil)

// NewAPIKeyAuthConfig creates a new APIKeyAuthConfig instance.
func NewAPIKeyAuthConfig(name string, in authscheme.AuthLocation, value goenvconf.EnvString) *APIKeyAuthConfig {
	return &APIKeyAuthConfig{
		Type:  authscheme.APIKeyScheme,
		Value: value,
		TokenLocation: authscheme.TokenLocation{
			Name: name,
			In:   in,
		},
	}
}

// Validate if the current instance is valid.
func (ap APIKeyAuthConfig) Validate(strict bool) error {
	authType := ap.GetType()

	if ap.Type != authType {
		return authscheme.NewUnmatchedSecuritySchemeError(authType, ap.Type)
	}

	if ap.Name == "" {
		return authscheme.NewRequiredSecurityFieldError(authType, "name")
	}

	err := ap.In.Validate()
	if err != nil {
		return err
	}

	if !strict {
		return nil
	}

	if ap.Value.IsZero() {
		return authscheme.NewRequiredSecurityFieldError(authType, "value")
	}

	return nil
}

// GetType get the type of security scheme.
func (ss APIKeyAuthConfig) GetType() authscheme.SecuritySchemeType {
	return authscheme.APIKeyScheme
}
