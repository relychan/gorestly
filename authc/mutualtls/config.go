package mutualtls

import (
	"errors"

	"github.com/relychan/gorestly/authc/authscheme"
)

// ErrTLSCertificateRequired is the error when the SSL certificate or key is null.
var ErrTLSCertificateRequired = errors.New("SSL certificate and key are required")

// MutualTLSAuthConfig represents a mutualTLS authentication configuration.
type MutualTLSAuthConfig struct {
	Type authscheme.SecuritySchemeType `json:"type" yaml:"type" jsonschema:"enum=mutualTLS"`
	// A description for security scheme.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

var _ authscheme.SecuritySchemeDefinition = (*MutualTLSAuthConfig)(nil)

// NewMutualTLSAuthConfig creates a new MutualTLSAuthConfig instance.
func NewMutualTLSAuthConfig() *MutualTLSAuthConfig {
	return &MutualTLSAuthConfig{
		Type: authscheme.MutualTLSScheme,
	}
}

// GetType get the type of security scheme.
func (ss MutualTLSAuthConfig) GetType() authscheme.SecuritySchemeType {
	return authscheme.MutualTLSScheme
}

// Validate if the current instance is valid.
func (ss MutualTLSAuthConfig) Validate(strict bool) error {
	authType := ss.GetType()

	if ss.Type != authType {
		return authscheme.NewUnmatchedSecuritySchemeError(authType, ss.Type)
	}

	return nil
}
