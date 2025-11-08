package digestauth

import (
	"github.com/hasura/goenvconf"
	"github.com/relychan/gorestly/authc/authscheme"
)

// DigestAuthConfig contains configurations for the http authentication using the digest scheme.
type DigestAuthConfig struct {
	Type authscheme.HTTPClientAuthType `json:"type" jsonschema:"enum=digest" yaml:"type"`
	// Username to authenticate.
	Username goenvconf.EnvString `json:"username" yaml:"username"`
	// Password to authenticate.
	Password goenvconf.EnvString `json:"password" yaml:"password"`
	// A description for security scheme.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

var _ authscheme.HTTPClientAuthDefinition = (*DigestAuthConfig)(nil)

// NewDigestAuthConfig creates a new DigestAuthConfig instance.
func NewDigestAuthConfig(username, password goenvconf.EnvString) *DigestAuthConfig {
	return &DigestAuthConfig{
		Type:     authscheme.DigestAuthScheme,
		Username: username,
		Password: password,
	}
}

// Validate if the current instance is valid.
func (ss DigestAuthConfig) Validate(strict bool) error {
	authType := ss.GetType()

	if ss.Type != authType {
		return authscheme.NewUnmatchedSecuritySchemeError(authType, ss.Type)
	}

	if !strict {
		return nil
	}

	if ss.Username.IsZero() {
		return authscheme.NewRequiredSecurityFieldError(authType, "username")
	}

	if ss.Password.IsZero() {
		return authscheme.NewRequiredSecurityFieldError(authType, "password")
	}

	return nil
}

// GetType get the type of security scheme.
func (ss DigestAuthConfig) GetType() authscheme.HTTPClientAuthType {
	return authscheme.DigestAuthScheme
}
