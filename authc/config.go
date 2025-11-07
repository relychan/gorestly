package authc

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/relychan/gorestly/authc/apikey"
	"github.com/relychan/gorestly/authc/authscheme"
	"github.com/relychan/gorestly/authc/basicauth"
	"github.com/relychan/gorestly/authc/httpauth"
	"github.com/relychan/gorestly/authc/oauth2scheme"
)

var (
	errSecuritySchemeDefinitionRequired = errors.New("security scheme definition is required")
	errUnsupportedSecurityScheme        = errors.New("unsupported security scheme")
)

// RestlyAuthConfig contains authentication configurations.
// The schema follows [OpenAPI 3] specification.
//
// [OpenAPI 3]: https://swagger.io/docs/specification/authentication
type RestlyAuthConfig struct {
	authscheme.HTTPClientAuthDefinition
}

type rawRestlyAuthConfig struct {
	Type authscheme.HTTPClientAuthType `json:"type" yaml:"type"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *RestlyAuthConfig) UnmarshalJSON(b []byte) error {
	var rawScheme rawRestlyAuthConfig

	err := json.Unmarshal(b, &rawScheme)
	if err != nil {
		return err
	}

	err = rawScheme.Type.Validate()
	if err != nil {
		return err
	}

	switch rawScheme.Type {
	case authscheme.APIKeyScheme:
		var config apikey.APIKeyAuthConfig

		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.HTTPClientAuthDefinition = &config
	case authscheme.BasicAuthScheme:
		var config basicauth.BasicAuthConfig

		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.HTTPClientAuthDefinition = &config
	case authscheme.HTTPAuthScheme:
		var config httpauth.HTTPAuthConfig

		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.HTTPClientAuthDefinition = &config
	case authscheme.OAuth2Scheme:
		var config oauth2scheme.OAuth2Config

		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.HTTPClientAuthDefinition = &config
	default:
		return fmt.Errorf("%w: %s", errUnsupportedSecurityScheme, rawScheme.Type)
	}

	return nil
}

// MarshalJSON implements json.Marshaler.
func (j RestlyAuthConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.HTTPClientAuthDefinition)
}

// Validate if the current instance is valid.
func (ss *RestlyAuthConfig) Validate(strict bool) error {
	if ss.HTTPClientAuthDefinition == nil {
		return errSecuritySchemeDefinitionRequired
	}

	return ss.HTTPClientAuthDefinition.Validate(strict)
}

// IsZero if the current instance is empty.
func (ss *RestlyAuthConfig) IsZero() bool {
	return ss.HTTPClientAuthDefinition == nil
}
