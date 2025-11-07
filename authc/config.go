package authc

import (
	"encoding/json"
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

var (
	errSecuritySchemeDefinitionRequired = errors.New("security scheme definition is required")
	errUnsupportedSecurityScheme        = errors.New("unsupported security scheme")
)

// RestlyAuthConfig contains authentication configurations.
// The schema follows [OpenAPI 3] specification.
//
// [OpenAPI 3]: https://swagger.io/docs/specification/authentication
type RestlyAuthConfig struct {
	authscheme.SecuritySchemeDefinition
}

type rawRestlyAuthConfig struct {
	Type authscheme.SecuritySchemeType `json:"type" yaml:"type"`
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
		if err := json.Unmarshal(b, &config); err != nil {
			return err
		}

		j.SecuritySchemeDefinition = &config
	case authscheme.BasicAuthScheme:
		var config basicauth.BasicAuthConfig

		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.SecuritySchemeDefinition = &config
	case authscheme.HTTPAuthScheme:
		var config httpauth.HTTPAuthConfig

		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.SecuritySchemeDefinition = &config
	case authscheme.OAuth2Scheme:
		var config oauth2scheme.OAuth2Config
		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.SecuritySchemeDefinition = &config
	case authscheme.OpenIDConnectScheme:
		var config openidscheme.OpenIDConnectConfig
		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.SecuritySchemeDefinition = &config
	case authscheme.MutualTLSScheme:
		var config mutualtls.MutualTLSAuthConfig
		err := json.Unmarshal(b, &config)
		if err != nil {
			return err
		}

		j.SecuritySchemeDefinition = &config
	default:
		return fmt.Errorf("%w: %s", errUnsupportedSecurityScheme, rawScheme.Type)
	}

	return nil
}

// MarshalJSON implements json.Marshaler.
func (j RestlyAuthConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.SecuritySchemeDefinition)
}

// Validate if the current instance is valid.
func (ss *RestlyAuthConfig) Validate(strict bool) error {
	if ss.SecuritySchemeDefinition == nil {
		return errSecuritySchemeDefinitionRequired
	}

	return ss.SecuritySchemeDefinition.Validate(strict)
}
