package oauth2scheme

import (
	"errors"
	"fmt"
	"slices"

	"github.com/hasura/goenvconf"
	"github.com/relychan/gorestly/authc/authscheme"
)

var (
	// ErrOAuth2FlowRequired is the error when there isn't any flow is configured.
	ErrOAuth2FlowRequired   = errors.New("require at least 1 flow for oauth2 security")
	ErrClientIDRequired     = errors.New("clientId is required for the OAuth2 client_credentials flow")
	ErrClientSecretRequired = errors.New("clientSecret is required for the OAuth2 client_credentials flow")
	ErrTokenURLRequired     = errors.New("tokenUrl: value and env are empty")
)

// OAuth2Config contains configurations for [OAuth 2.0] API specification
//
// [OAuth 2.0]: https://swagger.io/docs/specification/authentication/oauth2
type OAuth2Config struct {
	Type authscheme.SecuritySchemeType `json:"type" yaml:"type" jsonschema:"enum=oauth2"`
	// An object containing configuration information for the flow types supported.
	Flows map[OAuthFlowType]OAuthFlow `json:"flows" yaml:"flows"`
	// A description for security scheme.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// The location where the auth credential will be injected.
	TokenLocation *authscheme.TokenLocation `json:"tokenLocation,omitempty" yaml:"tokenLocation,omitempty"`
}

var _ authscheme.SecuritySchemeDefinition = (*OAuth2Config)(nil)

// NewOAuth2Config creates a new OAuth2Config instance.
func NewOAuth2Config(flows map[OAuthFlowType]OAuthFlow) *OAuth2Config {
	return &OAuth2Config{
		Type:  authscheme.OAuth2Scheme,
		Flows: flows,
	}
}

// GetType get the type of security scheme.
func (ss OAuth2Config) GetType() authscheme.SecuritySchemeType {
	return authscheme.OAuth2Scheme
}

// Validate if the current instance is valid.
func (ss OAuth2Config) Validate(strict bool) error {
	authType := ss.GetType()

	if ss.Type != authType {
		return authscheme.NewUnmatchedSecuritySchemeError(authType, ss.Type)
	}

	if len(ss.Flows) == 0 {
		return ErrOAuth2FlowRequired
	}

	for key, flow := range ss.Flows {
		if err := flow.Validate(key); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}

	return nil
}

// OAuthFlowType represents the OAuth flow type enum.
type OAuthFlowType string

const (
	AuthorizationCodeFlow OAuthFlowType = "authorizationCode"
	ImplicitFlow          OAuthFlowType = "implicit"
	PasswordFlow          OAuthFlowType = "password"
	ClientCredentialsFlow OAuthFlowType = "clientCredentials"
)

var enumValueOAuthFlowTypes = []OAuthFlowType{
	AuthorizationCodeFlow,
	ImplicitFlow,
	PasswordFlow,
	ClientCredentialsFlow,
}

// Validate checks if the current value is valid.
func (j OAuthFlowType) Validate() error {
	if !slices.Contains(enumValueOAuthFlowTypes, j) {
		return fmt.Errorf(
			"invalid OAuthFlowType. Expected %+v, got <%s>",
			enumValueOAuthFlowTypes,
			j,
		)
	}

	return nil
}

// ParseOAuthFlowType parses OAuthFlowType from string.
func ParseOAuthFlowType(value string) (OAuthFlowType, error) {
	result := OAuthFlowType(value)

	return result, result.Validate()
}

// OAuthFlow contains flow configurations for [OAuth 2.0] API specification
//
// [OAuth 2.0]: https://swagger.io/docs/specification/authentication/oauth2
type OAuthFlow struct {
	AuthorizationURL *goenvconf.EnvString `json:"authorizationUrl,omitempty" yaml:"authorizationUrl,omitempty"`
	// The token URL to be used for this flow. This MUST be in the form of a URL. The OAuth2 standard requires the use of TLS.
	TokenURL *goenvconf.EnvString `json:"tokenUrl,omitempty"         yaml:"tokenUrl,omitempty"`
	// The URL to be used for obtaining refresh tokens. This MUST be in the form of a URL. The OAuth2 standard requires the use of TLS.
	RefreshURL *goenvconf.EnvString `json:"refreshUrl,omitempty"       yaml:"refreshUrl,omitempty"`
	// The available scopes for the OAuth2 security scheme. A map between the scope name and a short description for it. The map MAY be empty.
	Scopes         map[string]string              `json:"scopes,omitempty"           yaml:"scopes,omitempty"`
	ClientID       *goenvconf.EnvString           `json:"clientId,omitempty"         yaml:"clientId,omitempty"`
	ClientSecret   *goenvconf.EnvString           `json:"clientSecret,omitempty"     yaml:"clientSecret,omitempty"`
	EndpointParams map[string]goenvconf.EnvString `json:"endpointParams,omitempty"   yaml:"endpointParams,omitempty"`
}

// Validate if the current instance is valid.
func (ss OAuthFlow) Validate(flowType OAuthFlowType) error {
	if ss.TokenURL == nil {
		if slices.Contains(
			[]OAuthFlowType{PasswordFlow, ClientCredentialsFlow, AuthorizationCodeFlow},
			flowType,
		) {
			return fmt.Errorf("tokenUrl is required for oauth2 %s security", flowType)
		}
	} else if ss.TokenURL.IsZero() {
		return ErrTokenURLRequired
	}

	if flowType != ClientCredentialsFlow {
		return nil
	}

	if ss.ClientID == nil || ss.ClientID.IsZero() {
		return ErrClientIDRequired
	}

	if ss.ClientSecret == nil || ss.ClientSecret.IsZero() {
		return ErrClientSecretRequired
	}

	return nil
}
