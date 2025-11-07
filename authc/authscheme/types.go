package authscheme

import (
	"fmt"
	"slices"

	"resty.dev/v3"
)

// HTTPAuthClient abstracts an interface for injecting authentication value into HTTP requests.
type HTTPAuthInjector interface {
	// Inject the credential into the incoming request.
	Inject(req *resty.Request) (bool, error)
	// InjectMock injects a mock credential into the incoming request for explaining.
	InjectMock(req *resty.Request) bool
}

// SecuritySchemeDefinition abstracts an interface of SecurityScheme.
type SecuritySchemeDefinition interface {
	// GetType gets the type of security scheme.
	GetType() SecuritySchemeType
	// Validate checks if the instance is valid.
	Validate(strict bool) error
}

// SecuritySchemeType represents the authentication scheme enum.
type SecuritySchemeType string

const (
	APIKeyScheme        SecuritySchemeType = "apiKey"
	BasicAuthScheme     SecuritySchemeType = "basic"
	CookieAuthScheme    SecuritySchemeType = "cookie"
	HTTPAuthScheme      SecuritySchemeType = "http"
	OAuth2Scheme        SecuritySchemeType = "oauth2"
	OpenIDConnectScheme SecuritySchemeType = "openIdConnect"
	MutualTLSScheme     SecuritySchemeType = "mutualTLS"
)

var enumValueSecuritySchemes = []SecuritySchemeType{
	APIKeyScheme,
	HTTPAuthScheme,
	BasicAuthScheme,
	CookieAuthScheme,
	OAuth2Scheme,
	OpenIDConnectScheme,
	MutualTLSScheme,
}

// Validate checks if the security scheme type is valid.
func (j SecuritySchemeType) Validate() error {
	if !slices.Contains(GetSupportedSecuritySchemeTypes(), j) {
		return fmt.Errorf(
			"invalid SecuritySchemeType. Expected %v, got <%s>",
			enumValueSecuritySchemes,
			j,
		)
	}

	return nil
}

// ParseSecuritySchemeType parses SecurityScheme from string.
func ParseSecuritySchemeType(value string) (SecuritySchemeType, error) {
	result := SecuritySchemeType(value)

	return result, result.Validate()
}

// GetSupportedSecuritySchemeTypes get the list of supported security scheme types.
func GetSupportedSecuritySchemeTypes() []SecuritySchemeType {
	return enumValueSecuritySchemes
}

// AuthLocation represents the location enum for setting authentication value.
type AuthLocation string

const (
	InHeader AuthLocation = "header"
	InQuery  AuthLocation = "query"
	InCookie AuthLocation = "cookie"
)

var enumValuesAuthLocations = []AuthLocation{InHeader, InQuery, InCookie}

// Validate checks if the security scheme type is valid.
func (j AuthLocation) Validate() error {
	if !slices.Contains(GetSupportedAuthLocations(), j) {
		return fmt.Errorf(
			"invalid AuthLocation. Expected %v, got <%s>",
			enumValuesAuthLocations,
			j,
		)
	}

	return nil
}

// ParseAuthLocation parses the auth location from string.
func ParseAuthLocation(value string) (AuthLocation, error) {
	result := AuthLocation(value)

	return result, result.Validate()
}

// GetSupportedAuthLocations get the list of supported auth locations.
func GetSupportedAuthLocations() []AuthLocation {
	return enumValuesAuthLocations
}
