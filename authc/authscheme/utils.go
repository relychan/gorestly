package authscheme

import (
	"fmt"
)

// NewRequiredSecurityFieldError creates an error for required field in the security scheme config.
func NewRequiredSecurityFieldError(scheme SecuritySchemeType, name string) error {
	return fmt.Errorf("%s is required for the %s security scheme", name, scheme)
}

// NewUnmatchedSecuritySchemeError creates an error for unexpected security scheme type.
func NewUnmatchedSecuritySchemeError(expected SecuritySchemeType, got SecuritySchemeType) error {
	return fmt.Errorf("expected security scheme `%s`, got `%s`", expected, got)
}
