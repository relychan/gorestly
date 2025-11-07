package apikey

import (
	"fmt"
	"strings"

	"github.com/relychan/gorestly/authc/authscheme"
	"resty.dev/v3"
)

// APIKeyCredential presents a credential to inject API key into http request.
type APIKeyCredential struct {
	location authscheme.TokenLocation
	value    string
}

var _ authscheme.HTTPAuthInjector = (*APIKeyCredential)(nil)

// NewApiKeyCredential creates a new APIKeyCredential instance.
func NewApiKeyCredential(config *APIKeyAuthConfig) (*APIKeyCredential, error) {
	value, err := config.Value.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to create ApiKeyCredential: %w", err)
	}

	config.TokenLocation.Scheme = strings.ToLower(config.TokenLocation.Scheme)

	return &APIKeyCredential{
		location: config.TokenLocation,
		value:    value,
	}, nil
}

// Inject the credential into the incoming request.
func (akc APIKeyCredential) Inject(req *resty.Request) (bool, error) {
	return akc.location.InjectRequest(req, akc.value, false)
}

// InjectMock injects the mock credential into the incoming request for explain APIs.
func (akc APIKeyCredential) InjectMock(req *resty.Request) bool {
	ok, _ := akc.location.InjectRequest(req, "[REDACTED]", true)

	return ok
}
