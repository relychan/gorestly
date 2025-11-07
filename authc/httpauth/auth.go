package httpauth

import (
	"fmt"
	"strings"

	"github.com/relychan/gorestly/authc/authscheme"
	"resty.dev/v3"
)

// HTTPCredential presents a header authentication credential.
type HTTPCredential struct {
	location authscheme.TokenLocation
	value    string
}

var _ authscheme.HTTPAuthInjector = (*HTTPCredential)(nil)

// NewHTTPCredential creates a new HTTPCredential instance.
func NewHTTPCredential(config *HTTPAuthConfig) (*HTTPCredential, error) {
	value, err := config.Value.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to create ApiKeyCredential: %w", err)
	}

	header := config.Header

	if header == "" {
		header = "Authorization"
	}

	return &HTTPCredential{
		location: authscheme.TokenLocation{
			In:     authscheme.InHeader,
			Name:   config.Header,
			Scheme: strings.ToLower(config.Scheme),
		},
		value: value,
	}, nil
}

// Inject the credential into the incoming request.
func (hc HTTPCredential) Inject(req *resty.Request) (bool, error) {
	return hc.location.InjectRequest(req, hc.value, false)
}

// InjectMock injects the mock credential into the incoming request for explain APIs.
func (hc HTTPCredential) InjectMock(req *resty.Request) bool {
	ok, _ := hc.location.InjectRequest(req, "[REDACTED]", false)

	return ok
}
