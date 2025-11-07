package openidscheme

import (
	"github.com/relychan/gorestly/authc/authscheme"
	"resty.dev/v3"
)

// OpenIDConnectClient represent the client of the OIDC client credentials.
type OpenIDConnectClient struct {
}

var _ authscheme.HTTPAuthInjector = (*OpenIDConnectClient)(nil)

// NewOOpenIDConnectClient creates an OIDC client from the security scheme.
func NewOpenIDConnectClient(conf *OpenIDConnectConfig) (*OpenIDConnectClient, error) {
	return &OpenIDConnectClient{}, nil
}

// Inject the credential into the incoming request.
func (oc OpenIDConnectClient) Inject(req *resty.Request) (bool, error) {
	return false, nil
}

// InjectMock injects the mock credential into the incoming request for explain APIs.
func (oc OpenIDConnectClient) InjectMock(req *resty.Request) bool {
	return false
}
