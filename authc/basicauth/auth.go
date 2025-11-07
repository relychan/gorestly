package basicauth

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/relychan/gorestly/authc/authscheme"
	"resty.dev/v3"
)

// BasicCredential represents the basic authentication credential.
type BasicCredential struct {
	username string
	password string
	header   string
}

var _ authscheme.HTTPAuthInjector = (*BasicCredential)(nil)

// NewBasicCredential creates a new BasicCredential instance.
func NewBasicCredential(config *BasicAuthConfig) (*BasicCredential, error) {
	user, err := config.Username.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to create basic credential. Invalid username: %w", err)
	}

	password, err := config.Password.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to create basic credential. Invalid password: %w", err)
	}

	result := &BasicCredential{
		username: user,
		password: password,
		header:   config.Header,
	}

	return result, nil
}

// Inject the credential into the incoming request.
func (bc BasicCredential) Inject(req *resty.Request) (bool, error) {
	return bc.inject(req, bc.username, bc.password)
}

// InjectMock injects the mock credential into the incoming request for explain APIs.
func (bc BasicCredential) InjectMock(req *resty.Request) bool {
	ok, _ := bc.inject(req, "user", "password")

	return ok
}

func (bc BasicCredential) inject(req *resty.Request, user, password string) (bool, error) {
	if bc.username == "" && bc.password == "" {
		return false, nil
	}

	if bc.header != "" {
		var userInfo *url.Userinfo

		if password != "" {
			userInfo = url.UserPassword(user, password)
		} else {
			userInfo = url.User(user)
		}

		b64Value := base64.StdEncoding.EncodeToString([]byte(userInfo.String()))
		req.Header.Set(bc.header, "Basic "+b64Value)
	} else {
		req.SetBasicAuth(user, password)
	}

	return true, nil
}
