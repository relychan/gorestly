package authc

import (
	"github.com/relychan/gorestly/authc/authscheme"
	"resty.dev/v3"
)

// NewAuthMiddleware creates an auth middleware from config.
func NewAuthMiddleware(injector authscheme.HTTPClientAuthInjector) resty.RequestMiddleware {
	return func(_ *resty.Client, req *resty.Request) error {
		_, err := injector.Inject(req)

		return err
	}
}
