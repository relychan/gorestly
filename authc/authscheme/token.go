package authscheme

import (
	"net/http"

	"github.com/relychan/goutils"
	"resty.dev/v3"
)

// TokenLocation contains the configuration for the location of the access token.
type TokenLocation struct {
	// Location where the api key is in.
	In AuthLocation `json:"in" jsonschema:"enum=header,enum=query,enum=cookie" yaml:"in"`
	// Name of the field to validate, for example, Authorization header.
	Name string `json:"name" yaml:"name"`
	// The name of the HTTP Authentication scheme to be used in the Authorization header as defined in RFC7235.
	// The values used SHOULD be registered in the IANA Authentication Scheme registry. https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
	// The value is case-insensitive, as defined in RFC7235.
	Scheme string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
}

// InjectRequest injects the authentication token value into the request.
func (tl TokenLocation) InjectRequest(
	req *resty.Request,
	value string,
	replace bool,
) (bool, error) {
	value = tl.addTokenSchemeToValue(value)

	switch tl.In {
	case InHeader:
		if !replace && req.Header.Get(tl.Name) != "" {
			return true, nil
		}

		if value != "" {
			req.Header.Set(tl.Name, value)

			return true, nil
		}

		return false, nil
	case InQuery:
		if value == "" {
			return false, nil
		}

		endpoint, err := goutils.ParseRelativeOrHTTPURL(req.URL)
		if err != nil {
			return false, err
		}

		q := endpoint.Query()
		q.Add(tl.Name, value)

		endpoint.RawQuery = q.Encode()
		req.URL = endpoint.String()

		return true, nil
	case InCookie:
		if !replace {
			for _, cookie := range req.Cookies {
				if cookie.Name == tl.Name && value != "" {
					return true, nil
				}
			}
		}

		if value == "" {
			return false, nil
		}

		req.SetCookie(&http.Cookie{
			Name:  tl.Name,
			Value: value,
		})

		return true, nil
	}

	return false, nil
}

func (tl TokenLocation) addTokenSchemeToValue(value string) string {
	switch tl.Scheme {
	case "bearer":
		return "Bearer " + value
	case "basic":
		return "Basic " + value
	case "":
		return value
	default:
		return tl.Scheme + " " + value
	}
}
