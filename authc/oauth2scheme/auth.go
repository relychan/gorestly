package oauth2scheme

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/relychan/gorestly/authc/authscheme"
	"github.com/relychan/goutils"
	"golang.org/x/oauth2/clientcredentials"
	"resty.dev/v3"
)

// OAuth2Client represent the client of the OAuth2 client credentials.
type OAuth2Client struct {
	oauth2Config *clientcredentials.Config
	location     authscheme.TokenLocation
}

var _ authscheme.HTTPAuthInjector = (*OAuth2Client)(nil)

// NewOAuth2Client creates an OAuth2 client from the security scheme.
func NewOAuth2Client(config *OAuth2Config) (*OAuth2Client, error) {
	location := config.TokenLocation
	if location == nil {
		location = &authscheme.TokenLocation{
			In:   authscheme.InHeader,
			Name: "Authorization",
		}
	}

	flow, ok := config.Flows[ClientCredentialsFlow]
	if !ok || flow.TokenURL == nil || flow.ClientID == nil || flow.ClientSecret == nil {
		return &OAuth2Client{
			location: *location,
		}, nil
	}

	rawTokenURL, err := flow.TokenURL.Get()
	if err != nil {
		return nil, fmt.Errorf("tokenUrl: %w", err)
	}

	tokenURL, err := goutils.ParseRelativeOrHTTPURL(rawTokenURL)
	if err != nil {
		return nil, fmt.Errorf("tokenUrl: %w", err)
	}

	scopes := make([]string, 0, len(flow.Scopes))
	for scope := range flow.Scopes {
		scopes = append(scopes, scope)
	}

	clientID, err := flow.ClientID.Get()
	if err != nil {
		return nil, fmt.Errorf("clientId: %w", err)
	}

	clientSecret, err := flow.ClientSecret.Get()
	if err != nil {
		return nil, fmt.Errorf("clientSecret: %w", err)
	}

	var endpointParams url.Values

	for key, envValue := range flow.EndpointParams {
		value, err := envValue.GetOrDefault("")
		if err != nil {
			return nil, fmt.Errorf("endpointParams[%s]: %w", key, err)
		}

		if value != "" {
			endpointParams.Set(key, value)
		}
	}

	conf := &clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		Scopes:         scopes,
		TokenURL:       tokenURL.String(),
		EndpointParams: endpointParams,
	}

	return &OAuth2Client{
		oauth2Config: conf,
		location:     *location,
	}, nil
}

// Inject the credential into the incoming request.
func (oc OAuth2Client) Inject(req *resty.Request) (bool, error) {
	if oc.oauth2Config == nil {
		return false, nil
	}

	// get the token from client credentials
	token, err := oc.oauth2Config.Token(req.Context())
	if err != nil {
		return false, err
	}

	if oc.location.Scheme == "" {
		oc.location.Scheme = strings.ToLower(token.Type())
	}

	return oc.location.InjectRequest(req, token.AccessToken, false)
}

// InjectMock injects the mock credential into the incoming request for explain APIs.
func (oc OAuth2Client) InjectMock(req *resty.Request) bool {
	if oc.oauth2Config == nil {
		return false
	}

	ok, _ := oc.location.InjectRequest(req, "[REDACTED]", true)

	return ok
}
