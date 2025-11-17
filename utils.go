package gorestly

import (
	"net/url"
	"strings"

	"github.com/hasura/gotel/otelutils"
)

// ParseHostNameAndPortFromURL parses the host and port from a URL.
func ParseHostNameAndPortFromURL(endpoint *url.URL) (string, int, error) {
	hostname, port, err := otelutils.SplitHostPort(endpoint.Host)

	if port <= 0 {
		port = 80

		if strings.HasPrefix(endpoint.Scheme, "https") {
			port = 443
		}
	}

	return hostname, port, err
}
