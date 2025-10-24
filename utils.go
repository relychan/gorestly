package gorestly

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseHostNameAndPortFromURL parses the host and port from a URL.
func ParseHostNameAndPortFromURL(endpoint *url.URL) (string, int, error) {
	host := endpoint.Host

	hostPort := strings.Split(host, ":")
	hostPortLength := len(hostPort)
	hostname := hostPort[0]
	port := ""

	if hostPortLength > 1 {
		port = hostPort[hostPortLength-1]
		hostname = strings.Join(hostPort[:hostPortLength-1], ":")
	}

	portNumber, err := ParsePort(port, endpoint.Scheme)

	return hostname, portNumber, err
}

// ParsePort parses the server port from a raw string.
func ParsePort(rawPort string, scheme string) (int, error) {
	port := 80

	if rawPort != "" {
		p, err := strconv.Atoi(rawPort)
		if err != nil {
			return 0, err
		}

		port = p
	} else if strings.HasPrefix(scheme, "https") {
		port = 443
	}

	return port, nil
}

// IsSensitiveHeader checks if the header name is sensitive.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaderRegex.MatchString(strings.ToLower(name))
}

// MaskString masks the string value for security.
func MaskString(input string) string {
	inputLength := len(input)

	switch {
	case inputLength <= 6:
		return strings.Repeat("*", inputLength)
	case inputLength < 12:
		return input[0:1] + strings.Repeat("*", inputLength-1)
	default:
		return input[0:3] + strings.Repeat("*", 7) + fmt.Sprintf("(%d)", inputLength)
	}
}
