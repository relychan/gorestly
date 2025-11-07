// Package digestauth implements authentication interfaces for the digest security scheme.
package digestauth

import (
	"fmt"

	"resty.dev/v3"
)

// SetDigestAuth set a digest auth to the client.
func SetDigestAuth(client *resty.Client, config *DigestAuthConfig) error {
	user, err := config.Username.Get()
	if err != nil {
		return fmt.Errorf("failed to set digest auth. Invalid username: %w", err)
	}

	password, err := config.Password.Get()
	if err != nil {
		return fmt.Errorf("failed to digest auth. Invalid password: %w", err)
	}

	client.SetDigestAuth(user, password)

	return nil
}
