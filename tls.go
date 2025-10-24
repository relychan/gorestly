package gorestly

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/hasura/goenvconf"
	"github.com/prometheus/common/model"
	"resty.dev/v3"
)

var systemCertPool = x509.SystemCertPool

// We should avoid that users unknowingly use a vulnerable TLS version.
// The defaults should be a safe configuration.
const defaultMinTLSVersion = tls.VersionTLS12

// Uses the default MaxVersion from "crypto/tls" which is the maximum supported version.
const defaultMaxTLSVersion = 0

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

var (
	errCertificateRequireEitherFileOrPEM = errors.New(
		"provide either a certificate or the PEM-encoded string, but not both",
	)
	errCertificateInvalidBase64 = errors.New(
		"certificate string must be in base64 format",
	)
	errTLSMinVersionGreaterThanMaxVersion = errors.New(
		"invalid TLS configuration: minVersion cannot be greater than max_version",
	)
	errUnsupportedTLSVersion  = errors.New("unsupported TLS version")
	errUnsupportedCipherSuite = errors.New("invalid TLS cipher suite")
	errTLSPEMAndFileEmpty     = errors.New("both PEM and file are empty")
)

// TLSClientCertificate represents a cert and key pair certificate.
type TLSClientCertificate struct {
	// Path to the TLS cert to use for TLS required connections.
	CertFile *goenvconf.EnvString `json:"cert_file,omitempty" mapstructure:"cert_file" yaml:"cert_file,omitempty"`
	// Alternative to cert_file. Provide the certificate contents as a base64-encoded string instead of a filepath.
	CertPem *goenvconf.EnvString `json:"cert_pem,omitempty" mapstructure:"cert_pem" yaml:"cert_pem,omitempty"`
	// Path to the TLS key to use for TLS required connections.
	KeyFile *goenvconf.EnvString `json:"key_file,omitempty" mapstructure:"key_file" yaml:"key_file,omitempty"`
	// Alternative to key_file. Provide the key contents as a base64-encoded string instead of a filepath.
	KeyPem *goenvconf.EnvString `json:"key_pem,omitempty" mapstructure:"key_pem" yaml:"key_pem,omitempty"`
}

// TLSConfig represents the transport layer security (LTS) configuration for the mutualTLS authentication.
type TLSConfig struct {
	// Interval to reload certificates. Only takes effect for file-path certificates.
	// Default value is 24 hours.
	ReloadInterval *model.Duration `json:"reload_interval,omitempty" jsonschema:"nullable,type=string,pattern=^((([0-9]+h)?([0-9]+m)?([0-9]+s))|(([0-9]+h)?([0-9]+m))|([0-9]+h))$" mapstructure:"reload_interval" yaml:"reload_interval"`
	// Path to the root certificate. For a client this verifies the server certificate. For a server this verifies client certificates.
	// If empty uses system root CA.
	RootCAFile []goenvconf.EnvString `json:"root_ca_file,omitempty" mapstructure:"root_ca_file" yaml:"root_ca_file,omitempty"`
	// Alternative to ca_file. Provide the CA cert contents as a base64-encoded string instead of a filepath.
	RootCAPem []goenvconf.EnvString `json:"root_ca_pem,omitempty" mapstructure:"root_ca_pem" yaml:"root_ca_pem,omitempty"`
	// Path to the CA cert. For a client this verifies the server certificate. For a server this verifies client certificates.
	// If empty uses system root CA.
	CAFile []goenvconf.EnvString `json:"ca_file,omitempty" mapstructure:"ca_file" yaml:"ca_file,omitempty"`
	// Alternative to ca_file. Provide the CA cert contents as a base64-encoded string instead of a filepath.
	CAPem []goenvconf.EnvString `json:"ca_pem,omitempty" mapstructure:"ca_pem" yaml:"ca_pem,omitempty"`
	// List of client certificates.
	Certificates []TLSClientCertificate `json:"certificates,omitempty" mapstructure:"certificates" yaml:"certificates,omitempty"`
	// Additionally you can configure TLS to be enabled but skip verifying the server's certificate chain.
	InsecureSkipVerify *goenvconf.EnvBool `json:"insecure_skip_verify,omitempty" mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify,omitempty"`
	// Whether to load the system certificate authorities pool alongside the certificate authority.
	IncludeSystemCACertsPool *goenvconf.EnvBool `json:"include_system_ca_certs_pool,omitempty" mapstructure:"include_system_ca_certs_pool" yaml:"include_system_ca_certs_pool,omitempty"`
	// Minimum acceptable TLS version.
	MinVersion string `json:"min_version,omitempty" mapstructure:"min_version" yaml:"min_version,omitempty"`
	// Maximum acceptable TLS version.
	MaxVersion string `json:"max_version,omitempty" mapstructure:"max_version" yaml:"max_version,omitempty"`
	// Explicit cipher suites can be set. If left blank, a safe default list is used.
	// See https://go.dev/src/crypto/tls/cipher_suites.go for a list of supported cipher suites.
	CipherSuites []string `json:"cipher_suites,omitempty" mapstructure:"cipher_suites" yaml:"cipher_suites,omitempty"`
	// ServerName requested by client for virtual hosting.
	// This sets the ServerName in the TLSConfig. Please refer to
	// https://godoc.org/crypto/tls#Config for more information. (optional)
	ServerName *goenvconf.EnvString `json:"server_name,omitempty" mapstructure:"server_name" yaml:"server_name,omitempty"`
}

// Validate if the current instance is valid.
func (tc TLSConfig) Validate() error {
	minTLS, err := tc.GetMinVersion()
	if err != nil {
		return fmt.Errorf("min_version: %w", err)
	}

	maxTLS, err := tc.GetMaxVersion()
	if err != nil {
		return fmt.Errorf("max_version: %w", err)
	}

	if maxTLS < minTLS && maxTLS != defaultMaxTLSVersion {
		return errTLSMinVersionGreaterThanMaxVersion
	}

	err = tc.validateCertificates()
	if err != nil {
		return err
	}

	if tc.IncludeSystemCACertsPool != nil {
		_, err := tc.IncludeSystemCACertsPool.GetOrDefault(false)
		if err != nil {
			return err
		}
	}

	if tc.ServerName != nil {
		_, err := tc.ServerName.GetOrDefault("")
		if err != nil {
			return err
		}
	}

	return nil
}

// GetMinVersion parses the minx TLS version from string.
func (tc TLSConfig) GetMinVersion() (uint16, error) {
	return tc.convertTLSVersion(tc.MinVersion, defaultMinTLSVersion)
}

// GetMaxVersion parses the max TLS version from string.
func (tc TLSConfig) GetMaxVersion() (uint16, error) {
	return tc.convertTLSVersion(tc.MinVersion, defaultMaxTLSVersion)
}

func (tc TLSConfig) validateCertificates() error {
	for i, cert := range tc.Certificates {
		if cert.CertFile != nil && cert.CertPem != nil {
			certFile, err := cert.CertFile.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].cert_file: %w", i, err)
			}

			certPem, err := cert.CertPem.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].cert_pem: %w", i, err)
			}

			if certFile != "" && certPem != "" {
				return errCertificateRequireEitherFileOrPEM
			}
		}

		if cert.KeyFile != nil && cert.KeyPem != nil {
			keyFile, err := cert.KeyFile.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].key_file: %w", i, err)
			}

			keyPem, err := cert.KeyPem.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].key_pem: %w", i, err)
			}

			if keyFile != "" && keyPem != "" {
				return errCertificateRequireEitherFileOrPEM
			}
		}
	}

	return nil
}

func (tc TLSConfig) convertTLSVersion(v string, defaultVersion uint16) (uint16, error) {
	// Use a default that is explicitly defined
	if v == "" {
		return defaultVersion, nil
	}

	val, ok := tlsVersions[v]
	if !ok {
		return 0, fmt.Errorf("%w: %q", errUnsupportedTLSVersion, v)
	}

	return val, nil
}

func (tc TLSConfig) toCertWatcherOptions() *resty.CertWatcherOptions {
	result := &resty.CertWatcherOptions{}

	if tc.ReloadInterval != nil {
		result.PoolInterval = time.Duration(*tc.ReloadInterval)
	}

	return result
}

// loadTLSConfig loads TLS certificates and returns a tls.Config.
// This will set the RootCAs and Certificates of a tls.Config.
func loadTLSConfig(tlsConfig *TLSConfig) (*tls.Config, error) {
	var (
		insecureSkipVerify bool
		err                error
	)

	if tlsConfig.InsecureSkipVerify != nil {
		insecureSkipVerify, err = tlsConfig.InsecureSkipVerify.GetOrDefault(false)
		if err != nil {
			return nil, fmt.Errorf("failed to parse insecureSkipVerify: %w", err)
		}
	}

	certPool, err := loadSystemCACertPool(tlsConfig)
	if err != nil {
		return nil, err
	}

	minTLS, err := tlsConfig.GetMinVersion()
	if err != nil {
		return nil, fmt.Errorf("min_version: %w", err)
	}

	maxTLS, err := tlsConfig.GetMaxVersion()
	if err != nil {
		return nil, fmt.Errorf("max_version: %w", err)
	}

	cipherSuites, err := convertCipherSuites(tlsConfig.CipherSuites)
	if err != nil {
		return nil, err
	}

	var serverName string

	if tlsConfig.ServerName != nil {
		serverName, err = tlsConfig.ServerName.GetOrDefault("")
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS server name: %w", err)
		}
	}

	result := &tls.Config{
		RootCAs:            certPool,
		MinVersion:         minTLS,
		MaxVersion:         maxTLS,
		CipherSuites:       cipherSuites,
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec
	}

	return result, nil
}

func loadSystemCACertPool(tlsConfig *TLSConfig) (*x509.CertPool, error) {
	// There is no need to load the System Certs for RootCAs because
	// if the value is nil, it will default to checking against th System Certs.
	var err error

	var certPool *x509.CertPool

	var includeSystemCACertsPool bool

	if tlsConfig.IncludeSystemCACertsPool != nil {
		includeSystemCACertsPool, err = tlsConfig.IncludeSystemCACertsPool.GetOrDefault(false)
		if err != nil {
			return nil, fmt.Errorf("invalid includeSystemCACertsPool config: %w", err)
		}
	}

	if includeSystemCACertsPool {
		scp, err := systemCertPool()
		if err != nil {
			return nil, err
		}

		if scp != nil {
			certPool = scp
		}
	}

	if certPool == nil {
		certPool = x509.NewCertPool()
	}

	return certPool, nil
}

func convertCipherSuites(cipherSuites []string) ([]uint16, error) {
	var result []uint16

	var errs []error

	for _, suite := range cipherSuites {
		found := false

		for _, supported := range tls.CipherSuites() {
			if suite == supported.Name {
				result = append(result, supported.ID)
				found = true

				break
			}
		}

		if !found {
			errs = append(errs, fmt.Errorf("%w: %q", errUnsupportedCipherSuite, suite))
		}
	}

	return result, errors.Join(errs...)
}

func addTLSCertificates(client *resty.Client, tlsConf *TLSConfig) error {
	err := addTLSRootCertificates(client, tlsConf)
	if err != nil {
		return err
	}

	err = addTLSClientRootCertificates(client, tlsConf)
	if err != nil {
		return err
	}

	return addTLSClientCertificates(client, tlsConf.Certificates)
}

func addTLSRootCertificates(client *resty.Client, tlsConf *TLSConfig) error {
	for i, certStrEnv := range tlsConf.RootCAPem {
		certStr, err := loadCertificateString(certStrEnv)
		if err != nil {
			return fmt.Errorf("failed to load root certificate string at %d: %w", i, err)
		}

		if len(certStr) == 0 {
			slog.Warn(fmt.Sprintf("the root certificate string at %d is empty", i))

			continue
		}

		client.SetRootCertificateFromString(string(certStr))
	}

	certFilePaths := []string{}

	for i, certEnv := range tlsConf.RootCAFile {
		certFile, err := certEnv.GetOrDefault("")
		if err != nil {
			return fmt.Errorf("failed to load root certificate file at %d: %w", i, err)
		}

		if certFile == "" {
			slog.Warn(fmt.Sprintf("the root certificate file path at %d is empty", i))

			continue
		}

		certFilePaths = append(certFilePaths, certFile)
	}

	if len(certFilePaths) > 0 {
		client.SetRootCertificatesWatcher(tlsConf.toCertWatcherOptions(), certFilePaths...)
	}

	return nil
}

func addTLSClientRootCertificates(client *resty.Client, tlsConf *TLSConfig) error {
	for i, certStrEnv := range tlsConf.CAPem {
		certStr, err := loadCertificateString(certStrEnv)
		if err != nil {
			return fmt.Errorf("failed to load client root certificate string at %d: %w", i, err)
		}

		if len(certStr) == 0 {
			slog.Warn(fmt.Sprintf("the client root certificate string at %d is empty", i))

			continue
		}

		client.SetClientRootCertificateFromString(string(certStr))
	}

	clientRootCertFilePaths := []string{}

	for i, certEnv := range tlsConf.CAFile {
		certFile, err := certEnv.GetOrDefault("")
		if err != nil {
			return fmt.Errorf("failed to load client root certificate file at %d: %w", i, err)
		}

		if certFile == "" {
			slog.Warn(fmt.Sprintf("client root certificate file path at %d is empty", i))

			continue
		}

		clientRootCertFilePaths = append(clientRootCertFilePaths, certFile)
	}

	if len(clientRootCertFilePaths) > 0 {
		client.SetClientRootCertificatesWatcher(
			tlsConf.toCertWatcherOptions(),
			clientRootCertFilePaths...)
	}

	return nil
}

func addTLSClientCertificates(client *resty.Client, certs []TLSClientCertificate) error {
	results := make([]tls.Certificate, 0, len(certs))

	for i, cert := range certs {
		c, err := loadClientCertificateKeyPair(cert)
		if err != nil {
			return fmt.Errorf("failed to load client certificate at %d: %w", i, err)
		}

		results = append(results, *c)
	}

	client.SetCertificates(results...)

	return nil
}

func loadCertificateString(certEnv goenvconf.EnvString) ([]byte, error) {
	certBase64, err := certEnv.GetOrDefault("")
	if err != nil {
		return nil, err
	}

	if certBase64 == "" {
		return nil, nil
	}

	certStr, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return nil, errCertificateInvalidBase64
	}

	return certStr, nil
}

func loadClientCertificateKeyPair(tlsConfig TLSClientCertificate) (*tls.Certificate, error) {
	certData, err := loadEitherCertPemOrFile(tlsConfig.CertPem, tlsConfig.CertFile)
	if err != nil {
		return nil, fmt.Errorf("certificate error: %w", err)
	}

	keyData, err := loadEitherCertPemOrFile(tlsConfig.KeyPem, tlsConfig.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("key error: %w", err)
	}

	certificate, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS cert and key PEMs: %w", err)
	}

	return &certificate, nil
}

func loadEitherCertPemOrFile(certPemEnv, certFileEnv *goenvconf.EnvString) ([]byte, error) {
	var certData []byte

	var err error

	if certPemEnv != nil {
		certData, err = loadCertificateString(*certPemEnv)
		if err != nil {
			return nil, fmt.Errorf("failed to load PEM: %w", err)
		}
	}

	if len(certData) == 0 && certFileEnv != nil {
		certFile, err := certFileEnv.GetOrDefault("")
		if err != nil {
			return nil, fmt.Errorf("failed to load file: %w", err)
		}

		if certFile != "" {
			certData, err = os.ReadFile(filepath.Clean(certFile))
			if err != nil {
				return nil, fmt.Errorf("failed to read certificate file: %w", err)
			}
		}
	}

	if len(certData) == 0 {
		return nil, errTLSPEMAndFileEmpty
	}

	return certData, nil
}
