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
		"invalid TLS configuration: minVersion cannot be greater than maxVersion",
	)
	errUnsupportedTLSVersion  = errors.New("unsupported TLS version")
	errUnsupportedCipherSuite = errors.New("invalid TLS cipher suite")
	errTLSPEMAndFileEmpty     = errors.New("both PEM and file are empty")
)

// TLSClientCertificate represents a cert and key pair certificate.
type TLSClientCertificate struct {
	// CertFile is the path to the TLS cert to use for TLS required connections.
	CertFile *goenvconf.EnvString `json:"certFile,omitempty" mapstructure:"certFile" yaml:"certFile,omitempty"`
	// CertPem is alternative to certFile. Provide the certificate contents as a base64-encoded string instead of a filepath.
	CertPem *goenvconf.EnvString `json:"certPem,omitempty" mapstructure:"certPem" yaml:"certPem,omitempty"`
	// KeyFile is the path to the TLS key to use for TLS required connections.
	KeyFile *goenvconf.EnvString `json:"keyFile,omitempty" mapstructure:"keyFile" yaml:"keyFile,omitempty"`
	// KeyPem is the alternative to keyFile. Provide the key contents as a base64-encoded string instead of a filepath.
	KeyPem *goenvconf.EnvString `json:"keyPem,omitempty" mapstructure:"keyPem" yaml:"keyPem,omitempty"`
}

// LoadKeyPair loads the X509 key pair from configurations.
func (tc TLSClientCertificate) LoadKeyPair(
	tlsConfig TLSClientCertificate,
) (*tls.Certificate, error) {
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

// TLSConfig represents the transport layer security (LTS) configuration for the mutualTLS authentication.
type TLSConfig struct {
	// Interval to reload certificates. Only takes effect for file-path certificates.
	// Default value is 24 hours.
	ReloadInterval *model.Duration `json:"reloadInterval,omitempty" jsonschema:"nullable,type=string,pattern=^((([0-9]+h)?([0-9]+m)?([0-9]+s))|(([0-9]+h)?([0-9]+m))|([0-9]+h))$" mapstructure:"reloadInterval" yaml:"reloadInterval"`
	// RootCAFile represents paths to root certificates. For a client this verifies the server certificate. For a server this verifies client certificates.
	// If empty uses system root CA.
	RootCAFile []goenvconf.EnvString `json:"rootCAFile,omitempty" mapstructure:"rootCAFile" yaml:"rootCAFile,omitempty"`
	// RootCAPem is the alternative to rootCAFile. Provide the CA cert contents as a base64-encoded string instead of a filepath.
	RootCAPem []goenvconf.EnvString `json:"rootCAPem,omitempty" mapstructure:"rootCAPem" yaml:"rootCAPem,omitempty"`
	// CAFile is the path to the CA cert. For a client this verifies the server certificate. For a server this verifies client certificates.
	// If empty uses system root CA.
	CAFile []goenvconf.EnvString `json:"caFile,omitempty" mapstructure:"caFile" yaml:"caFile,omitempty"`
	// CAPem is alternative to caFile. Provide the CA cert contents as a base64-encoded string instead of a filepath.
	CAPem []goenvconf.EnvString `json:"caPem,omitempty" mapstructure:"caPem" yaml:"caPem,omitempty"`
	// Certificates contains the list of client certificates.
	Certificates []TLSClientCertificate `json:"certificates,omitempty" mapstructure:"certificates" yaml:"certificates,omitempty"`
	// InsecureSkipVerify you can configure TLS to be enabled but skip verifying the server's certificate chain.
	InsecureSkipVerify *goenvconf.EnvBool `json:"insecureSkipVerify,omitempty" mapstructure:"insecureSkipVerify" yaml:"insecureSkipVerify,omitempty"`
	// IncludeSystemCACertsPool whether to load the system certificate authorities pool alongside the certificate authority.
	IncludeSystemCACertsPool *goenvconf.EnvBool `json:"includeSystemCACertsPool,omitempty" mapstructure:"includeSystemCACertsPool" yaml:"includeSystemCACertsPool,omitempty"`
	// Minimum acceptable TLS version.
	MinVersion string `json:"minVersion,omitempty" mapstructure:"minVersion" yaml:"minVersion,omitempty"`
	// Maximum acceptable TLS version.
	MaxVersion string `json:"maxVersion,omitempty" mapstructure:"maxVersion" yaml:"maxVersion,omitempty"`
	// Explicit cipher suites can be set. If left blank, a safe default list is used.
	// See https://go.dev/src/crypto/tls/cipher_suites.go for a list of supported cipher suites.
	CipherSuites []string `json:"cipherSuites,omitempty" mapstructure:"cipherSuites" yaml:"cipherSuites,omitempty"`
	// ServerName requested by client for virtual hosting.
	// This sets the ServerName in the TLSConfig. Please refer to
	// https://godoc.org/crypto/tls#Config for more information. (optional)
	ServerName *goenvconf.EnvString `json:"serverName,omitempty" mapstructure:"serverName" yaml:"serverName,omitempty"`
}

// Validate if the current instance is valid.
func (tc TLSConfig) Validate() error {
	minTLS, err := tc.GetMinVersion()
	if err != nil {
		return fmt.Errorf("minVersion: %w", err)
	}

	maxTLS, err := tc.GetMaxVersion()
	if err != nil {
		return fmt.Errorf("maxVersion: %w", err)
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
				return fmt.Errorf("certificates[%d].certFile: %w", i, err)
			}

			certPem, err := cert.CertPem.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].certPem: %w", i, err)
			}

			if certFile != "" && certPem != "" {
				return errCertificateRequireEitherFileOrPEM
			}
		}

		if cert.KeyFile != nil && cert.KeyPem != nil {
			keyFile, err := cert.KeyFile.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].keyFile: %w", i, err)
			}

			keyPem, err := cert.KeyPem.GetOrDefault("")
			if err != nil {
				return fmt.Errorf("certificates[%d].keyPem: %w", i, err)
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
		return nil, fmt.Errorf("minVersion: %w", err)
	}

	maxTLS, err := tlsConfig.GetMaxVersion()
	if err != nil {
		return nil, fmt.Errorf("maxVersion: %w", err)
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
		c, err := cert.LoadKeyPair(cert)
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
