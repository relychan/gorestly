package gorestly

import (
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/common/model"
	"github.com/relychan/gocompress"
	"github.com/relychan/gorestly/authc"
	"resty.dev/v3"
)

// RestyConfig contains configurations to create client.
type RestyConfig struct {
	// Default maximum timeout duration that is applied for all requests.
	Timeout *model.Duration `json:"timeout,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"timeout,omitempty"`
	// Transport stores the http.Transport configuration for the http client.
	Transport *HTTPTransportConfig `json:"transport,omitempty" yaml:"transport,omitempty"`
	// The transport layer security (LTS) configuration for the mutualTLS authentication.
	TLS *TLSConfig `json:"tls,omitempty" yaml:"tls,omitempty"`
	// Retry policy of client requests.
	Retry *RestyRetryConfig `json:"retry,omitempty" yaml:"retry,omitempty"`
	// Authentication configuration.
	Authentication *authc.RestlyAuthConfig `json:"authentication,omitempty" yaml:"authentication,omitempty"`
}

// ToTransport creates an http transport from configurations.
func (c *RestyConfig) ToTransport() (*http.Transport, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}

	if c.Transport != nil {
		transport = c.Transport.ToTransport()
	}

	if c.TLS == nil {
		return transport, nil
	}

	tlsConf, err := loadTLSConfig(c.TLS)
	if err != nil {
		return nil, err
	}

	transport.TLSClientConfig = tlsConf

	return transport, nil
}

// RestyDialerConfig contains options the http.Dialer to connect to an address.
type RestyDialerConfig struct {
	// The maximum amount of time a dial will wait for a connect to complete.
	// If Deadline is also set, it may fail earlier.
	Timeout *model.Duration `json:"timeout,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"timeout"`
	// Keep-alive probes are enabled by default.
	KeepAliveEnabled *bool `json:"keepAliveEnabled,omitempty" yaml:"keepAliveEnabled"`
	// KeepAliveInterval is the time between keep-alive probes. If zero, a default value of 15 seconds is used.
	KeepAliveInterval *model.Duration `json:"keepAliveInterval,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"keepAliveInterval"`
	// KeepAliveCount is the maximum number of keep-alive probes that can go unanswered before dropping a connection.
	// If zero, a default value of 9 is used.
	KeepAliveCount *int `json:"keepAliveCount,omitempty" jsonschema:"nullable,min=0" yaml:"keepAliveCount"`
	// KeepAliveIdle is the time that the connection must be idle before the first keep-alive probe is sent.
	// If zero, a default value of 15 seconds is used.
	KeepAliveIdle *model.Duration `json:"keepAliveIdle,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"keepAliveIdle"`
	// FallbackDelay specifies the length of time to wait before spawning a RFC 6555 Fast Fallback connection.
	// That is, this is the amount of time to wait for IPv6 to succeed before assuming that IPv6 is misconfigured and falling back to IPv4.
	// If zero, a default delay of 300ms is used. A negative value disables Fast Fallback support.
	FallbackDelay *model.Duration `json:"fallbackDelay,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"fallbackDelay"`
}

// HTTPTransportConfig stores the http.Transport configuration for the http client.
type HTTPTransportConfig struct {
	// Options the http.Dialer to connect to an address
	Dialer *RestyDialerConfig `json:"dialer,omitempty" yaml:"dialer"`
	// Idle connection timeout. The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself. Zero means no limit.
	IdleConnTimeout *model.Duration `json:"idleConnTimeout,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"idleConnTimeout"`
	// Response header timeout, if non-zero, specifies the amount of time to wait for a server's response headers after fully writing the request (including its body, if any).
	// This time does not include the time to read the response body.
	// This timeout is used to cover cases where the tcp connection works but the server never answers.
	ResponseHeaderTimeout *model.Duration `json:"responseHeaderTimeout,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"responseHeaderTimeout"`
	// TLS handshake timeout is the maximum amount of time to wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout *model.Duration `json:"tlsHandshakeTimeout,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"tlsHandshakeTimeout"`
	// Expect continue timeout, if non-zero, specifies the amount of time to wait for a server's first response headers after fully writing the request headers if the request has an "Expect: 100-continue" header.
	ExpectContinueTimeout *model.Duration `json:"expectContinueTimeout,omitempty" jsonschema:"oneof_ref=#/$defs/Duration,oneof_type=null" yaml:"expectContinueTimeout"`
	// MaxIdleConns controls the maximum number of idle (keep-alive) connections across all hosts. Zero means no limit.
	MaxIdleConns *int `json:"maxIdleConns,omitempty" jsonschema:"nullable,min=0" yaml:"maxIdleConns"`
	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle (keep-alive) connections to keep per-host.
	MaxIdleConnsPerHost *int `json:"maxIdleConnsPerHost,omitempty" jsonschema:"nullable,min=0" yaml:"maxIdleConnsPerHost"`
	// MaxConnsPerHost optionally limits the total number of connections per host, including connections in the dialing, active, and idle states.
	// On limit violation, dials will block. Zero means no limit.
	MaxConnsPerHost *int `json:"maxConnsPerHost,omitempty" jsonschema:"nullable,min=0" yaml:"maxConnsPerHost"`
	// MaxResponseHeaderBytes specifies a limit on how many response bytes are allowed in the server's response header.
	// Zero means to use a default limit.
	MaxResponseHeaderBytes *int64 `json:"maxResponseHeaderBytes,omitempty" jsonschema:"nullable,min=0" yaml:"maxResponseHeaderBytes"`
	// ReadBufferSize specifies the size of the read buffer used when reading from the transport.
	// If zero, a default (currently 4KB) is used.
	ReadBufferSize *int `json:"readBufferSize,omitempty" jsonschema:"nullable,min=0" yaml:"readBufferSize"`
	// WriteBufferSize specifies the size of the write buffer used when writing to the transport.
	// If zero, a default (currently 4KB) is used.
	WriteBufferSize *int `json:"writeBufferSize,omitempty" jsonschema:"nullable,min=0" yaml:"writeBufferSize"`
	// DisableKeepAlives, if true, disables HTTP keep-alives and will only use the connection to the server for a single HTTP request.
	// This is unrelated to the similarly named TCP keep-alives.
	DisableKeepAlives bool `json:"disableKeepAlives,omitempty" yaml:"disableKeepAlives"`
}

// ToTransport creates an http transport from the configuration.
func (ttc HTTPTransportConfig) ToTransport() *http.Transport {
	dialer := ttc.toDialer()

	defaultTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		ResponseHeaderTimeout: time.Minute,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     ttc.DisableKeepAlives,
		DisableCompression:    true, // Resty handles it, see [Client.AddContentDecoder]
	}

	if ttc.ExpectContinueTimeout != nil {
		defaultTransport.ExpectContinueTimeout = time.Duration(*ttc.ExpectContinueTimeout)
	}

	if ttc.IdleConnTimeout != nil {
		defaultTransport.IdleConnTimeout = time.Duration(*ttc.IdleConnTimeout)
	}

	if ttc.MaxConnsPerHost != nil {
		defaultTransport.MaxConnsPerHost = *ttc.MaxConnsPerHost
	}

	if ttc.MaxIdleConns != nil {
		defaultTransport.MaxIdleConns = *ttc.MaxIdleConns
	}

	if ttc.MaxIdleConnsPerHost != nil && *ttc.MaxIdleConnsPerHost > 0 {
		defaultTransport.MaxIdleConnsPerHost = *ttc.MaxIdleConnsPerHost
	} else {
		defaultTransport.MaxIdleConnsPerHost = runtime.GOMAXPROCS(0) + 1
	}

	if ttc.ResponseHeaderTimeout != nil {
		defaultTransport.ResponseHeaderTimeout = time.Duration(*ttc.ResponseHeaderTimeout)
	}

	if ttc.TLSHandshakeTimeout != nil {
		defaultTransport.TLSHandshakeTimeout = time.Duration(*ttc.TLSHandshakeTimeout)
	}

	if ttc.MaxResponseHeaderBytes != nil && *ttc.MaxResponseHeaderBytes > 0 {
		defaultTransport.MaxResponseHeaderBytes = *ttc.MaxResponseHeaderBytes
	}

	if ttc.ReadBufferSize != nil && *ttc.ReadBufferSize > 0 {
		defaultTransport.ReadBufferSize = *ttc.ReadBufferSize
	}

	if ttc.WriteBufferSize != nil && *ttc.WriteBufferSize > 0 {
		defaultTransport.WriteBufferSize = *ttc.WriteBufferSize
	}

	return defaultTransport
}

// ToDialer creates a net dialer from the configuration.
func (ttc HTTPTransportConfig) toDialer() *net.Dialer {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Interval: 30 * time.Second,
		},
	}

	if ttc.Dialer == nil {
		return dialer
	}

	if ttc.Dialer.Timeout != nil {
		dialer.Timeout = time.Duration(*ttc.Dialer.Timeout)
	}

	if ttc.Dialer.KeepAliveEnabled != nil {
		dialer.KeepAliveConfig.Enable = *ttc.Dialer.KeepAliveEnabled
	}

	if ttc.Dialer.KeepAliveCount != nil {
		dialer.KeepAliveConfig.Count = *ttc.Dialer.KeepAliveCount
	}

	if ttc.Dialer.KeepAliveIdle != nil {
		dialer.KeepAliveConfig.Idle = time.Duration(*ttc.Dialer.KeepAliveIdle)
	}

	if ttc.Dialer.KeepAliveInterval != nil {
		dialer.KeepAliveConfig.Interval = time.Duration(*ttc.Dialer.KeepAliveInterval)
	}

	if ttc.Dialer.FallbackDelay != nil {
		dialer.FallbackDelay = time.Duration(*ttc.Dialer.FallbackDelay)
	}

	return dialer
}

func addContentDecompresser(client *resty.Client) *resty.Client {
	gzipc := gocompress.GzipCompressor{}
	deflatec := gocompress.DeflateCompressor{}
	zstdc := gocompress.ZstdCompressor{}

	client = client.AddContentDecompresser(string(gocompress.EncodingDeflate), deflatec.Decompress).
		AddContentDecompresser(string(gocompress.EncodingGzip), gzipc.Decompress).
		AddContentDecompresser(string(gocompress.EncodingZstd), zstdc.Decompress)

	return client
}
