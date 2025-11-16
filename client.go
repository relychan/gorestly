// Package gorestly is a wrapper of https://github.com/go-resty/resty HTTP client with reusable configurations.
package gorestly

import (
	"context"
	"log/slog"
	"time"

	"github.com/relychan/gorestly/authc"
	"github.com/relychan/gorestly/authc/digestauth"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

// NewClientFromConfig creates a resty client with configuration.
func NewClientFromConfig(config RestyConfig, options ...Option) (*resty.Client, error) {
	opts := &clientOptions{
		Logger: slog.Default(),
	}

	for _, option := range options {
		option(opts)
	}

	transport, err := config.ToTransport()
	if err != nil {
		return nil, err
	}

	isDebug := opts.Logger.Enabled(context.TODO(), slog.LevelDebug)

	client := resty.New().
		SetTransport(transport).
		SetDebug(isDebug).
		SetDebugLogFormatter(nil).
		OnDebugLog(createDebugLogCallback(opts.Logger)).
		SetLogger(&slogWrapper{Logger: opts.Logger})

	err = addTelemetryMiddlewares(client, opts)
	if err != nil {
		return nil, err
	}

	if !isDebug {
		client = client.AddResponseMiddleware(createResponseLoggingMiddleware(opts.Logger))
	}

	if config.TLS != nil {
		err = addTLSCertificates(client, config.TLS)
		if err != nil {
			return nil, err
		}
	}

	err = setClientAuthentication(client, config.Authentication)
	if err != nil {
		return nil, err
	}

	if config.Timeout != nil && *config.Timeout > 0 {
		client = client.SetTimeout(time.Duration(*config.Timeout))
	}

	client = setRestyRetryConfig(client, config.Retry)

	return addContentDecompresser(client), nil
}

func setClientAuthentication(client *resty.Client, authentication *authc.RestlyAuthConfig) error {
	if authentication == nil || authentication.IsZero() {
		return nil
	}

	digestAuthConfig, ok := authentication.HTTPClientAuthDefinition.(*digestauth.DigestAuthConfig)
	if ok {
		return digestauth.SetDigestAuth(client, digestAuthConfig)
	}

	injector, err := authc.NewInjectorFromConfig(*authentication)
	if err != nil {
		return err
	}

	if injector != nil {
		client.AddRequestMiddleware(authc.NewAuthMiddleware(injector))
	}

	return nil
}

type clientOptions struct {
	Logger                    *slog.Logger
	Tracer                    trace.Tracer
	Meter                     metric.Meter
	TraceHighCardinalityPath  bool
	MetricHighCardinalityPath bool
	CustomAttributesFunc      CustomAttributesFunc
}

// CustomAttributesFunc abstracts a function to add custom attributes to spans and metrics.
type CustomAttributesFunc func(*resty.Response) []attribute.KeyValue

// Option abstracts a function to modify client options.
type Option func(*clientOptions)

// WithLogger create an option to set the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(co *clientOptions) {
		if logger != nil {
			co.Logger = logger
		}
	}
}

// WithTracer create an option to set the tracer.
func WithTracer(tracer trace.Tracer) Option {
	return func(co *clientOptions) {
		co.Tracer = tracer
	}
}

// WithMeter create an option to set the meter for metrics.
func WithMeter(meter metric.Meter) Option {
	return func(co *clientOptions) {
		co.Meter = meter
	}
}

// WithTraceHighCardinalityPath enables high cardinality path on traces.
func WithTraceHighCardinalityPath(enabled bool) Option {
	return func(co *clientOptions) {
		co.TraceHighCardinalityPath = enabled
	}
}

// WithMetricHighCardinalityPath enables high cardinality path on metrics.
func WithMetricHighCardinalityPath(enabled bool) Option {
	return func(co *clientOptions) {
		co.MetricHighCardinalityPath = enabled
	}
}

// WithCustomAttributesFunc set the function to add custom attributes to spans and metrics.
func WithCustomAttributesFunc(fn CustomAttributesFunc) Option {
	return func(co *clientOptions) {
		co.CustomAttributesFunc = fn
	}
}
