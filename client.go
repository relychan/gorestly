// Package gorestly is a wrapper of https://github.com/go-resty/resty HTTP client with reusable configurations.
package gorestly

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

// NewFromConfig creates a resty client with configuration.
func NewFromConfig(config RestyConfig, options ...Option) (*resty.Client, error) {
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

	if opts.Tracer != nil {
		client = client.AddRequestMiddleware(createRequestTracingMiddleware(opts)).
			AddResponseMiddleware(responseTracingMiddleware)
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

	if config.Timeout != nil && *config.Timeout > 0 {
		client = client.SetTimeout(time.Duration(*config.Timeout))
	}

	client = setRestyRetryConfig(client, config.Retry)

	return addContentDecompresser(client), nil
}

type clientOptions struct {
	Logger                     *slog.Logger
	Tracer                     trace.Tracer
	DisableHighCardinalityPath bool
}

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

// WithDisableHighCardinalityPath disables high cardinality path on tracing and metrics.
func WithDisableHighCardinalityPath(disabled bool) Option {
	return func(co *clientOptions) {
		co.DisableHighCardinalityPath = disabled
	}
}
