package gorestly

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

var sensitiveHeaderRegex = regexp.MustCompile(`auth|key|secret|token`)

// SetSpanHeaderAttributes sets header attributes to the otel span.
func SetSpanHeaderAttributes(
	span trace.Span,
	prefix string,
	httpHeaders http.Header,
	allowedHeaders ...string,
) {
	headers := NewTelemetryHeaders(httpHeaders, allowedHeaders...)

	for key, values := range headers {
		span.SetAttributes(attribute.StringSlice(prefix+strings.ToLower(key), values))
	}
}

// NewTelemetryHeaders creates a new header map with sensitive values masked.
func NewTelemetryHeaders(httpHeaders http.Header, allowedHeaders ...string) http.Header {
	result := http.Header{}

	if len(allowedHeaders) > 0 {
		for _, key := range allowedHeaders {
			value := httpHeaders.Get(key)

			if value == "" {
				continue
			}

			if IsSensitiveHeader(key) {
				result.Set(strings.ToLower(key), MaskString(value))
			} else {
				result.Set(strings.ToLower(key), value)
			}
		}

		return result
	}

	for key, headers := range httpHeaders {
		if len(headers) == 0 {
			continue
		}

		values := headers
		if IsSensitiveHeader(key) {
			values = make([]string, len(headers))
			for i, header := range headers {
				values[i] = MaskString(header)
			}
		}

		result[key] = values
	}

	return result
}

func createRequestTracingMiddleware(opts *clientOptions) resty.RequestMiddleware {
	return func(client *resty.Client, req *resty.Request) error {
		spanName := req.Method

		reqURL, err := url.Parse(req.URL)
		if err != nil {
			client.Logger().
				Warnf("", fmt.Sprintf("failed to parse url %s: %s", req.URL, err.Error()))
		} else if !opts.DisableHighCardinalityPath {
			spanName += " " + reqURL.Path
		}

		ctx, span := opts.Tracer.Start(
			req.Context(),
			spanName,
			trace.WithSpanKind(trace.SpanKindClient),
		)

		span.SetAttributes(
			attribute.String("http.request.method", req.Method),
			attribute.String("url.full", req.URL),
			attribute.String("network.protocol.name", "http"),
		)

		hostname, port, err := ParseHostNameAndPortFromURL(reqURL)
		if err != nil {
			client.Logger().
				Warnf("", fmt.Sprintf("failed to parse hostname and port from host %s: %s", reqURL.Host, err.Error()))
		} else {
			span.SetAttributes(
				attribute.String("server.address", hostname),
				attribute.Int("server.port", port),
			)
		}

		if req.RawRequest != nil && req.RawRequest.ContentLength > 0 {
			span.SetAttributes(
				attribute.Int64("http.request.body.size", req.RawRequest.ContentLength),
			)
		}

		if req.Timeout > 0 {
			span.SetAttributes(attribute.String("http.request.timeout", req.Timeout.String()))
		}

		SetSpanHeaderAttributes(span, "http.request.header.", req.Header)

		propagator := otel.GetTextMapPropagator()
		propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))
		req.SetContext(ctx)

		return nil
	}
}

func responseTracingMiddleware(_ *resty.Client, resp *resty.Response) error {
	span := trace.SpanFromContext(resp.Request.Context())

	if !span.IsRecording() {
		return nil
	}

	statusCode := resp.StatusCode()

	span.SetAttributes(attribute.Int("http.response.status_code", statusCode))
	SetSpanHeaderAttributes(span, "http.response.header.", resp.Header())

	if resp.Request.RawRequest != nil && resp.Request.RawRequest.ContentLength > 0 {
		span.SetAttributes(
			attribute.Int64("http.request.body.size", resp.Request.RawRequest.ContentLength),
		)
	}

	responseSize := resp.RawResponse.ContentLength

	if resp.IsRead {
		responseSize = resp.Size()
	}

	span.SetAttributes(attribute.Int64("http.response.size", responseSize))

	if resp.Request.IsTrace {
		traceInfo := resp.Request.TraceInfo()
		span.SetAttributes(
			attribute.String("network.peer.address", traceInfo.RemoteAddr),
			attribute.Int("http.request.resend_count", traceInfo.RequestAttempt),
			attribute.Int64(
				"http.stats.connection_idle_time_ms",
				traceInfo.ConnIdleTime.Milliseconds(),
			),
			attribute.Int64("http.stats.connection_time_ms", traceInfo.ConnTime.Milliseconds()),
			attribute.Int64("http.stats.dns_lookup_time_ms", traceInfo.DNSLookup.Milliseconds()),
			attribute.Int64("http.stats.response_time", traceInfo.ResponseTime.Milliseconds()),
			attribute.Int64("http.stats.server_time", traceInfo.ServerTime.Milliseconds()),
			attribute.Int64("http.stats.tcp_connection_time", traceInfo.TCPConnTime.Milliseconds()),
			attribute.Int64("http.stats.tls_handshake_time", traceInfo.TLSHandshake.Milliseconds()),
			attribute.Bool("http.stats.is_connection_reused", traceInfo.IsConnReused),
			attribute.Bool("http.stats.is_connection_was_idle", traceInfo.IsConnWasIdle),
		)
	}

	if statusCode >= 400 {
		span.SetStatus(codes.Error, resp.String())
		span.SetAttributes(attribute.String("http.response.body", resp.String()))
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()

	return nil
}
