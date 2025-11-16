package gorestly

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/hasura/gotel/otelutils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/semconv/v1.37.0/httpconv"
	"go.opentelemetry.io/otel/trace"
	"resty.dev/v3"
)

func addTelemetryMiddlewares(c *resty.Client, opts *clientOptions) error {
	if opts.Tracer == nil && opts.Meter == nil {
		return nil
	}

	if opts.Tracer == nil {
		opts.Tracer = otel.Tracer("gorestly")
	}

	if opts.Meter == nil {
		opts.Meter = otel.Meter("gorestly")
	}

	activeRequestsMetric, err := httpconv.NewClientActiveRequests(opts.Meter)
	if err != nil {
		return err
	}

	addTelemetryRequestMiddleware(c, opts, activeRequestsMetric)

	return addTelemetryResponseMiddlewares(c, opts, activeRequestsMetric)
}

func addTelemetryRequestMiddleware( //nolint:funlen
	c *resty.Client,
	opts *clientOptions,
	activeRequestsMetric httpconv.ClientActiveRequests,
) {
	c.AddRequestMiddleware(func(client *resty.Client, req *resty.Request) error {
		spanName := req.Method

		reqURL, err := url.Parse(req.URL)
		if err != nil {
			client.Logger().
				Warnf("", fmt.Sprintf("failed to parse url %s: %s", req.URL, err.Error()))
		} else if opts.TraceHighCardinalityPath {
			spanName += " " + reqURL.Path
		}

		ctx, span := opts.Tracer.Start(
			req.Context(),
			spanName,
			trace.WithSpanKind(trace.SpanKindClient),
		)

		span.SetAttributes(
			semconv.URLFull(req.URL),
			semconv.NetworkProtocolName("http"),
		)

		hostname, port, err := ParseHostNameAndPortFromURL(reqURL)
		if err != nil {
			client.Logger().
				Warnf("", fmt.Sprintf("failed to parse hostname and port from host %s: %s", reqURL.Host, err.Error()))
		}

		commonAttrs := []attribute.KeyValue{
			semconv.ServerAddress(hostname),
			semconv.ServerPort(port),
			httpRequestMethodAttr(req.Method),
		}

		span.SetAttributes(commonAttrs...)

		metricWithRequestAttrs := commonAttrs

		if opts.MetricHighCardinalityPath {
			metricWithRequestAttrs = append(
				metricWithRequestAttrs,
				semconv.URLPath(reqURL.Path),
			)
		}

		activeRequestsMetric.Add(ctx, 1, hostname, port, metricWithRequestAttrs...)

		if req.RawRequest != nil && req.RawRequest.ContentLength > 0 {
			span.SetAttributes(
				semconv.HTTPRequestBodySize(int(req.RawRequest.ContentLength)),
			)
		}

		if req.Timeout > 0 {
			span.SetAttributes(attribute.String("http.request.timeout", req.Timeout.String()))
		}

		otelutils.SetSpanHeaderAttributes(span, "http.request.header", req.Header)

		propagator := otel.GetTextMapPropagator()
		propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))
		req.SetContext(ctx)

		return nil
	})
}

func addTelemetryResponseMiddlewares( //nolint:gocognit,funlen,maintidx
	c *resty.Client,
	opts *clientOptions,
	activeRequestsMetric httpconv.ClientActiveRequests,
) error {
	idleConnectionDurationMetric, err := opts.Meter.Float64Histogram(
		"http.client.idle_connection.duration",
		metric.WithDescription("The duration of how long the connection that was previously idle."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	dnsLookupDurationMetric, err := opts.Meter.Float64Histogram("http.client.dns_lookup.duration",
		metric.WithDescription("The duration of the transport took to perform DNS lookup."),
		metric.WithUnit("s"))
	if err != nil {
		return err
	}

	serverDurationMetric, err := opts.Meter.Float64Histogram("http.client.server.duration",
		metric.WithDescription("The duration of the server for responding to the first byte."),
		metric.WithUnit("s"))
	if err != nil {
		return err
	}

	responseDurationMetric, err := opts.Meter.Float64Histogram(
		"http.client.response.duration",
		metric.WithDescription(
			"the duration since the first response byte from the server to request completion.",
		),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	tcpConnectionDurationMetric, err := opts.Meter.Float64Histogram(
		"http.client.tcp_connection.duration",
		metric.WithDescription(
			"the duration since the first response byte from the server to request completion.",
		),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	tlsHandshakeDurationMetric, err := opts.Meter.Float64Histogram(
		"http.client.tls_handshake.duration",
		metric.WithDescription(
			"the duration since the first response byte from the server to request completion.",
		),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	connectionDurationMetric, err := httpconv.NewClientConnectionDuration(opts.Meter)
	if err != nil {
		return err
	}

	requestBodySizeMetric, err := httpconv.NewClientRequestBodySize(opts.Meter)
	if err != nil {
		return err
	}

	requestDurationMetric, err := httpconv.NewClientRequestDuration(opts.Meter)
	if err != nil {
		return err
	}

	responseBodySizeMetric, err := httpconv.NewClientResponseBodySize(opts.Meter)
	if err != nil {
		return err
	}

	c.AddResponseMiddleware(func(client *resty.Client, resp *resty.Response) error {
		ctx := resp.Request.Context()
		span := trace.SpanFromContext(ctx)

		requestMethod := httpconv.RequestMethodAttr(resp.Request.Method)

		hostname, port, err := ParseHostNameAndPortFromURL(resp.Request.RawRequest.URL)
		if err != nil {
			client.Logger().
				Warnf("", fmt.Sprintf("failed to parse hostname and port from host %s: %s", resp.Request.RawRequest.URL.Host, err.Error()))
		}

		commonAttrs := []attribute.KeyValue{
			semconv.ServerAddress(hostname),
			semconv.ServerPort(port),
			semconv.URLScheme(resp.RawResponse.Request.URL.Scheme),
		}

		metricWithRequestAttrs := commonAttrs
		metricWithRequestAttrs = append(
			metricWithRequestAttrs,
			httpRequestMethodAttr(resp.Request.Method),
		)

		if opts.MetricHighCardinalityPath {
			metricWithRequestAttrs = append(
				metricWithRequestAttrs,
				semconv.URLPath(resp.Request.RawRequest.URL.Path),
			)
		}

		activeRequestsMetric.Add(ctx, -1, hostname, port, metricWithRequestAttrs...)

		if !span.IsRecording() {
			return nil
		}

		statusCode := resp.StatusCode()
		statusCodeAttr := semconv.HTTPResponseStatusCode(statusCode)
		protocolVersionAttr := semconv.NetworkProtocolVersion(
			fmt.Sprintf(
				"%d.%d",
				resp.RawResponse.Request.ProtoMajor,
				resp.RawResponse.Request.ProtoMinor,
			),
		)

		metricWithRequestAttrs = append(
			metricWithRequestAttrs,
			statusCodeAttr,
			protocolVersionAttr,
			semconv.NetworkProtocolName("http"),
		)

		span.SetAttributes(statusCodeAttr, protocolVersionAttr)

		if opts.CustomAttributesFunc != nil {
			customAttrs := opts.CustomAttributesFunc(resp)
			metricWithRequestAttrs = append(metricWithRequestAttrs, customAttrs...)
			span.SetAttributes(customAttrs...)
		}

		otelutils.SetSpanHeaderAttributes(span, "http.response.header", resp.Header())

		if resp.Request.RawRequest != nil && resp.Request.RawRequest.ContentLength > 0 {
			requestBodySizeMetric.Record(
				ctx,
				resp.Request.RawRequest.ContentLength,
				requestMethod,
				hostname,
				port,
				metricWithRequestAttrs...,
			)

			span.SetAttributes(
				semconv.HTTPRequestBodySize(int(resp.Request.RawRequest.ContentLength)),
			)
		}

		responseSize := resp.RawResponse.ContentLength

		if resp.IsRead {
			responseSize = resp.Size()
		}

		responseBodySizeMetric.Record(
			ctx,
			responseSize,
			requestMethod,
			hostname,
			port,
			metricWithRequestAttrs...)
		span.SetAttributes(semconv.HTTPResponseBodySize(int(responseSize)))

		if resp.Request.IsTrace { //nolint:nestif
			traceInfo := resp.Request.TraceInfo()

			peerAddress, peerPort, err := otelutils.SplitHostPort(traceInfo.RemoteAddr)
			if err != nil {
				client.Logger().
					Warnf("", fmt.Sprintf("failed to split hostname and port from remote address %s: %s", traceInfo.RemoteAddr, err.Error()))
			}

			if peerAddress != "" {
				span.SetAttributes(semconv.NetworkPeerAddress(peerAddress))

				if peerPort > 0 {
					span.SetAttributes(semconv.NetworkPeerPort(peerPort))
				}
			}

			commonAttrsSet := metric.WithAttributeSet(attribute.NewSet(commonAttrs...))
			metricWithRequestAttrsSet := metric.WithAttributeSet(
				attribute.NewSet(metricWithRequestAttrs...),
			)

			requestDurationMetric.Record(
				ctx,
				traceInfo.TotalTime.Seconds(),
				requestMethod,
				hostname,
				port,
				metricWithRequestAttrs...,
			)
			connectionDurationMetric.Record(
				ctx,
				traceInfo.ConnTime.Seconds(),
				hostname,
				port,
				commonAttrs...)
			dnsLookupDurationMetric.Record(
				ctx,
				traceInfo.DNSLookup.Seconds(),
				commonAttrsSet,
			)
			serverDurationMetric.Record(
				ctx,
				traceInfo.ServerTime.Seconds(),
				metricWithRequestAttrsSet,
			)
			responseDurationMetric.Record(
				ctx,
				traceInfo.ResponseTime.Seconds(),
				metricWithRequestAttrsSet,
			)
			tcpConnectionDurationMetric.Record(
				ctx,
				traceInfo.TCPConnTime.Seconds(),
				commonAttrsSet,
			)
			tlsHandshakeDurationMetric.Record(
				ctx,
				traceInfo.TLSHandshake.Seconds(),
				commonAttrsSet,
			)

			if traceInfo.IsConnWasIdle {
				idleConnectionDurationMetric.Record(
					ctx,
					traceInfo.ConnIdleTime.Seconds(),
					commonAttrsSet,
				)

				span.SetAttributes(
					attribute.Int64(
						"http.stats.connection_idle_time_ms",
						traceInfo.ConnIdleTime.Milliseconds(),
					),
				)
			}

			span.SetAttributes(
				semconv.HTTPRequestResendCount(traceInfo.RequestAttempt),
				attribute.Int64("http.stats.connection_time_ms", traceInfo.ConnTime.Milliseconds()),
				attribute.Int64(
					"http.stats.dns_lookup_time_ms",
					traceInfo.DNSLookup.Milliseconds(),
				),
				attribute.Int64(
					"http.stats.response_time_ms",
					traceInfo.ResponseTime.Milliseconds(),
				),
				attribute.Int64("http.stats.server_time_ms", traceInfo.ServerTime.Milliseconds()),
				attribute.Int64(
					"http.stats.tcp_connection_time_ms",
					traceInfo.TCPConnTime.Milliseconds(),
				),
				attribute.Int64(
					"http.stats.tls_handshake_time_ms",
					traceInfo.TLSHandshake.Milliseconds(),
				),
				attribute.Bool("http.stats.is_connection_reused", traceInfo.IsConnReused),
				attribute.Bool("http.stats.is_connection_was_idle", traceInfo.IsConnWasIdle),
			)
		}

		if statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(statusCode))
			span.SetAttributes(attribute.String("http.response.body", resp.String()))
		} else {
			span.SetStatus(codes.Ok, "")
		}

		span.End()

		return nil
	})

	return nil
}

func httpRequestMethodAttr(method string) attribute.KeyValue {
	return attribute.String("http.request.method", method)
}
