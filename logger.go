package gorestly

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/hasura/gotel/otelutils"
	"resty.dev/v3"
)

// wrap the base logger with the resty.Logger interface.
type slogWrapper struct {
	*slog.Logger
}

var _ resty.Logger = (*slogWrapper)(nil)

func (sw *slogWrapper) Errorf(_ string, values ...any) {
	sw.printf(slog.LevelError, values...)
}

func (sw *slogWrapper) Warnf(_ string, values ...any) {
	sw.printf(slog.LevelWarn, values...)
}

// Debugf print debug log. Return no-op. Print debug logs at the OnDebugLog callback instead.
func (sw *slogWrapper) Debugf(_ string, _ ...any) {}

func (sw *slogWrapper) printf(level slog.Level, values ...any) {
	messages := []string{}
	attrs := []slog.Attr{}

	for i, value := range values {
		switch val := value.(type) {
		case string:
			messages = append(messages, val)
		case map[string]any:
			for key, mapValue := range val {
				attrs = append(attrs, slog.Any(key, mapValue))
			}
		default:
			attrs = append(attrs, slog.Any("arg"+strconv.Itoa(i), value))
		}
	}

	sw.LogAttrs(context.TODO(), level, strings.Join(messages, ". "), attrs...)
}

func createDebugLogCallback(logger *slog.Logger) resty.DebugLogCallbackFunc {
	return func(dl *resty.DebugLog) {
		logLevel := slog.LevelInfo

		if dl.Response.StatusCode >= 400 {
			logLevel = slog.LevelError
		}

		logger.LogAttrs(
			context.Background(),
			logLevel,
			fmt.Sprintf("[%d] %s %s", dl.Response.StatusCode, dl.Request.Method, dl.Request.URI),
			slog.Any("request", dl.Request),
			slog.Any("response", dl.Response),
			slog.Any("trace_info", dl.TraceInfo),
		)
	}
}

// print request log if the debug mode is disabled.
func createResponseLoggingMiddleware(logger *slog.Logger) resty.ResponseMiddleware {
	return func(_ *resty.Client, resp *resty.Response) error {
		statusCode := resp.StatusCode()

		if resp.Request.Debug || statusCode < 400 {
			return nil
		}

		args := []slog.Attr{
			slog.Any("request", resty.DebugLogRequest{
				URI:          resp.Request.URL,
				Method:       resp.Request.Method,
				Host:         resp.Request.RawRequest.URL.Host,
				Proto:        resp.Request.RawRequest.Proto,
				Header:       otelutils.NewTelemetryHeaders(resp.Request.Header),
				RetryTraceID: resp.Request.RetryTraceID,
				CurlCmd:      resp.Request.CurlCmd(),
				Attempt:      resp.Request.Attempt,
			}),
		}

		if resp.Request.IsTrace {
			traceInfo := resp.Request.TraceInfo()
			args = append(args, slog.Any("trace_info", traceInfo))
		}

		debugResponse := resty.DebugLogResponse{
			StatusCode: statusCode,
			Status:     resp.Status(),
			Proto:      resp.Proto(),
			ReceivedAt: resp.ReceivedAt(),
			Duration:   resp.Duration(),
			Size:       resp.Size(),
			Header:     otelutils.NewTelemetryHeaders(resp.Header()),
		}

		logLevel := slog.LevelInfo

		if statusCode >= 400 {
			logLevel = slog.LevelError
			debugResponse.Body = resp.String()
		}

		args = append(args, slog.Any("response", debugResponse))

		logger.LogAttrs(
			resp.Request.Context(),
			logLevel,
			fmt.Sprintf("[%d] %s %s", statusCode, resp.Request.Method, resp.Request.URL),
			args...,
		)

		return nil
	}
}
