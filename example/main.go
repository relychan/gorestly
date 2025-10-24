package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/common/model"
	"github.com/relychan/gorestly"
	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"resty.dev/v3"
)

var tracer = otel.Tracer("gorestly")

func main() {
	traceProvider := setupTraceProvider(context.Background())
	defer func() {
		_ = traceProvider.Shutdown(context.Background())
	}()

	otel.SetTracerProvider(traceProvider)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		// Level: slog.LevelDebug,
	}))

	timeout := 10 * model.Duration(time.Second)
	client, err := gorestly.NewFromConfig(
		gorestly.RestyConfig{
			Timeout: &timeout,
		},
		gorestly.WithLogger(logger),
		gorestly.WithTracer(tracer),
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = client.Close()
	}()

	for i := range 100 {
		getTodo(client, i)
		createPost(client, i)
		time.Sleep(time.Second)
	}
}

func setupTraceProvider(ctx context.Context) *trace.TracerProvider {
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader)),
	)

	otel.SetTextMapPropagator(propagator)

	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint("localhost:4317"),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		panic(err)
	}

	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("gorestly"),
	)
	return trace.NewTracerProvider(trace.WithResource(resources), trace.WithBatcher(traceExporter))
}

func getTodo(client *resty.Client, id int) {
	ctx, span := tracer.Start(context.Background(), "getTodo")
	defer span.End()

	endpoint := "https://jsonplaceholder.typicode.com/todos/" + strconv.Itoa(id)

	resp, err := client.R().SetContext(ctx).Get(endpoint)
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

}

func createPost(client *resty.Client, id int) {
	ctx, span := tracer.Start(context.Background(), "createPost")
	defer span.End()

	endpoint := "https://jsonplaceholder.typicode.com/posts"

	resp, err := client.R().SetContext(ctx).SetBody(map[string]any{
		"id":   id + 1,
		"name": "test",
	}).Post(endpoint)
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()
}
