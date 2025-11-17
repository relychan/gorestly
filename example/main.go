package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/hasura/gotel"
	"github.com/prometheus/common/model"
	"github.com/relychan/gorestly"
	"go.opentelemetry.io/otel"
	"resty.dev/v3"
)

var tracer = otel.Tracer("gorestly")

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		// Level: slog.LevelDebug,
	}))

	_ = os.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "1000ms")

	otlpConfig := &gotel.OTLPConfig{
		ServiceName:         "restly",
		OtlpTracesEndpoint:  "http://localhost:4317",
		OtlpMetricsEndpoint: "http://localhost:9090/api/v1/otlp/v1/metrics",
		OtlpMetricsProtocol: gotel.OTLPProtocolHTTPProtobuf,
		MetricsExporter:     gotel.OTELMetricsExporterOTLP,
	}

	exporters, err := gotel.SetupOTelExporters(context.Background(), otlpConfig, "restly", logger)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		_ = exporters.Shutdown(context.Background())
	}()

	timeout := 10 * model.Duration(time.Second)

	client, err := gorestly.NewClientFromConfig(
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

	client.EnableTrace()

	for i := range 100 {
		getTodo(client, i)
		createPost(client, i)
		time.Sleep(time.Second)
	}
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
