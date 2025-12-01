package observability

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Init configures OpenTelemetry tracing for the Rocket server.
// It is intentionally lightweight: if OTEL_EXPORTER_OTLP_ENDPOINT is not set,
// tracing stays disabled. When enabled, it uses parent-based sampling with a
// configurable ratio.
func Init(ctx context.Context) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// Tracing disabled; return no-op shutdown.
		return func(context.Context) error { return nil }, nil
	}

	insecure := os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true"
	sampleRatio := parseRatio(os.Getenv("SPARK_TRACE_SAMPLE_RATIO"), 0.2)

	clientOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
	}
	if insecure {
		clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
	}
	if headers := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"); headers != "" {
		// Headers should follow k=v comma-separated per OTEL spec.
		clientOpts = append(clientOpts, otlptracehttp.WithHeaders(parseHeaders(headers)))
	}

	exp, err := otlptracehttp.New(ctx, clientOpts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("rocket-server"),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithMaxExportBatchSize(512),
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

func parseRatio(value string, def float64) float64 {
	if value == "" {
		return def
	}
	r, err := strconv.ParseFloat(value, 64)
	if err != nil || r <= 0 || r > 1 {
		return def
	}
	return r
}

// parseHeaders converts "k1=v1,k2=v2" into a map for OTLP header injection.
func parseHeaders(value string) map[string]string {
	out := make(map[string]string)
	pairs := splitAndTrim(value, ",")
	for _, p := range pairs {
		kv := splitAndTrim(p, "=")
		if len(kv) == 2 {
			out[kv[0]] = kv[1]
		}
	}
	return out
}

func splitAndTrim(value, sep string) []string {
	raw := []string{}
	for _, part := range strings.Split(value, sep) {
		part = strings.TrimSpace(part)
		if part != "" {
			raw = append(raw, part)
		}
	}
	return raw
}
