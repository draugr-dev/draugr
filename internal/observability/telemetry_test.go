package observability

import (
	"context"
	"testing"
)

func TestInitTracingNoopWhenUnconfigured(t *testing.T) {
	// Ensure no OTLP endpoint is set for this test.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	shutdown, err := InitTracing(context.Background(), "draugr", "test")
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown should not be nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown should not error: %v", err)
	}
}

func TestInitMetricsNoopWhenUnconfigured(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")

	shutdown, err := InitMetrics(context.Background(), "draugr", "test")
	if err != nil {
		t.Fatalf("InitMetrics: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown should not error: %v", err)
	}
}

func TestInitTracingConfigured(t *testing.T) {
	// A configured endpoint builds a real provider. The gRPC exporter connects lazily,
	// so New succeeds and shutdown (with nothing recorded) returns promptly.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")

	shutdown, err := InitTracing(context.Background(), "draugr", "test")
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // bound shutdown so it can't block on a missing collector
	_ = shutdown(ctx)
}

func TestInitMetricsConfigured(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")

	shutdown, err := InitMetrics(context.Background(), "draugr", "test")
	if err != nil {
		t.Fatalf("InitMetrics: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = shutdown(ctx)
}
