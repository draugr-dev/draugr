package engine

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Instrumentation uses the OpenTelemetry global providers, which are no-ops until the
// process installs real providers (see internal/observability). Attributes carry only
// non-sensitive identifiers (control, scanner, target kind, severity) — never secrets,
// config values, or target URLs.

const instrumentationScope = "github.com/draugr-dev/draugr/pkg/engine"

var (
	tracer = otel.Tracer(instrumentationScope)
	meter  = otel.Meter(instrumentationScope)

	scanCounter     metric.Int64Counter
	cacheHitCounter metric.Int64Counter
	findingCounter  metric.Int64Counter
	scanDuration    metric.Float64Histogram
)

func init() {
	scanCounter, _ = meter.Int64Counter("draugr.scans",
		metric.WithDescription("Number of scans executed"))
	cacheHitCounter, _ = meter.Int64Counter("draugr.cache.hits",
		metric.WithDescription("Number of cache hits"))
	findingCounter, _ = meter.Int64Counter("draugr.findings",
		metric.WithDescription("Number of findings by severity"))
	scanDuration, _ = meter.Float64Histogram("draugr.scan.duration.seconds",
		metric.WithDescription("Scan wall-clock duration in seconds"))
}

// recordFindings increments the findings counter per severity for a report.
func recordFindings(ctx context.Context, control string, report sarif.Report) {
	c := report.Counts()
	for sev, n := range map[string]int{
		"error":   c.Error,
		"warning": c.Warning,
		"note":    c.Note,
		"none":    c.None,
	} {
		if n > 0 {
			findingCounter.Add(ctx, int64(n), metric.WithAttributes(
				attribute.String("control", control),
				attribute.String("severity", sev),
			))
		}
	}
}
