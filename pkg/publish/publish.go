// Package publish delivers rendered reports (report.Artifact) to destinations. A Publisher is
// the "where" of reporting — separate from the Reporter (the "what", pkg/report) — so a scan
// can render several formats once and deliver them to several destinations.
//
// Built-in publishers: file. Each publisher is configured from a saga.PublisherConfig.
package publish

import (
	"context"
	"fmt"
	"sort"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Publisher delivers rendered report artifacts to one destination.
type Publisher interface {
	// Kind is the publisher's config selector, e.g. "file".
	Kind() string
	// Publish delivers the artifacts. A publisher may use only the artifacts it cares about
	// (e.g. a code-scanning publisher would take the SARIF one), ignoring the rest.
	Publish(ctx context.Context, artifacts []report.Artifact) error
}

// builders maps a config kind to a constructor that validates the config and returns a
// Publisher. Registering here keeps the set of built-in publishers in one place.
var builders = map[string]func(saga.PublisherConfig) (Publisher, error){
	"file":   newFilePublisher,
	"github": newGithubPublisher,
}

// For resolves a configured publisher, validating its kind and required fields.
func For(cfg saga.PublisherConfig) (Publisher, error) {
	build, ok := builders[cfg.Kind]
	if !ok {
		return nil, fmt.Errorf("unknown publisher kind %q (available: %v)", cfg.Kind, Kinds())
	}
	return build(cfg)
}

// Kinds lists the available publisher kinds, sorted.
func Kinds() []string {
	out := make([]string, 0, len(builders))
	for k := range builders {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Run renders each configured report format once, then delivers every rendered artifact to
// every configured publisher. It returns the first error encountered; a publisher that fails
// does not prevent the others from being attempted.
func Run(ctx context.Context, reports []saga.ReportConfig, publishers []saga.PublisherConfig, data report.Data) error {
	if len(publishers) == 0 {
		return nil
	}

	artifacts := make([]report.Artifact, 0, len(reports))
	for _, r := range reports {
		a, err := report.Build(r, data)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, a)
	}

	var firstErr error
	for _, cfg := range publishers {
		p, err := For(cfg)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := p.Publish(ctx, artifacts); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("publisher %q: %w", cfg.Kind, err)
			}
		}
	}
	return firstErr
}
