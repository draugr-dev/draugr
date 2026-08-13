// Package publish delivers rendered reports (report.Artifact) to destinations. A Publisher is
// the "where" of reporting — separate from the Reporter (the "what", pkg/report) — so a scan
// can render several formats once and deliver them to several destinations.
//
// Each publisher is configured from a saga.PublisherConfig and named by its kind; Kinds lists
// the built-in set.
package publish

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// skipPublisher is a no-op Publisher: a configured publisher that has nothing to do in the
// current environment (e.g. a github publisher run outside CI). It logs why and delivers nothing.
type skipPublisher struct{ kind, reason string }

func (p skipPublisher) Kind() string { return p.kind }
func (p skipPublisher) Publish(context.Context, []report.Artifact) error {
	slog.Info("publisher skipped", "kind", p.kind, "reason", p.reason)
	return nil
}

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
	"file":              newFilePublisher,
	"github":            newGithubPublisher,
	"github-pr-comment": newGithubPRCommentPublisher,
	"azure-pr-comment":  newAzurePRCommentPublisher,
	"gitlab-mr-comment": newGitLabMRCommentPublisher,
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

	// A publisher delivers the record, so it gets the whole record. --min-priority narrows what
	// this invocation shows you; it must not narrow what is filed.
	//
	// This matters most for code scanning, where GitHub resolves any alert absent from an upload
	// as fixed — so publishing a filtered report would quietly close real findings, and the
	// filtering would be invisible in the place it did the damage. Said out loud rather than
	// dropped silently, because a flag that does nothing is the thing this exists to prevent.
	if data.MinPriority != "" {
		slog.Info("publishers ignore --min-priority",
			"reason", "an upload missing findings resolves them as fixed",
			"minPriority", data.MinPriority)
		data.MinPriority = ""
	}

	artifacts := make([]report.Artifact, 0, len(reports))
	for _, r := range reports {
		a, err := report.Build(r, data)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, a)
	}
	// SBOMs are already rendered by the time a run finishes, so they are appended rather than
	// built from data. That is also why "sbom" is not a --format: a run produces one document
	// per target, and a format that writes N files has no sensible meaning on stdout.
	artifacts = append(artifacts, report.SBOMArtifacts(data.Run.SBOMs)...)

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

// DiffMarker identifies the sticky comment `draugr diff --publish` maintains.
//
// Exported so the diff command asks for it by name rather than restating the string. It is
// deliberately not the marker a Saga's PR-comment publisher uses: a run that posts both a report
// and a delta wants two comments, not one that overwrites the other.
const DiffMarker = defaultDiffPRMarker

// ReportMarker identifies the sticky comment a Saga's PR-comment publisher maintains.
const ReportMarker = defaultPRMarker
