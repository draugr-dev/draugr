// Package publish delivers rendered reports (report.Artifact) to destinations. A Publisher is
// the "where" of reporting, separate from the Reporter (the "what", pkg/report). So a scan can
// render several formats once and deliver them to several destinations.
//
// Each publisher is configured from a saga.PublisherConfig and named by its kind; Kinds lists
// the built-in set.
package publish

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

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
	"draugr-api":        newDraugrAPIPublisher,
}

// For resolves a configured publisher, validating its kind and required fields.
func For(cfg saga.PublisherConfig) (Publisher, error) {
	build, ok := builders[cfg.Kind]
	if !ok {
		return nil, fmt.Errorf("unknown publisher kind %q (available: %v)", cfg.Kind, Kinds())
	}
	return build(cfg)
}

// rendered names the report formats a publisher produces for itself.
//
// A destination that can only deliver one thing knows what that thing is. Asking an author to
// declare it as well is boilerplate that can only be got wrong: the publisher cannot work without
// it, nothing else decides it, and a descriptor that omits it is a descriptor that does not run.
// So `kind: draugr-api` is a complete destination, and the formats it posts are its business.
//
// `file` is the exception and the reason the list has an empty entry rather than no entry: a
// directory has no inherent format, so what goes in it is the author's choice and has to be
// written down.
//
// TestEveryPublisherSaysWhatItRenders holds this to the builders, so a publisher added without an
// entry fails rather than silently rendering nothing.
var rendered = map[string][]string{
	// Writes whatever it is handed, and has no format of its own.
	"file":              nil,
	"github":            {"sarif"},
	"github-pr-comment": {"markdown"},
	"azure-pr-comment":  {"markdown"},
	"gitlab-mr-comment": {"markdown"},
	// The report carries the verdict and the findings carry the evidence, and the plane stores
	// both, so neither alone is a run it can show anybody.
	"draugr-api": {"json", "sarif"},
}

// Renders returns the formats kind produces for itself, nil for a kind with none and for one this
// build does not have.
func Renders(kind string) []string { return rendered[kind] }

// distinguishes names the field that makes a second entry of a kind a second destination.
//
// A list of publishers can hold one kind twice on purpose: two directories, two servers, two
// comments under different markers. It can also hold one kind twice by mistake, and the two are
// written identically. The field named here is what tells them apart, so a descriptor can be
// refused when it does not differ in the one place that would make a difference.
//
// TestEveryPublisherSaysWhatDistinguishesIt holds this to the builders, so a publisher added
// without an entry fails rather than quietly getting no check.
var distinguishes = map[string]string{
	"file":              "dir",
	"github":            "repo",
	"github-pr-comment": "marker",
	"azure-pr-comment":  "marker",
	"gitlab-mr-comment": "marker",
	"draugr-api":        "url",
}

// Distinguishes returns the field that makes a second entry of kind a second destination, empty
// for a kind this build does not have.
func Distinguishes(kind string) string { return distinguishes[kind] }

// DistinguishingValue returns what cfg wrote in the field that tells two entries of its kind
// apart.
//
// What the descriptor wrote, not what it resolves to. `repo`, `pr` and `url` all default from the
// environment, so two entries that write nothing are the same entry twice however they resolve,
// and that is the case worth catching.
func DistinguishingValue(cfg saga.PublisherConfig) string {
	switch distinguishes[cfg.Kind] {
	case "dir":
		return cfg.Dir
	case "repo":
		return cfg.Repo
	case "marker":
		return cfg.Marker
	case "url":
		return cfg.URL
	}
	return ""
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
func Run(ctx context.Context, publishers []saga.PublisherConfig, data report.Data) error {
	if len(publishers) == 0 {
		return nil
	}

	// A publisher delivers the record, so it gets the whole record. --min-priority narrows what
	// this invocation shows you; it must not narrow what is filed.
	//
	// This matters most for code scanning, where GitHub resolves any alert absent from an upload as
	// fixed, so publishing a filtered report would quietly close real findings, and the filtering
	// would be invisible in the place it did the damage. Said out loud rather than dropped silently,
	// because a flag that does nothing is the thing this exists to prevent.
	if data.MinPriority != "" {
		slog.Info("publishers ignore --min-priority",
			"reason", "an upload missing findings resolves them as fixed",
			"minPriority", data.MinPriority)
		data.MinPriority = ""
	}

	// Build what can be built and deliver it, rather than returning on the first format that fails.
	// One unrenderable format used to cost every report from the run, a scan that took four minutes
	// produced nothing, because of something a descriptor check catches in milliseconds. The
	// publisher loop below has always tolerated one destination failing; this is the same reasoning
	// applied one step earlier.
	//
	// Rendered once per distinct report, however many destinations ask for it. Two publishers
	// wanting markdown is one document delivered twice, not one rendered twice, which is what
	// separating the "what" from the "where" is worth keeping internally even now that the
	// descriptor states them together.
	built := map[string]report.Artifact{}
	var buildErrs []error
	render := func(r saga.ReportConfig) (report.Artifact, bool) {
		id := reportKey(r)
		if a, done := built[id]; done {
			return a, a.Format != ""
		}
		a, err := report.Build(r, data)
		if err != nil {
			buildErrs = append(buildErrs, err)
			built[id] = report.Artifact{} // remembered, so one bad format is reported once
			return report.Artifact{}, false
		}
		built[id] = a
		return a, true
	}

	// SBOMs are already rendered by the time a run finishes, so they are appended rather than
	// built from data. That is also why "sbom" is not a --format: a run produces one document
	// per target, and a format that writes N files has no sensible meaning on stdout.
	sboms := report.SBOMArtifacts(data.Run.SBOMs)

	// A destination that fails does not stop the others, and a format that will not render does
	// not stop the destinations that wanted something else. Both are collected and reported
	// together at the end, because a scan that took four minutes and produced nothing, over
	// something a descriptor check catches in milliseconds, is the worse outcome.
	var failures []error
	for _, cfg := range publishers {
		p, err := For(cfg)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		// What this destination produces for itself, then whatever the descriptor added. A kind
		// that can only deliver one thing knows what it is, so a descriptor naming it as well
		// would be saying something the publisher already knows and could only get wrong.
		want := make([]saga.ReportConfig, 0, len(cfg.Reports)+2)
		for _, f := range rendered[cfg.Kind] {
			want = append(want, saga.ReportConfig{Format: f})
		}
		want = append(want, cfg.Reports...)

		deliver := make([]report.Artifact, 0, len(want)+len(sboms))
		seen := map[string]bool{}
		for _, r := range want {
			// A descriptor naming a format the publisher already renders is narrowing it, so the
			// descriptor's entry wins and the implicit one is dropped rather than delivered twice.
			if r.Format != "" && seen[r.Format] && r.MinPriority == "" && r.Filename == "" {
				continue
			}
			a, ok := render(r)
			if !ok {
				continue
			}
			seen[r.Format] = true
			deliver = append(deliver, a)
		}
		// The SBOMs are the run's own documents rather than a rendered format, so they follow
		// whoever is taking files. Only the file publisher writes them, and it ignores what it
		// cannot use.
		deliver = append(deliver, sboms...)
		if err := p.Publish(ctx, deliver); err != nil {
			failures = append(failures, fmt.Errorf("publisher %q: %w", cfg.Kind, err))
		}
	}
	// Rendering failures first: a destination that delivered nothing usually did so because the
	// thing it was to deliver could not be built, and naming the delivery ahead of the cause sends
	// a reader to the wrong half.
	return errors.Join(append(buildErrs, failures...)...)
}

// reportKey identifies a report by everything that changes what it renders, so two destinations
// asking for the same document share one render and two asking for different ones do not.
func reportKey(r saga.ReportConfig) string {
	return strings.Join([]string{r.Format, r.Template, r.TemplateFile, r.MinPriority, r.Filename}, "\x00")
}

// DiffMarker identifies the sticky comment `draugr diff --publish` maintains.
//
// Exported so the diff command asks for it by name rather than restating the string. It is
// deliberately not the marker a Saga's PR-comment publisher uses: a run that posts both a report
// and a delta wants two comments, not one that overwrites the other.
const DiffMarker = defaultDiffPRMarker

// ReportMarker identifies the sticky comment a Saga's PR-comment publisher maintains.
const ReportMarker = defaultPRMarker
