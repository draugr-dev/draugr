package publish

import (
	"reflect"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// One table answers what each publisher reads, and everything that has to agree about it is derived
// from the table: the Saga schema's per-kind rules (internal/schemagen), the refusal `draugr
// validate` gives for a field the kind does not read (internal/cli), and the config a constructor is
// handed, which For trims to the declared fields so a publisher cannot read one the table omits.
//
// PublisherConfig is one struct shared by every kind, so the type system says nothing about which
// fields belong to which. Written out in several places, that knowledge drifts one copy at a time:
// a field the publisher ignores passes every reader, and a field the loader accepts is refused by
// the editor. Derived from here, a disagreement is a test failure in this package rather than a
// descriptor that misleads whoever wrote it.

// issueFields are the fields every issue publisher reads, deciding which part of the run each
// item covers and what it carries.
var issueFields = []string{
	"label", "branches", "select", "split", "minPriority", "children", "maxChildren", "labelBy", "item",
}

// reads names the descriptor fields each publisher reads, besides `kind`.
//
// TestEveryPublisherSaysWhatItReads holds it to the builders, and TestEveryFieldAPublisherReadsIsDeclared
// holds it to what the constructors do with a field.
var reads = map[string][]string{
	"file":              {"dir", "reports"},
	"github":            {"repo", "commit", "ref", "tokenEnv", "reports"},
	"github-pr-comment": {"repo", "pr", "marker", "tokenEnv", "reports"},
	"github-issue":      append([]string{"repo", "tokenEnv"}, issueFields...),
	"azure-pr-comment":  {"org", "project", "repo", "pr", "marker", "tokenEnv", "reports"},
	"azure-work-item":   append([]string{"org", "project", "tokenEnv"}, issueFields...),
	"gitlab-mr-comment": {"repo", "pr", "marker", "tokenEnv", "reports"},
	"gitlab-issue":      append([]string{"repo", "tokenEnv"}, issueFields...),
	"draugr-api":        {"url", "tokenEnv", "reports"},
}

// requires names the fields a publisher cannot run without, where no environment variable supplies
// a default. A directory has no default anybody could guess, and a directory given nothing to write
// delivers nothing.
var requires = map[string][]string{
	"file": {"dir", "reports"},
}

// accepts names the report formats each publisher delivers, nil for one that delivers any.
//
// A format outside the list is rendered and then dropped, because the publisher takes only the
// artifacts it can use. A pull-request comment posts one document, the markdown report or a
// template the descriptor supplies; code scanning takes SARIF.
var accepts = map[string][]string{
	"file":              nil,
	"github":            {"sarif"},
	"github-pr-comment": {"markdown", "template"},
	"github-issue":      {},
	"azure-pr-comment":  {"markdown", "template"},
	"azure-work-item":   {},
	"gitlab-mr-comment": {"markdown", "template"},
	"gitlab-issue":      {},
	"draugr-api":        {"json", "sarif"},
}

// Reads returns the descriptor fields kind reads besides `kind`, nil for a kind this build does not
// have.
func Reads(kind string) []string { return slices.Clone(reads[kind]) }

// Requires returns the fields kind cannot run without.
func Requires(kind string) []string { return slices.Clone(requires[kind]) }

// Accepts returns the report formats kind delivers, and whether it delivers only those. A kind that
// delivers any format returns nil and false.
func Accepts(kind string) ([]string, bool) {
	formats, ok := accepts[kind]
	return slices.Clone(formats), ok && formats != nil
}

// Unread returns the fields cfg writes that its kind does not read, in the order PublisherConfig
// declares them.
func Unread(cfg saga.PublisherConfig) []string {
	declared := reads[cfg.Kind]
	var out []string
	for _, key := range cfg.Written() {
		if key != "kind" && !slices.Contains(declared, key) {
			out = append(out, key)
		}
	}
	return out
}

// only returns cfg with every field its kind does not read set to zero.
//
// What a constructor is given, so a publisher reading a field the table leaves out reads nothing,
// and the field's absence from the table shows up as the publisher not working rather than as a
// descriptor every reader accepts and nothing checks.
func only(cfg saga.PublisherConfig) saga.PublisherConfig {
	declared := reads[cfg.Kind]
	v := reflect.ValueOf(&cfg).Elem()
	t := v.Type()
	for i := range t.NumField() {
		key, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		// "-" is carried for the publisher rather than written in a descriptor: the server address
		// draugr.config.yaml supplies.
		if key == "kind" || key == "-" || slices.Contains(declared, key) {
			continue
		}
		v.Field(i).SetZero()
	}
	return cfg
}
