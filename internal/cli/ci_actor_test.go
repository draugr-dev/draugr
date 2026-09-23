package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// The descriptor decides whether email addresses are read: absent or false reads none, and
// recordEmail reads what the platform reports.
func TestTheDescriptorDecidesWhetherEmailIsRead(t *testing.T) {
	for _, k := range []string{"GITHUB_ACTIONS", "GITHUB_RUN_ID", "TF_BUILD", "BUILD_BUILDID",
		"CIRCLECI", "CIRCLE_WORKFLOW_ID", "BUILDKITE", "BUILDKITE_BUILD_ID"} {
		t.Setenv(k, "")
	}
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("GITLAB_USER_LOGIN", "bo")
	t.Setenv("GITLAB_USER_EMAIL", "bo@example.com")

	for name, cfg := range map[string]*saga.CIConfig{"absent": nil, "false": {RecordEmail: false}} {
		c := detectedCI(cfg)
		if c == nil || c.RunBy == nil || c.RunBy.Handle != "bo" {
			t.Fatalf("%s: runBy = %+v", name, c)
		}
		if c.RunBy.Email != "" {
			t.Errorf("%s: read an email the descriptor did not ask for", name)
		}
	}
	if c := detectedCI(&saga.CIConfig{RecordEmail: true}); c == nil || c.RunBy.Email != "bo@example.com" {
		t.Errorf("recordEmail: runBy = %+v", c)
	}

	t.Setenv("GITLAB_CI", "")
	t.Setenv("CI_JOB_ID", "")
	if c := detectedCI(nil); c != nil {
		t.Errorf("outside CI: %+v", c)
	}
}

// The report.json -o writes records what produced the run, the same as the --format json document
// a publisher sends: the CI job, its actors, the descriptor and the feeds.
func TestTheArtifactRecordsWhatProducedTheRun(t *testing.T) {
	dir := t.TempDir()
	data := report.Data{
		Release:        saga.Release{Version: "1"},
		CI:             &ci.Context{System: "gitlab-ci", RunID: "991", RunBy: &ci.Actor{Handle: "bo", ID: "7"}},
		Descriptor:     &skald.DescriptorRef{Digest: "sha256:abc"},
		Exploitability: []report.FeedProvenance{{Name: "kev", SHA256: "def"}},
	}
	if err := writeArtifacts(dir, []string{"json"}, data, saga.Release{Version: "1"},
		engine.Result{}, norn.Result{Verdict: norn.Pass}, "", ""); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"runBy"`, `"handle": "bo"`, `"descriptor"`, `"sha256:abc"`, `"kev"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("report.json lacks %s:\n%s", want, body)
		}
	}
}
