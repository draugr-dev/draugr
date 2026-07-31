package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

type stubSurveyor struct {
	name string
	comp saga.Component
}

func (s stubSurveyor) Info() plugin.SurveyorInfo { return plugin.SurveyorInfo{Name: s.name} }
func (s stubSurveyor) Survey(context.Context, plugin.SurveyScope) (saga.Fragment, error) {
	return saga.Fragment{Components: []saga.Component{s.comp}}, nil
}

func stubRegistry() *surveyor.Registry {
	r := surveyor.NewRegistry()
	r.Register(stubSurveyor{name: "k8s-images", comp: saga.Component{
		Name: "cluster", Images: []saga.Image{{Image: "repo/x:1"}},
	}})
	r.Register(stubSurveyor{name: "github-org-repos", comp: saga.Component{
		Name: "svc", Repositories: []saga.Repository{{URL: "https://git/svc.git", Revision: "main"}},
	}})
	return r
}

// Selecting nothing is now impossible by construction: a surveyor is chosen by naming its
// subcommand, so `draugr survey` with no subcommand prints help rather than running an empty
// survey. What replaces this test is the retired-flag check below.
func TestSurveyWithNoSubcommandPrintsHelp(t *testing.T) {
	cmd := newSurveyCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Available Commands") {
		t.Errorf("want help listing the surveyors, got %q", out.String())
	}
}

func TestRunSurveyToStdout(t *testing.T) {
	var buf bytes.Buffer
	opts := surveyOptions{name: "app", version: "1.0"}
	if err := runSurvey(context.Background(), opts, []surveyor.Request{{Surveyor: "k8s-images"}}, stubRegistry(), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "cluster") || !strings.Contains(out, "repo/x:1") {
		t.Errorf("expected discovered component in output:\n%s", out)
	}
	// Output must be a loadable Saga.
	if _, err := saga.Load(buf.Bytes()); err != nil {
		t.Errorf("survey output is not a valid Saga: %v", err)
	}
}

func TestRunSurveyWritesFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	opts := surveyOptions{version: "1.0", output: out}
	if err := runSurvey(context.Background(), opts, []surveyor.Request{{Surveyor: "github-org-repos"}}, stubRegistry(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) //nolint:gosec // test reads a temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "svc") {
		t.Errorf("expected repo component in file:\n%s", data)
	}
}

func TestRunSurveyMerge(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	// Pre-existing Saga with a hand-written component.
	existing := "release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: existing\n"
	if err := os.WriteFile(out, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := surveyOptions{output: out, merge: true}
	if err := runSurvey(context.Background(), opts, []surveyor.Request{{Surveyor: "k8s-images"}}, stubRegistry(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out) //nolint:gosec // test reads a temp file
	s := string(data)
	if !strings.Contains(s, "existing") || !strings.Contains(s, "cluster") {
		t.Errorf("merged Saga should contain both components:\n%s", s)
	}
}

// Through the root command, `survey` with no surveyor now lists them rather than erroring:
// there is nothing to get wrong, because a surveyor is chosen by naming it.
func TestSurveyCommandViaCobraListsSurveyors(t *testing.T) {
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"survey"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{"k8s", "github"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help should list %q, got %q", want, out.String())
		}
	}
}

// The defect the rework fixes: `--github-org acme --k8s-namespace prod` used to run, apply the
// namespace to nothing, and say nothing. Leaving a retired flag to be ignored would have
// preserved exactly that.
func TestRetiredSurveyFlagsErrorWithTheirReplacement(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--k8s-images"}, "draugr survey k8s images"},
		{[]string{"--k8s-namespace", "prod"}, "--namespace"},
		{[]string{"--github-org", "acme"}, "draugr survey github repos"},
		// The combination that was silently wrong: it must fail, not run.
		{[]string{"--github-org", "acme", "--k8s-namespace", "prod"}, "replaced by a subcommand"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			cmd := newSurveyCommand()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatal("a retired flag must not be accepted in silence")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should point at the replacement %q, got: %v", tc.want, err)
			}
		})
	}
}

// Retired flags are answers to a question, not choices — offering them in --help would invite
// the usage being removed.
func TestRetiredSurveyFlagsAreHidden(t *testing.T) {
	t.Parallel()
	cmd := newSurveyCommand()
	for name := range retiredSurveyFlags {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("--%s must still parse, or the error naming its replacement never runs", name)
			continue
		}
		if !f.Hidden {
			t.Errorf("--%s should be hidden", name)
		}
	}
}

// Each surveyor's options belong to it. The whole point is that a k8s option cannot be handed to
// the GitHub surveyor and quietly ignored.
func TestSurveyorOptionsAreScopedToTheirSurveyor(t *testing.T) {
	t.Parallel()

	cmd := newSurveyCommand()
	var images, repos *cobra.Command
	for _, group := range cmd.Commands() {
		for _, sub := range group.Commands() {
			switch group.Name() + " " + sub.Name() {
			case "k8s images":
				images = sub
			case "github repos":
				repos = sub
			}
		}
	}
	if images == nil || repos == nil {
		t.Fatal("expected `k8s images` and `github repos`")
	}
	if images.Flags().Lookup("namespace") == nil {
		t.Error("--namespace belongs to k8s images")
	}
	if images.Flags().Lookup("org") != nil {
		t.Error("--org must not be reachable from k8s images")
	}
	if repos.Flags().Lookup("namespace") != nil {
		t.Error("--namespace must not be reachable from github repos — that was the original defect")
	}
	// Shared output settings stay shared.
	if repos.InheritedFlags().Lookup("output") == nil || repos.InheritedFlags().Lookup("merge") == nil {
		t.Error("--output and --merge apply to every surveyor")
	}
}

// --org is what the surveyor scopes to, so running without it would survey nothing and report
// success.
func TestSurveyGitHubReposRequiresAnOrg(t *testing.T) {
	t.Parallel()
	cmd := newSurveyCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"github", "repos"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--org") {
		t.Errorf("want an error naming --org, got: %v", err)
	}
}
