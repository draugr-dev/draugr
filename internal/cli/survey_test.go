package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
// survey.
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
	opts := surveyOptions{output: out}
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
	for _, want := range []string{"k8s", "github", "gitlab", "azure"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help should list %q, got %q", want, out.String())
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
		t.Error("--namespace must not be reachable from github repos — a flag accepted where it means nothing does nothing, silently")
	}
	// Shared output settings stay shared.
	if repos.InheritedFlags().Lookup("output") == nil || repos.InheritedFlags().Lookup("replace") == nil {
		t.Error("--output and --replace apply to every surveyor")
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

// --org is what the surveyor scopes to; --project narrows it. Running without --org would survey
// nothing and report success.
func TestSurveyAzureReposRequiresAnOrg(t *testing.T) {
	t.Parallel()
	cmd := newSurveyCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"azure", "repos"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--org") {
		t.Errorf("want an error naming --org, got: %v", err)
	}
}

// An omitted --project has to mean "the whole organization", not "a project with no name": the
// second builds a URL with a trailing slash and asks Azure DevOps for something else.
func TestAzureScopeRef(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, org, project, want string }{
		{"organization only", "acme", "", "acme"},
		{"organization and project", "acme", "Platform", "acme/Platform"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := azureScopeRef(tc.org, tc.project); got != tc.want {
				t.Errorf("azureScopeRef(%q, %q) = %q, want %q", tc.org, tc.project, got, tc.want)
			}
		})
	}
}

// Each surveyor's options belong to it, and --project is meaningless anywhere but here.
func TestSurveyAzureOptionsAreScopedToTheSubcommand(t *testing.T) {
	t.Parallel()
	var azure *cobra.Command
	for _, group := range newSurveyCommand().Commands() {
		if group.Name() == "azure" {
			azure = group
		}
	}
	if azure == nil {
		t.Fatal("expected an `azure` group")
	}
	if azure.Flags().Lookup("org") != nil {
		t.Error("--org belongs to `azure repos`, not to the group")
	}
	repos := azure.Commands()[0]
	for _, flag := range []string{"org", "project"} {
		if repos.Flags().Lookup(flag) == nil {
			t.Errorf("--%s belongs to `azure repos`", flag)
		}
	}
	if repos.Flags().Lookup("group") != nil {
		t.Error("--group is GitLab's and must not be reachable here — a flag accepted where it means nothing does nothing, silently")
	}
	if repos.InheritedFlags().Lookup("output") == nil {
		t.Error("--output applies to every surveyor")
	}
}

// --context says which cluster, so it belongs to the group rather than to one surveyor:
// otherwise surveying one cluster two ways means setting it twice, and getting it wrong once
// means two components describing different clusters under one name.
func TestSurveyK8sGroupSharesTheContextFlag(t *testing.T) {
	t.Parallel()

	var k8s *cobra.Command
	for _, c := range newSurveyCommand().Commands() {
		if c.Name() == "k8s" {
			k8s = c
		}
	}
	if k8s == nil {
		t.Fatal("expected a k8s group")
	}
	if k8s.PersistentFlags().Lookup("context") == nil {
		t.Error("--context should be shared by every k8s surveyor")
	}

	subs := map[string]*cobra.Command{}
	for _, c := range k8s.Commands() {
		subs[c.Name()] = c
	}
	for _, want := range []string{"images", "cluster"} {
		sub, ok := subs[want]
		if !ok {
			t.Errorf("expected `k8s %s`", want)
			continue
		}
		if sub.InheritedFlags().Lookup("context") == nil {
			t.Errorf("`k8s %s` should inherit --context", want)
		}
		// Both take --namespace, but they mean different things: for images it narrows what is
		// listed, for cluster it declares what the component owns.
		if sub.Flags().Lookup("namespace") == nil {
			t.Errorf("`k8s %s` should take --namespace", want)
		}
	}
}

// The surveyor a subcommand runs is the one its name promises — the whole point of splitting
// k8s-cluster out of k8s-images.
func TestSurveyK8sClusterRunsTheClusterSurveyor(t *testing.T) {
	t.Parallel()

	reg := surveyor.NewRegistry()
	var got []surveyor.Request
	reg.Register(stubSurveyor{name: "k8s-cluster", comp: saga.Component{
		Name:           "prod",
		Infrastructure: []saga.Infrastructure{{Kind: "kubernetes", Ref: "prod"}},
	}})

	var buf bytes.Buffer
	got = []surveyor.Request{{Surveyor: "k8s-cluster", Scope: plugin.SurveyScope{Ref: "team-a"}}}
	if err := runSurvey(context.Background(), surveyOptions{version: "1.0"}, got, reg, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "infrastructure") || !strings.Contains(out, "kubernetes") {
		t.Errorf("expected an infrastructure component:\n%s", out)
	}
	if strings.Contains(out, "images:") {
		t.Error("the cluster surveyor must not emit images — that is the other surveyor's job")
	}
}

// A surveyor that cannot reach its source must fail, not write an empty descriptor. An empty
// Saga is the worst outcome: it looks like a successful survey of an application with nothing
// in it, and the next scan passes for the same reason.
func TestSurveyFailsWhenTheSourceIsUnreachable(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"k8s images", []string{"k8s", "images"}},
		{"k8s cluster", []string{"k8s", "cluster"}},
		{"k8s cluster scoped", []string{"k8s", "cluster", "--namespace", "team-a", "--context", "nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A kubeconfig that does not exist, so the outcome does not depend on whatever
			// cluster the machine running the tests happens to be pointed at.
			t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent.yaml"))

			cmd := newSurveyCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil {
				t.Fatalf("want an error rather than an empty Saga; wrote %q", out.String())
			}
		})
	}
}

// The end the feature exists for: a descriptor produced entirely by discovery scans something.
func TestSurveyOutputIsScannable(t *testing.T) {
	t.Parallel()

	reg := surveyor.NewRegistry()
	reg.Register(stubSurveyor{name: "k8s-cluster", comp: saga.Component{
		Name:           "prod",
		Infrastructure: []saga.Infrastructure{{Kind: "kubernetes", Ref: "prod"}},
	}})

	var buf bytes.Buffer
	err := runSurvey(context.Background(), surveyOptions{version: "1.0"},
		[]surveyor.Request{{Surveyor: "k8s-cluster"}}, reg, &buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := saga.Load(buf.Bytes())
	if err != nil {
		t.Fatalf("survey output is not a valid Saga: %v", err)
	}
	if !m.Config.ControllerEnabled("infrastructure") {
		t.Errorf("a surveyed cluster should be scannable without hand-editing:\n%s", buf.String())
	}
}

func TestSurveySummaryDescribesTheArtifact(t *testing.T) {
	// The command's whole purpose is to write a file, so it has to name it, count what it
	// found, and say where it went. Without that, silence and failure look identical.
	model := saga.Model{Components: []saga.Component{
		{Name: "web", Repositories: []saga.Repository{{URL: "https://git/a"}}, Hosts: []saga.Host{{URL: "https://a"}}},
		{Name: "api", Repositories: []saga.Repository{{URL: "https://git/b"}}},
	}}
	got := surveySummary(surveyOptions{output: ".saga.yaml"}, saga.Fragment{}, model.Components, false)
	want := "wrote .saga.yaml — 2 components, 2 repositories, 1 host"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestSurveySummarySaysWhatAMergeAdded(t *testing.T) {
	// After a merge the total says little on its own — the reader wants to know what this run
	// contributed, which is otherwise answered by diffing the file.
	model := saga.Model{Components: []saga.Component{{Name: "a"}, {Name: "b"}, {Name: "c"}}}
	frag := saga.Fragment{Components: []saga.Component{{Name: "c"}}}
	got := surveySummary(surveyOptions{output: "s.yaml"}, frag, model.Components, true)
	if !strings.Contains(got, "merged into s.yaml") || !strings.Contains(got, "this survey found 1 component") {
		t.Errorf("got %q", got)
	}
}

func TestSurveySummaryCallsOutADescriptorThatScansNothing(t *testing.T) {
	// A survey that discovered nothing writes a valid file that checks nothing, and the count
	// alone reads as success.
	got := surveySummary(surveyOptions{output: "s.yaml"}, saga.Fragment{}, nil, false)
	if !strings.Contains(got, "nothing was discovered") {
		t.Errorf("an empty descriptor must say so: %q", got)
	}
}

func TestPluralHandlesTheNounsWeUse(t *testing.T) {
	cases := map[string]string{
		"1 component":    plural(1, "component"),
		"2 components":   plural(2, "component"),
		"1 repository":   plural(1, "repository"),
		"3 repositories": plural(3, "repository"),
		"0 hosts":        plural(0, "host"),
	}
	for want, got := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestPlural(t *testing.T) {
	cases := []struct {
		n    int
		noun string
		want string
	}{
		{1, "component", "1 component"},
		{2, "component", "2 components"},
		{3, "repository", "3 repositories"},
		{4, "day", "4 days"}, // vowel before the y: not "daies"
		{2, "key", "2 keys"},
		{0, "tool", "0 tools"},
	}
	for _, c := range cases {
		if got := plural(c.n, c.noun); got != c.want {
			t.Errorf("plural(%d, %q) = %q, want %q", c.n, c.noun, got, c.want)
		}
	}
}

func TestRequestPerNamespaceMakesOneRequestEach(t *testing.T) {
	t.Parallel()
	// Two, not one. A surveyor scoped to a namespace names its component after it and proposes
	// an exposure from its topology; with one namespace any implementation looks right, and with
	// two an implementation that collapses them into a single scope silently keeps one.
	scopeFor := func(ref string) plugin.SurveyScope {
		return plugin.SurveyScope{Ref: ref, Config: plugin.Config{"context": "prod"}}
	}
	got := requestPerNamespace("k8s-images", []string{"payments", "checkout"}, scopeFor)
	if len(got) != 2 {
		t.Fatalf("got %d requests, want one per namespace: %+v", len(got), got)
	}
	for i, want := range []string{"payments", "checkout"} {
		if got[i].Scope.Ref != want {
			t.Errorf("request %d scoped to %q, want %q", i, got[i].Scope.Ref, want)
		}
		if got[i].Surveyor != "k8s-images" {
			t.Errorf("request %d ran %q", i, got[i].Surveyor)
		}
		// --context says which cluster, so it has to reach every request rather than the first.
		if got[i].Scope.Config["context"] != "prod" {
			t.Errorf("request %d lost the kube context: %+v", i, got[i].Scope.Config)
		}
	}
}

func TestRequestPerNamespaceDefaultsToTheWholeCluster(t *testing.T) {
	t.Parallel()
	// No namespace has always meant the whole cluster, and still does — one request with an
	// empty ref, which is what the surveyor reads as "every namespace".
	got := requestPerNamespace("k8s-cluster", nil, func(ref string) plugin.SurveyScope {
		return plugin.SurveyScope{Ref: ref}
	})
	if len(got) != 1 || got[0].Scope.Ref != "" {
		t.Fatalf("want a single whole-cluster request, got %+v", got)
	}
}

func TestSurveyNamespaceFlagTakesSeveral(t *testing.T) {
	t.Parallel()
	// The descriptor's `infrastructure.namespaces` is a list, so discovery that could only
	// express one left a user who owns three unable to survey what they can describe.
	cmd := newSurveyCommand()
	for _, path := range [][]string{{"k8s", "images"}, {"k8s", "cluster"}} {
		sub, _, err := cmd.Find(path)
		if err != nil {
			t.Fatalf("%v: %v", path, err)
		}
		f := sub.Flags().Lookup("namespace")
		if f == nil {
			t.Fatalf("%v has no --namespace", path)
		}
		if f.Value.Type() != "stringSlice" {
			t.Errorf("%v --namespace is %s, want a repeatable list", path, f.Value.Type())
		}
	}
}

// Merging keeps the wider scope, which is safe and also surprising: --namespace was accepted, the
// survey ran, and the descriptor still covers the whole cluster. Somebody who narrowed on purpose
// has to be told their flag did not reach the file, or they will believe the next scan is scoped.
func TestSurveySaysWhenANamespaceScopeWasNotApplied(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(out, []byte(
		"release:\n  name: app\n  version: \"1.0\"\n"+
			"components:\n  - name: prod\n    infrastructure:\n      - kind: kubernetes\n        ref: prod\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := surveyor.NewRegistry()
	reg.Register(stubSurveyor{name: "k8s-cluster", comp: saga.Component{
		Name: "prod",
		Infrastructure: []saga.Infrastructure{{
			Kind: "kubernetes", Ref: "prod", Namespaces: []string{"team-a"},
		}},
	}})

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	err := runSurvey(context.Background(), surveyOptions{version: "1.0", output: out},
		[]surveyor.Request{{Surveyor: "k8s-cluster", Scope: plugin.SurveyScope{Ref: "team-a"}}},
		reg, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(logs.String(), "--namespace not applied") {
		t.Errorf("the dropped scope was not reported:\n%s", logs.String())
	}
	written, err := os.ReadFile(out) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatal(err)
	}
	// The warning describes what happened; the file has to match it.
	if strings.Contains(string(written), "team-a") {
		t.Errorf("the descriptor was narrowed after all:\n%s", written)
	}
}

// A descriptor carries decisions a survey cannot rediscover — exposure, criticality, exclusions,
// controls somebody chose. Overwriting it has to be asked for, because the failure is a file you
// reconstruct from memory and the success looks identical at the moment it happens.
func TestSurveyAddsToAnExistingDescriptorUnlessToldOtherwise(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(existing, []byte("release:\n  name: app\n  version: \"1.0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "new.saga.yaml")

	cases := []struct {
		name string
		opts surveyOptions
		want bool
	}{
		{"an existing file is added to", surveyOptions{output: existing}, true},
		{"--replace starts again", surveyOptions{output: existing, replace: true}, false},
		{"a file that does not exist is created", surveyOptions{output: absent}, false},
		{"stdout has nothing to merge into", surveyOptions{}, false},
	}
	for _, c := range cases {
		if got := c.opts.mergesInto(); got != c.want {
			t.Errorf("%s: mergesInto() = %v, want %v", c.name, got, c.want)
		}
	}
}

// The verb has to follow what actually happened, or the summary describes a different run from
// the one that wrote the file.
func TestSurveySummaryVerbFollowsWhatHappened(t *testing.T) {
	model := saga.Model{Components: []saga.Component{{Name: "a"}}}
	if got := surveySummary(surveyOptions{output: "s.yaml", replace: true}, saga.Fragment{}, model.Components, false); !strings.Contains(got, "wrote s.yaml") {
		t.Errorf("--replace should say it wrote: %q", got)
	}
}

// A proposal that arrives silently is indistinguishable from a decision once it is in the file,
// and exposure is what turns a severity into a P1 or a P3.
func TestSurveyNamesTheExposuresItProposed(t *testing.T) {
	proposed := saga.Component{Name: "payments", Exposure: saga.Unstated(saga.ExposurePublic)}
	for _, tc := range []struct {
		name     string
		existing string
		frag     saga.Component
		want     []string
		silent   bool
	}{
		{
			name: "a new component",
			frag: proposed,
			want: []string{"payments", "public", "draugr classify"},
		},
		{
			// The merge keeps the exposure already in the descriptor, so this proposal was
			// discarded. Naming it would ask someone to confirm a value that is not in their file.
			name:     "a component somebody has already classified",
			existing: "components:\n  - name: payments\n    exposure:\n      value: restricted\n",
			frag:     proposed,
			silent:   true,
		},
		{
			name:   "a surveyor that proposes nothing",
			frag:   saga.Component{Name: "payments", Images: []saga.Image{{Image: "repo/x:1"}}},
			silent: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "draugr.saga.yaml")
			body := "release:\n  name: app\n  version: \"1.0\"\n" + tc.existing
			if err := os.WriteFile(out, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}

			reg := surveyor.NewRegistry()
			reg.Register(stubSurveyor{name: "k8s-images", comp: tc.frag})

			stderr := captureStderr(t)
			err := runSurvey(context.Background(), surveyOptions{version: "1.0", output: out},
				[]surveyor.Request{{Surveyor: "k8s-images"}}, reg, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			got := stderr()

			if tc.silent {
				if strings.Contains(got, "exposure proposed") {
					t.Errorf("nothing was proposed into the file:\n%s", got)
				}
				return
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("the note should mention %q:\n%s", want, got)
				}
			}
		})
	}
}

// The reader's next action is per component — confirming or correcting each one — so a count
// would tell them only that there is something to open the file for.
func TestProposedExposureNoteNamesEachComponent(t *testing.T) {
	t.Parallel()
	note := proposedExposureNote([]exposureProposal{
		{component: "payments", exposure: saga.ExposurePublic},
		{component: "a", exposure: saga.ExposureInternal},
	})
	for _, want := range []string{"payments  public", "a         internal"} {
		if !strings.Contains(note, want) {
			t.Errorf("want %q, aligned, in:\n%s", want, note)
		}
	}
	if proposedExposureNote(nil) != "" {
		t.Error("no proposals should print nothing at all")
	}
}

// captureStderr redirects os.Stderr for the duration of a test, returning a reader for what was
// written. A survey writes its notes there deliberately, so that a descriptor sent to stdout stays
// a descriptor — which means stdout is the one place these messages cannot be checked.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prior := os.Stderr
	os.Stderr = w
	var once sync.Once
	var out string
	read := func() string {
		once.Do(func() {
			os.Stderr = prior
			_ = w.Close()
			b, _ := io.ReadAll(r)
			_ = r.Close()
			out = string(b)
		})
		return out
	}
	t.Cleanup(func() { read() })
	return read
}

// A descriptor a survey wrote must survive `draugr classify` without being reformatted.
//
// Several commands write the same file: a survey creates it, classify sets exposure and
// criticality in place, `validate --resolved` prints it merged. Each one that picks its own indent
// reindents the whole document as a side effect of changing two fields — and a two-field edit that
// rewrites every line is a diff nobody reviews, so the one real change goes through unread.
//
// yaml.Marshal's default is four spaces, which is not a decision anybody made. Everything that
// writes a Saga now shares saga.Indent, and this is what notices if one stops.
func TestASurveyedDescriptorSurvivesClassifyUnreformatted(t *testing.T) {
	model := saga.Model{
		Release: saga.Release{Name: "app", Version: "1"},
		Components: []saga.Component{
			{Name: "front", Images: []saga.Image{{Image: "repo/a:1"}}},
			{Name: "back", Images: []saga.Image{{Image: "repo/b:1"}}},
		},
	}
	written, err := saga.Marshal(&model)
	if err != nil {
		t.Fatalf("saga.Marshal: %v", err)
	}
	classified, _, err := saga.WriteClassifications(written, map[string]saga.Classification{
		"front": {Exposure: saga.ExposurePublic, Criticality: saga.CriticalityCritical},
	})
	if err != nil {
		t.Fatalf("WriteClassifications: %v", err)
	}

	// Every line the survey wrote still appears verbatim. Setting two fields adds lines; it must
	// not rewrite the ones it did not touch.
	after := string(classified)
	for _, line := range strings.Split(strings.TrimRight(string(written), "\n"), "\n") {
		if !strings.Contains(after, line+"\n") {
			t.Fatalf("classify reformatted a line it did not change:\n  survey wrote: %q\n  result:\n%s",
				line, after)
		}
	}
}

// --fragment writes components and nothing else.
//
// A fragment is part of a descriptor rather than a thing to release, so it carries no `release:`;
// and FragmentConfig deliberately cannot express `controllers`, so it enables nothing — the
// descriptor that includes it decides what to run. Both absences are the point of the option, and
// both are what a reader would otherwise have to infer from a file that looks unfinished.
func TestSurveyFragmentWritesComponentsAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "team.saga-fragment.yaml")
	opts := surveyOptions{output: out, fragment: true}
	frag := saga.Fragment{Components: []saga.Component{
		{Name: "team-a", Images: []saga.Image{{Image: "repo/a:1"}}, Exposure: saga.Unstated(saga.ExposureInternal)},
	}}
	if err := surveyIntoFragment(opts, frag, io.Discard); err != nil {
		t.Fatalf("surveyIntoFragment: %v", err)
	}
	data, err := os.ReadFile(out) //#nosec G304 -- a path this test just created under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, absent := range []string{"release:", "controllers:"} {
		if strings.Contains(got, absent) {
			t.Errorf("a fragment must not carry %q:\n%s", absent, got)
		}
	}
	if !strings.Contains(got, "name: team-a") {
		t.Errorf("the surveyed component is missing:\n%s", got)
	}
	// And it has to be readable as what it claims to be.
	parsed, err := saga.LoadFragment(data, out)
	if err != nil {
		t.Fatalf("the fragment it wrote does not load: %v\n%s", err, got)
	}
	if len(parsed.Components) != 1 {
		t.Errorf("components = %d, want 1", len(parsed.Components))
	}
}

// A second survey adds to the fragment rather than replacing it, the same contract a Saga has.
func TestSurveyFragmentAddsToWhatIsAlreadyThere(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "team.saga-fragment.yaml")
	opts := surveyOptions{output: out, fragment: true}

	first := saga.Fragment{Components: []saga.Component{{Name: "team-a", Images: []saga.Image{{Image: "repo/a:1"}}}}}
	if err := surveyIntoFragment(opts, first, io.Discard); err != nil {
		t.Fatal(err)
	}
	second := saga.Fragment{Components: []saga.Component{{Name: "team-b", Images: []saga.Image{{Image: "repo/b:1"}}}}}
	if err := surveyIntoFragment(opts, second, io.Discard); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(out) //#nosec G304 -- a path this test just created under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := saga.LoadFragment(data, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Components) != 2 {
		t.Fatalf("second survey replaced the first: components = %d, want 2\n%s", len(parsed.Components), data)
	}
}

// A fragment is recognized by its name, so writing one under a Saga's name produces a file Draugr
// reads back as a Saga and rejects for having no release. The survey knows that before it connects
// to anything, and saying so then costs a retype rather than a survey.
func TestSurveyFragmentRefusesAFilenameDraugrWouldMisread(t *testing.T) {
	cmd := newSurveyCommand()
	cmd.SetArgs([]string{"k8s", "images", "--fragment", "-o", "wrong.saga.yaml"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("a fragment written under a Saga's name was accepted")
	}
	for _, want := range []string{".saga-fragment.yaml", "wrong.saga.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

// --name and --version set the release, and a fragment has none. Accepting them would leave
// somebody believing they had named the thing they are describing.
func TestSurveyFragmentRefusesReleaseFlags(t *testing.T) {
	for _, flag := range []string{"--name=app", "--version=2.0.0"} {
		cmd := newSurveyCommand()
		cmd.SetArgs([]string{"k8s", "images", "--fragment", flag, "-o", "x.saga-fragment.yaml"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s was accepted alongside --fragment", flag)
		}
	}
}
