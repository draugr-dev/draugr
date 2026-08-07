package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
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

// What the subcommands exist to prevent: `--github-org acme --k8s-namespace prod` reading as a
// valid command, applying the namespace to nothing, and saying nothing. Leaving a retired flag
// registered and ignored would reproduce exactly that, so it errors with its replacement.
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
		t.Error("--namespace must not be reachable from github repos — a flag accepted where it means nothing does nothing, silently")
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

// Discovery's promise is that the descriptor writes itself. One that enables no control has not
// written itself — it has written a shape, and its first scan reports PASS having checked
// nothing.
func TestEnableControlsForSurface(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		comp saga.Component
		want []string
	}{
		{"repositories", saga.Component{Repositories: []saga.Repository{{URL: "u"}}}, []string{"iac", "sast", "sca", "secrets"}},
		{"images", saga.Component{Images: []saga.Image{{Image: "nginx:1"}}}, []string{"images"}},
		{"infrastructure", saga.Component{Infrastructure: []saga.Infrastructure{{Kind: "kubernetes"}}}, []string{"infrastructure"}},

		// Passive host controls only. dast sends attack traffic at a live service, and enabling
		// that because a survey noticed the service exists is not discovery's decision to make.
		{"hosts", saga.Component{Hosts: []saga.Host{{URL: "https://x.test"}}}, []string{"headers", "tls"}},

		{"nothing discovered", saga.Component{Name: "empty"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &saga.Model{Components: []saga.Component{tc.comp}}
			got := enableControlsForSurface(m)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("enabled %v, want %v", got, tc.want)
			}
			for _, name := range tc.want {
				if m.Config.Controllers[name] == nil {
					t.Errorf("%s should be present in the descriptor", name)
				}
			}
			if tc.name == "hosts" && m.Config.Controllers["dast"] != nil {
				t.Error("dast must not be enabled by discovery")
			}
		})
	}
}

// --merge runs against a descriptor people edit. A survey that re-enabled something switched off
// by hand would be a worse failure than the one this fixes.
func TestEnableControlsLeavesConfiguredControlsAlone(t *testing.T) {
	t.Parallel()

	m := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"sca":     {"enabled": false},
			"secrets": {"enabled": true, "someOption": "kept"},
		}},
		Components: []saga.Component{{Repositories: []saga.Repository{{URL: "u"}}}},
	}
	added := enableControlsForSurface(m)

	if slices.Contains(added, "sca") || slices.Contains(added, "secrets") {
		t.Errorf("a configured control must be left alone, added %v", added)
	}
	if enabled, _ := m.Config.Controllers["sca"]["enabled"].(bool); enabled {
		t.Error("a control switched off by hand must stay off")
	}
	if m.Config.Controllers["secrets"]["someOption"] != "kept" {
		t.Error("an existing control's options must survive")
	}
	// The ones nobody mentioned are still filled in.
	if !slices.Equal(added, []string{"iac", "sast"}) {
		t.Errorf("added = %v, want [iac sast]", added)
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
	got := surveySummary(surveyOptions{output: ".saga.yaml"}, saga.Fragment{}, model)
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
	got := surveySummary(surveyOptions{output: "s.yaml", merge: true}, frag, model)
	if !strings.Contains(got, "merged into s.yaml") || !strings.Contains(got, "this survey found 1 component") {
		t.Errorf("got %q", got)
	}
}

func TestSurveySummaryCallsOutADescriptorThatScansNothing(t *testing.T) {
	// A survey that discovered nothing writes a valid file that checks nothing, and the count
	// alone reads as success.
	got := surveySummary(surveyOptions{output: "s.yaml"}, saga.Fragment{}, saga.Model{})
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
