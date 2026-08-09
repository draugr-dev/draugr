package cli

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// The decision tree these used to walk is gone: both questions are numbered lists now, and
// TestClassifyMapsChoicesToValues covers every rung of both ladders. What is kept here is the
// behaviour that is easy to lose in a rewrite — reprompting, and what happens at EOF.
func TestAskCriticalityRepromptsAndDefaults(t *testing.T) {
	cases := map[string]saga.Criticality{
		"x\n9\n2\n": saga.CriticalityImportant, // reprompts until valid
		"":          saga.CriticalityImportant, // EOF → the middle of the ladder
	}
	for answers, want := range cases {
		sc := bufio.NewScanner(strings.NewReader(answers))
		if got := askCriticality(sc, &bytes.Buffer{}); got != want {
			t.Errorf("answers %q → %s, want %s", answers, got, want)
		}
	}
}

const classifySaga = `release:
  name: app
  version: "1.0"
components:
  - name: gateway
    images:
      - image: repo/gw:1
  - name: dashboard
    exposure: internal
    criticality: supporting
`

func TestRunClassifyWritesUnclassified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}
	// gateway is unclassified → 1 = public, 1 = critical; dashboard is skipped (already done).
	// One numbered answer per question, which is the whole point of the change: the reader no
	// longer switches between y/N and a list halfway through.
	in := strings.NewReader("1\n1\n")
	var out bytes.Buffer
	if err := runClassify(path, classifyOptions{}, in, &out); err != nil {
		t.Fatal(err)
	}
	m, err := saga.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]saga.Component{}
	for _, c := range m.Components {
		byName[c.Name] = c
	}
	if byName["gateway"].Exposure != saga.ExposurePublic || byName["gateway"].Criticality != saga.CriticalityCritical {
		t.Errorf("gateway = %+v", byName["gateway"])
	}
	// dashboard untouched.
	if byName["dashboard"].Exposure != saga.ExposureInternal {
		t.Errorf("dashboard should be untouched: %+v", byName["dashboard"])
	}
	if !strings.Contains(out.String(), "Classified 1 component") {
		t.Errorf("summary missing:\n%s", out.String())
	}
}

func TestRunClassifyLoadError(t *testing.T) {
	err := runClassify(filepath.Join(t.TempDir(), "missing.yaml"), classifyOptions{}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error for a missing saga file")
	}
}

func TestRunClassifyNoComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(path, []byte("release:\n  version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runClassify(path, classifyOptions{}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No components") {
		t.Errorf("expected no-components message:\n%s", out.String())
	}
}

func TestClassifyCommandViaCobra(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newClassifyCommand()
	cmd.SetIn(strings.NewReader("n\nn\n3\n")) // gateway → internal/supporting
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	m, _ := saga.LoadFile(path)
	if m.Components[0].Exposure != saga.ExposureInternal {
		t.Errorf("gateway = %+v", m.Components[0])
	}
}

func TestRunClassifyAllAlreadyClassified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	body := "release:\n  version: \"1\"\ncomponents:\n  - name: a\n    exposure: public\n    criticality: critical\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runClassify(path, classifyOptions{}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already classified") {
		t.Errorf("expected already-classified message:\n%s", out.String())
	}
}

func TestClassifyAsksOneKindOfQuestion(t *testing.T) {
	// Exposure used to be a tree of yes/no questions and criticality a numbered list, so a
	// reader switched modes halfway through a wizard whose point is to be quick.
	var buf bytes.Buffer
	sc := bufio.NewScanner(strings.NewReader("1\n1\n"))
	askExposure(sc, &buf)
	askCriticality(sc, &buf)

	out := buf.String()
	if strings.Contains(out, "[y/N]") {
		t.Errorf("a yes/no question survived:\n%s", out)
	}
	if n := strings.Count(out, "Choose ["); n != 2 {
		t.Errorf("expected two numbered prompts, got %d:\n%s", n, out)
	}
}

func TestClassifyShowsTheWholeLadder(t *testing.T) {
	// A decision tree hides rungs: answering "not public" never revealed that restricted sits
	// below internal. Every value has to be visible while choosing.
	var buf bytes.Buffer
	askExposure(bufio.NewScanner(strings.NewReader("1\n")), &buf)
	for _, want := range []string{"public", "authenticated", "internal", "restricted"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("exposure option %q not offered:\n%s", want, buf.String())
		}
	}

	buf.Reset()
	askCriticality(bufio.NewScanner(strings.NewReader("1\n")), &buf)
	for _, want := range []string{"critical", "important", "supporting"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("criticality option %q not offered:\n%s", want, buf.String())
		}
	}
}

func TestClassifyWordingNamesNoPlatform(t *testing.T) {
	// "Is its network access restricted (namespace / network policy)?" is answerable if you run
	// Kubernetes and a guess otherwise — and a guess here silently miscolours every P1 after it.
	var buf bytes.Buffer
	askExposure(bufio.NewScanner(strings.NewReader("1\n")), &buf)
	for _, leak := range []string{"namespace", "network policy", "kubernetes", "cluster", "pod"} {
		if strings.Contains(strings.ToLower(buf.String()), leak) {
			t.Errorf("wording assumes a platform (%q):\n%s", leak, buf.String())
		}
	}
}

func TestClassifyMapsChoicesToValues(t *testing.T) {
	for in, want := range map[string]saga.Exposure{
		"1\n": saga.ExposurePublic, "2\n": saga.ExposureAuthenticated,
		"3\n": saga.ExposureInternal, "4\n": saga.ExposureRestricted,
	} {
		if got := askExposure(bufio.NewScanner(strings.NewReader(in)), io.Discard); got != want {
			t.Errorf("exposure %q → %q, want %q", strings.TrimSpace(in), got, want)
		}
	}
	for in, want := range map[string]saga.Criticality{
		"1\n": saga.CriticalityCritical, "2\n": saga.CriticalityImportant, "3\n": saga.CriticalitySupporting,
	} {
		if got := askCriticality(bufio.NewScanner(strings.NewReader(in)), io.Discard); got != want {
			t.Errorf("criticality %q → %q, want %q", strings.TrimSpace(in), got, want)
		}
	}
}

func TestClassifyRepromptsAndFallsBack(t *testing.T) {
	var buf bytes.Buffer
	// A bad answer is re-asked rather than guessed at.
	got := askExposure(bufio.NewScanner(strings.NewReader("9\nbanana\n2\n")), &buf)
	if got != saga.ExposureAuthenticated {
		t.Errorf("got %q after two bad answers", got)
	}
	if !strings.Contains(buf.String(), "Please enter a number from 1 to 4") {
		t.Errorf("no reprompt:\n%s", buf.String())
	}
	// At EOF — a piped or truncated session — the middle of the ladder, which neither hides risk
	// nor invents it.
	if got := askExposure(bufio.NewScanner(strings.NewReader("")), io.Discard); got != saga.ExposureInternal {
		t.Errorf("EOF fallback = %q, want internal", got)
	}
}

// `draugr scan .` finds the descriptor; a reader who has just run it has no reason to think the
// next command needs the filename spelled out.
func TestClassifyFindsTheDescriptorInADirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "web.saga.yaml")
	if err := os.WriteFile(path, []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runClassify(dir, classifyOptions{}, strings.NewReader("1\n1\n"), &out); err != nil {
		t.Fatal(err)
	}
	m, err := saga.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Components[0].Exposure != saga.ExposurePublic {
		t.Errorf("the descriptor in the directory was not the one written: %+v", m.Components[0])
	}
	if !strings.Contains(out.String(), "web.saga.yaml") {
		t.Errorf("the summary has to name the file it wrote:\n%s", out.String())
	}
}

// A scan can synthesize a descriptor and say so. Classification cannot: exposure and criticality
// are judgements, and there is nowhere to record them.
func TestClassifyOnADirectoryWithNoDescriptorSaysWhatToDo(t *testing.T) {
	err := runClassify(t.TempDir(), classifyOptions{}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Fatal("want an error, got a silent success")
	}
	if !strings.Contains(err.Error(), "draugr init") {
		t.Errorf("error = %q, want it to say how to get a descriptor", err)
	}
}

// Reclassifying one component must not mean reclassifying every other one to reach it.
func TestClassifyComponentsPicksOneAndRedoesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}

	// dashboard is already classified. Naming it is the instruction to redo it — without --all,
	// which would have dragged gateway in too.
	var out bytes.Buffer
	err := runClassify(path, classifyOptions{components: []string{"dashboard"}},
		strings.NewReader("1\n1\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	m, err := saga.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]saga.Component{}
	for _, c := range m.Components {
		byName[c.Name] = c
	}
	if byName["dashboard"].Exposure != saga.ExposurePublic {
		t.Errorf("dashboard was not reclassified: %+v", byName["dashboard"])
	}
	if byName["gateway"].Exposure != "" {
		t.Errorf("gateway was not asked about and must be untouched: %+v", byName["gateway"])
	}
	if !strings.Contains(out.String(), "Classified 1 component") {
		t.Errorf("summary:\n%s", out.String())
	}
}

// A name that matches nothing is an error. Skipping it would report "all components are already
// classified" — an answer to a question nobody asked.
func TestClassifyRejectsAComponentThatIsNotThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		want []string
		says []string
	}{
		{"a typo suggests the name meant", []string{"gatewy"}, []string{"gateway"}},
		{"an unrelated name lists what there is", []string{"nothing-like-it"}, []string{`"gateway"`, `"dashboard"`}},
		{"several unknown names are all reported", []string{"nope", "also-nope"},
			[]string{`"nope"`, `"also-nope"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runClassify(path, classifyOptions{components: tc.want},
				strings.NewReader("1\n1\n"), &bytes.Buffer{})
			if err == nil {
				t.Fatal("want an error, got a silent skip")
			}
			for _, s := range tc.says {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("error = %q, want it to mention %q", err, s)
				}
			}
		})
	}
}

// The refusal has to name the command the reader is running. Suggesting `draugr scan` to somebody
// who typed `draugr classify` sends them to a different command than the one they wanted.
func TestClassifyRefusesTwoDescriptorsInItsOwnName(t *testing.T) {
	orig := chooser
	t.Cleanup(func() { chooser = orig })
	chooser = func([]string) (string, bool) { return "", false } // no terminal

	dir := writeDescriptors(t, "web.saga.yaml", "api.saga.yaml")
	err := runClassify(dir, classifyOptions{}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected a refusal, not a guess")
	}
	if !strings.Contains(err.Error(), "draugr classify") {
		t.Errorf("the suggestion names the wrong command: %v", err)
	}
}

// No argument at all is the shortest path and the one a reader reaches for after `draugr scan .`.
func TestClassifyWithNoArgumentUsesTheCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "draugr.saga.yaml"), []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	var out bytes.Buffer
	if err := runClassify("", classifyOptions{}, strings.NewReader("1\n1\n"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Classified 1 component") {
		t.Errorf("summary:\n%s", out.String())
	}

	// And with nothing to classify, the message names the directory it looked in.
	t.Chdir(t.TempDir())
	err := runClassify("", classifyOptions{}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "in .") {
		t.Errorf("error = %v, want it to name the directory", err)
	}
}

// `--components ,gateway` and `--components gateway,` are what a shell produces from a trailing
// comma. Neither is a component named "".
func TestClassifyIgnoresEmptyComponentNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(classifySaga), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runClassify(path, classifyOptions{components: []string{"", "gateway", " "}},
		strings.NewReader("1\n1\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Classified 1 component") {
		t.Errorf("summary:\n%s", out.String())
	}
}
