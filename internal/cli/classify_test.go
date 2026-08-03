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
	if err := runClassify(path, false, in, &out); err != nil {
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
	err := runClassify(filepath.Join(t.TempDir(), "missing.yaml"), false, strings.NewReader(""), &bytes.Buffer{})
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
	if err := runClassify(path, false, strings.NewReader(""), &out); err != nil {
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
	if err := runClassify(path, false, strings.NewReader(""), &out); err != nil {
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
