package cli

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestAskExposure(t *testing.T) {
	cases := []struct {
		answers string
		want    saga.Exposure
	}{
		{"y\ny\n", saga.ExposureAuthenticated}, // internet + auth
		{"y\nn\n", saga.ExposurePublic},        // internet, no auth
		{"n\ny\n", saga.ExposureRestricted},    // not internet, restricted
		{"n\nn\n", saga.ExposureInternal},      // not internet, not restricted
	}
	for _, tc := range cases {
		sc := bufio.NewScanner(strings.NewReader(tc.answers))
		if got := askExposure(sc, &bytes.Buffer{}); got != tc.want {
			t.Errorf("answers %q → %s, want %s", tc.answers, got, tc.want)
		}
	}
}

func TestAskCriticality(t *testing.T) {
	cases := map[string]saga.Criticality{
		"1\n":       saga.CriticalityCritical,
		"2\n":       saga.CriticalityImportant,
		"3\n":       saga.CriticalitySupporting,
		"x\n9\n2\n": saga.CriticalityImportant, // reprompts until valid
		"":          saga.CriticalityImportant, // EOF → sane default
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
	// gateway is unclassified → answer public + critical; dashboard is skipped (already done).
	in := strings.NewReader("y\nn\n1\n")
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
