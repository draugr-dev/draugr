package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestGosecInfo(t *testing.T) {
	info := NewGosec().Info()
	if info.Name != "gosec" || info.Binary != "gosec" {
		t.Errorf("info = %+v", info)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sast" {
		t.Errorf("controls = %v, want [sast]", info.Controls)
	}
}

// twoGoModules is a checkout with no go.mod at the root and a module in each of two directories,
// the shape where a single run from the root analyzes nothing.
func twoGoModules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, m := range []string{"service", "tools"} {
		if err := os.MkdirAll(filepath.Join(dir, m), 0o750); err != nil {
			t.Fatal(err)
		}
		body := "module example.com/" + m + "\n\ngo 1.21\n"
		if err := os.WriteFile(filepath.Join(dir, m, "go.mod"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestGosecArgsRunsOncePerModule(t *testing.T) {
	dir := twoGoModules(t)
	got := gosecArgs(dir, nil)
	if len(got) != 2 {
		t.Fatalf("runs = %v, want one per module", got)
	}
	for i, m := range []string{"service", "tools"} {
		want := []string{"gosec", "-fmt", "sarif", "-no-fail", "-track-suppressions", filepath.Join(dir, m, "...")}
		if !slices.Equal(got[i], want) {
			t.Errorf("run %d = %v, want %v", i, got[i], want)
		}
	}
	if got := gosecArgs(t.TempDir(), nil); len(got) != 0 {
		t.Errorf("a tree with no module ran gosec: %v", got)
	}
}

// A `#nosec` result has to survive into the report, because an excluded finding that is simply
// gone reads as a finding nobody ever made. gosec only emits it when asked, and the flag that asks
// is the one thing standing between an acceptance and a silent deletion.
func TestGosecIsAskedToKeepWhatItSuppressed(t *testing.T) {
	dir := twoGoModules(t)
	for _, cfg := range []plugin.Config{
		nil,
		{"include": "G101"},
		{"exclude": "G204", "tags": "integration"},
	} {
		for _, argv := range gosecArgs(dir, cfg) {
			if !slices.Contains(argv, "-track-suppressions") {
				t.Errorf("gosecArgs(%v) = %v, with no -track-suppressions", cfg, argv)
			}
		}
	}
}

// Two modules' SARIF arrive one after the other and are read as one report. No output is a tree
// with no module, which the report says rather than passing.
func TestParseGosec(t *testing.T) {
	doc := func(rule, uri string) string {
		return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"` + rule +
			`","defaultConfiguration":{"level":"error"}}]}},"results":[{"ruleId":"` + rule +
			`","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + uri +
			`"},"region":{"startLine":3}}}]}]}]}`
	}
	// Each run names its files relative to its own module, and they come back under it.
	rep, err := parseGosec([]byte(doc("G204", "main.go")+"\n"+doc("G101", "main.go")), twoGoModules(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rep.Results {
		got = append(got, r.RuleID+"@"+r.Location.URI)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"G101@tools/main.go", "G204@service/main.go"}) {
		t.Errorf("results = %v", got)
	}

	// A report missing for a module is refused rather than read as that module being clean.
	if _, err := parseGosec([]byte(doc("G204", "main.go")), twoGoModules(t), nil); err == nil || !strings.Contains(err.Error(), "1 reports for 2 modules") {
		t.Errorf("err = %v, want the missing report named", err)
	}

	rep, err = parseGosec(nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 || len(rep.Provenance) != 1 || !strings.Contains(rep.Provenance[0].Describe(), "no go.mod found") {
		t.Errorf("no module = %+v, want a statement that nothing was analyzed", rep)
	}
	if _, err := parseGosec([]byte("{"), "", nil); err == nil {
		t.Error("unreadable output was accepted")
	}
	if _, err := parseGosec([]byte(`{"runs":"x"}`), "", nil); err == nil {
		t.Error("a document that is not SARIF was accepted")
	}
}

// A rule include or exclude left out comes back from gosec as an external suppression, and is
// dropped: the descriptor said the rule does not apply, which is not an acceptance of a finding.
// A #nosec, kind inSource, stays in the report either way.
func TestParseGosecDropsRulesOutsideTheSelection(t *testing.T) {
	result := func(rule, kind string) string {
		sup := ""
		if kind != "" {
			sup = `,"suppressions":[{"kind":"` + kind + `","justification":"j"}]`
		}
		return `{"ruleId":"` + rule + `","message":{"text":"m"},"locations":[{"physicalLocation":` +
			`{"artifactLocation":{"uri":"main.go"},"region":{"startLine":3}}}]` + sup + `}`
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"G204"},{"id":"G401"},{"id":"G101"}]}},"results":[` +
		result("G204", "") + "," + result("G401", "external") + "," + result("G101", "inSource") + `]}]}`
	for _, c := range []struct {
		cfg  plugin.Config
		want []string
	}{
		{plugin.Config{"include": []any{"G204", "G101"}}, []string{"G101", "G204"}},
		{plugin.Config{"exclude": []any{"G401"}}, []string{"G101", "G204"}},
		{nil, []string{"G101", "G204", "G401"}},
	} {
		rep, err := parseGosec([]byte(doc), "", c.cfg)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rep.Results {
			got = append(got, r.RuleID)
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("parseGosec(%v) = %v, want %v", c.cfg, got, c.want)
		}
	}
}

func TestExecArgvInDirSetsCwd(t *testing.T) {
	dir := t.TempDir()
	out, err := execArgvInDir(context.Background(), dir, []string{"pwd"})
	if err != nil {
		t.Fatalf("execArgvInDir: %v", err)
	}
	// macOS resolves /var → /private/var; compare on the base name to stay portable.
	if !strings.Contains(strings.TrimSpace(string(out)), strings.TrimPrefix(dir, "/private")) {
		t.Errorf("pwd = %q, want it to reflect dir %q", strings.TrimSpace(string(out)), dir)
	}
	if _, err := execArgvInDir(context.Background(), "", nil); err == nil {
		t.Error("empty argv should error")
	}
}
