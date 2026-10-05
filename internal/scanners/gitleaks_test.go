package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestGitleaksInfo(t *testing.T) {
	info := NewGitleaks().Info()
	if info.Name != "gitleaks" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "secrets" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetRepository {
		t.Errorf("target kinds = %v", info.TargetKinds)
	}
}

func TestGitleaksArgs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	argv := gitleaksArgs("/work/repo", nil)
	want := []string{
		"gitleaks", "dir", "/work/repo",
		"--report-format", "sarif",
		"--report-path", ReportPathToken,
		"--exit-code", "0",
		"--no-banner",
	}
	// Plus `--config <composed ruleset>`, which every invocation carries and which
	// TestEveryGitleaksInvocationCarriesTheRuleset checks the contents of. Compared as a prefix so
	// this test stays about the invocation's shape.
	if len(argv) != len(want)+2 {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

// Gitleaks says when it is reading history, so the engine can tell a job it may key on a subtree
// from one it may not.
//
// Two commits can carry an identical tree and different history, so a result keyed on the tree
// would be served to a run asking a different question.
func TestGitleaksSaysWhenItReadsHistory(t *testing.T) {
	s, ok := NewGitleaks().(plugin.HistoryReader)
	if !ok {
		t.Fatal("gitleaks does not implement plugin.HistoryReader, so a history scan may be keyed on a tree")
	}
	if !s.ReadsHistory(plugin.Config{"history": true}) {
		t.Error("a history scan does not say so")
	}
	if s.ReadsHistory(plugin.Config{}) {
		t.Error("a tree scan claims to read history, which costs it the narrower cache key")
	}
}

// A scanner with nothing wired reads the tree, which is true of everything but one.
func TestAScannerWithNoHistoryModeReadsTheTree(t *testing.T) {
	s, ok := NewSemgrep().(plugin.HistoryReader)
	if !ok {
		t.Fatal("expected the shared repo scanner to answer")
	}
	if s.ReadsHistory(plugin.Config{"history": true}) {
		t.Error("semgrep claims to read history")
	}
}

// What a secret finding leaves behind, in the report and in a cache entry, holds neither the
// secret nor who committed it. The fixture is Gitleaks 8.30.1's own SARIF for a token committed
// and then removed, so found only in history, its rule list cut to the rule that fired; the token
// is written into it at run time, so this file holds no credential for a scanner to report.
//
// Gitleaks puts the secret in the region's snippet and the commit's author name, email, date and
// message in the partial fingerprints. A report, and a cache entry, which is the same report
// serialized, would otherwise carry personal data and could carry the credential itself.
func TestASecretFindingCarriesNeitherTheSecretNorItsAuthor(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "gitleaks-history.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	token := "ghp_" + strings.Repeat("Dr4ugrFixtur3", 3)[:36]
	out := []byte(strings.ReplaceAll(string(fixture), "__TOKEN__", token))

	report, err := NewGitleaks().(repoScanner).decode(out, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %d, want the one finding", len(report.Results))
	}
	if got := report.Results[0].PartialFingerprints["commitSha"]; got != "4dd0b35ce7497770369b24c3e860be3954b27b3c" {
		t.Errorf("commitSha = %q, want the commit kept", got)
	}
	asSARIF, err := report.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	asCacheEntry, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{"results.sarif": asSARIF, "a cache entry": asCacheEntry} {
		for _, leaked := range []string{token, "jane.doe@example.com", "Jane Doe", "temporary token for the release job", "2026-10-05T05:47:11Z"} {
			if strings.Contains(string(doc), leaked) {
				t.Errorf("%s carries %q", name, leaked)
			}
		}
	}
}
