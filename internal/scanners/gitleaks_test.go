package scanners

import (
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
