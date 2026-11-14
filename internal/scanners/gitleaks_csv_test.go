package scanners

import (
	"context"
	"encoding/csv"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gitleaksCSVHeader is the header Gitleaks 8.30.1's CSV writer puts first (report/csv.go), Link
// last as it adds it when the first finding has one.
var gitleaksCSVHeader = []string{"RuleID", "Commit", "File", "SymlinkFile", "Secret", "Match",
	"StartLine", "EndLine", "StartColumn", "EndColumn", "Author", "Message", "Date", "Email",
	"Fingerprint", "Tags", "Link"}

// writeGitleaksCSV writes rows under header as Gitleaks' CSV writer does, through encoding/csv,
// and returns the file's path.
func writeGitleaksCSV(t *testing.T, header []string, rows ...[]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.csv")
	f, err := os.Create(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	if header != nil {
		if err := w.Write(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.WriteAll(rows); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// The token is assembled at run time, so this file holds no credential for a scanner to report.
var csvToken = "ghp_" + strings.Repeat("Dr4ugrFixtur3", 3)[:36]

// A CSV row becomes the result Gitleaks' SARIF writer gives the same finding: the rule, the
// sentence naming the file and the commit, the location, at the symlink where the file was reached
// through one, the secret as the snippet, and of the commit only its hash, whatever the row's
// commit message holds.
func TestGitleaksCSVBecomesTheSARIFGitleaksWrites(t *testing.T) {
	commit := "4dd0b35ce7497770369b24c3e860be3954b27b3c"
	path := writeGitleaksCSV(t, gitleaksCSVHeader,
		[]string{"github-pat", commit, "deploy.env", "", csvToken, "TOKEN=" + csvToken, "1", "1", "14", "53",
			"Jane Doe", "temporary token, for the \"release\" job\nsecond line", "2026-10-05T05:47:11Z",
			"jane.doe@example.com", commit + ":deploy.env:github-pat:1", "a b", "https://example.com/c"},
		[]string{"generic-api-key", "", "real/config.py", "linked/config.py", "s3cr3tvalue", "m", "7", "8", "2", "30",
			"", "", "", "", "fp", "", ""},
	)
	out := filepath.Join(t.TempDir(), "report.sarif")
	if err := gitleaksCSVToSARIF(path, out); err != nil {
		t.Fatal(err)
	}
	report, err := parseGitleaksFile(out, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []sarif.Result{
		{RuleID: "github-pat",
			Message:             "github-pat has detected secret for file deploy.env at commit " + commit + ".",
			Location:            sarif.Location{URI: "deploy.env", StartLine: 1},
			PartialFingerprints: map[string]string{"commitSha": commit}},
		{RuleID: "generic-api-key",
			Message:  "generic-api-key has detected secret for file real/config.py.",
			Location: sarif.Location{URI: "linked/config.py", StartLine: 7}},
	}
	if len(report.Results) != len(want) {
		t.Fatalf("results %+v", report.Results)
	}
	for i, w := range want {
		got := report.Results[i]
		if got.RuleID != w.RuleID || got.Message != w.Message || got.Location != w.Location ||
			!maps.Equal(got.PartialFingerprints, w.PartialFingerprints) {
			t.Errorf("result %d = %+v\nwant %+v", i, got, w)
		}
	}
	if got := gitleaksSecretsFile(out); !slices.Equal(got, []string{csvToken, "s3cr3tvalue"}) {
		t.Errorf("secrets = %q", got)
	}
	raw, err := os.ReadFile(out) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, left := range []string{"Jane Doe", "jane.doe@example.com", "release", "2026-10-05"} {
		if strings.Contains(string(raw), left) {
			t.Errorf("the SARIF carries %q from the commit", left)
		}
	}
	if !strings.Contains(string(raw), `"tags":["a","b"]`) {
		t.Errorf("the tags were not carried:\n%s", raw)
	}
}

// Gitleaks writes nothing at all when it finds nothing, and a header with no rows is the same
// answer; either is a report with no results. Columns are found by name, so another order reads
// the same.
func TestGitleaksCSVWithNothingOrInAnotherOrder(t *testing.T) {
	for name, path := range map[string]string{
		"empty":       writeGitleaksCSV(t, nil),
		"header only": writeGitleaksCSV(t, gitleaksCSVHeader),
	} {
		out := filepath.Join(t.TempDir(), "r.sarif")
		if err := gitleaksCSVToSARIF(path, out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		report, err := sarif.FromSARIFFile(out)
		if err != nil || len(report.Results) != 0 || report.Tool != "gitleaks" {
			t.Errorf("%s: %+v, %v", name, report, err)
		}
	}
	reordered := writeGitleaksCSV(t, []string{"File", "StartLine", "RuleID"}, []string{"a.txt", "3", "r"})
	out := filepath.Join(t.TempDir(), "r.sarif")
	if err := gitleaksCSVToSARIF(reordered, out); err != nil {
		t.Fatal(err)
	}
	report, err := sarif.FromSARIFFile(out)
	if err != nil || len(report.Results) != 1 || report.Results[0].RuleID != "r" ||
		report.Results[0].Location != (sarif.Location{URI: "a.txt", StartLine: 3}) {
		t.Errorf("%+v, %v", report.Results, err)
	}
}

// A report that is not Gitleaks' CSV is an error, never a report with fewer findings.
func TestGitleaksCSVRefusesWhatItCannotRead(t *testing.T) {
	for name, path := range map[string]string{
		"no rule column": writeGitleaksCSV(t, []string{"File"}, []string{"a"}),
		"a bad line":     writeGitleaksCSV(t, gitleaksCSVHeader, append([]string{"r", "", "a", "", "s", "", "x"}, make([]string, 10)...)),
		"a short row":    writeGitleaksCSV(t, []string{"RuleID", "File"}, []string{"r", "a"}, []string{"r"}),
	} {
		if err := gitleaksCSVToSARIF(path, filepath.Join(t.TempDir(), "r.sarif")); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if err := gitleaksCSVToSARIF(filepath.Join(t.TempDir(), "missing.csv"), filepath.Join(t.TempDir(), "r.sarif")); err == nil {
		t.Error("a missing report was read")
	}
	if err := gitleaksCSVToSARIF(writeGitleaksCSV(t, nil), filepath.Join(t.TempDir(), "no", "dir", "r.sarif")); err == nil {
		t.Error("a SARIF path that cannot be written was accepted")
	}
}

// A pass asking for CSV runs with a CSV path of its own, leaves SARIF at the path it named, and
// leaves no CSV behind; any other pass runs as it is, and a run that fails is that failure.
func TestGitleaksCSVAsSARIFWrapsOnlyACSVPass(t *testing.T) {
	var ran []string
	csvRow := []string{"r", "", "a.txt", "", "s", "", "2", "2", "1", "3", "", "", "", "", "", "", ""}
	run := gitleaksCSVAsSARIF(func(_ context.Context, _ string, argv []string) ([]byte, error) {
		ran = slices.Clone(argv)
		p := argv[slices.Index(argv, "--report-path")+1]
		if argv[slices.Index(argv, "--report-format")+1] != "csv" {
			return []byte("as is"), nil
		}
		f, err := os.Create(p) // #nosec G304 -- the path the wrapper made
		if err != nil {
			return nil, err
		}
		w := csv.NewWriter(f)
		_ = w.Write(gitleaksCSVHeader)
		_ = w.Write(csvRow)
		w.Flush()
		return nil, f.Close()
	})
	sarifPath := filepath.Join(t.TempDir(), "history.sarif")
	if _, err := run(context.Background(), "", []string{"gitleaks", "git", ".", "--report-format", "csv", "--report-path", sarifPath}); err != nil {
		t.Fatal(err)
	}
	csvPath := ran[slices.Index(ran, "--report-path")+1]
	if csvPath == sarifPath {
		t.Fatal("Gitleaks was given the SARIF path for its CSV")
	}
	if _, err := os.Stat(csvPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the CSV %s is still there: %v", csvPath, err)
	}
	report, err := sarif.FromSARIFFile(sarifPath)
	if err != nil || len(report.Results) != 1 || report.Results[0].Location.URI != "a.txt" {
		t.Errorf("%+v, %v", report.Results, err)
	}

	argv := []string{"gitleaks", "dir", ".", "--report-format", "sarif", "--report-path", sarifPath}
	if out, err := run(context.Background(), "", argv); err != nil || string(out) != "as is" || !slices.Equal(ran, argv) {
		t.Errorf("a SARIF pass ran %v: %q %v", ran, out, err)
	}

	failed := errors.New("exit status 1")
	failing := gitleaksCSVAsSARIF(func(context.Context, string, []string) ([]byte, error) { return nil, failed })
	if _, err := failing(context.Background(), "", []string{"gitleaks", "git", ".", "--report-format", "csv", "--report-path", sarifPath}); !errors.Is(err, failed) {
		t.Errorf("err = %v, want the run's", err)
	}
	broken := gitleaksCSVAsSARIF(func(_ context.Context, _ string, argv []string) ([]byte, error) {
		return nil, os.WriteFile(argv[slices.Index(argv, "--report-path")+1], []byte("Nope\nx\n"), 0o600)
	})
	if _, err := broken(context.Background(), "", []string{"gitleaks", "git", ".", "--report-format", "csv", "--report-path", sarifPath}); err == nil ||
		!strings.Contains(err.Error(), "read its CSV report") {
		t.Errorf("err = %v, want the report refused", err)
	}
}

// The history pass asks Gitleaks for CSV and the tree pass for SARIF, and a history scan built by
// NewGitleaks turns the CSV into findings marked historical.
func TestGitleaksHistoryPassAsksForCSV(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	hist := gitleaksHistoryArgs("/work/repo", plugin.Config{"history": true})
	if i := slices.Index(hist, "--report-format"); i < 0 || hist[i+1] != "csv" {
		t.Errorf("history argv %v, want --report-format csv", hist)
	}
	if tree := gitleaksArgs("/work/repo", nil); tree[slices.Index(tree, "--report-format")+1] != "sarif" {
		t.Errorf("tree argv %v, want --report-format sarif", tree)
	}

	prior := execArgvInDir
	t.Cleanup(func() { execArgvInDir = prior })
	execArgvInDir = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		path := argv[slices.Index(argv, "--report-path")+1]
		if argv[1] != "git" {
			return nil, os.WriteFile(path, []byte(gitleaksReport()), 0o600)
		}
		f, err := os.Create(path) // #nosec G304 -- the path the wrapper made
		if err != nil {
			return nil, err
		}
		w := csv.NewWriter(f)
		_ = w.Write(gitleaksCSVHeader)
		_ = w.Write([]string{"github-pat", "abc123", "old/deploy.env", "", csvToken, "", "1", "1", "1", "40", "", "", "", "", "", "", ""})
		w.Flush()
		return nil, f.Close()
	}
	s := NewGitleaks().(repoScanner)
	s.cacheVersion = nil
	dir := t.TempDir()
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	s.runLogged = gitleaksTree(withoutLog(s.run), gitleaksVersion(""))
	report, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "./api"}, plugin.Config{"history": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || !report.Results[0].Historical || report.Results[0].Location.URI != "old/deploy.env" ||
		report.Results[0].PartialFingerprints["commitSha"] != "abc123" {
		t.Errorf("results %+v, want the history finding", report.Results)
	}
}
