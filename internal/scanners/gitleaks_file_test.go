package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A history report read from its file gives the findings and the secrets that reading it whole
// gives.
func TestAGitleaksReportReadsTheSameFromItsFile(t *testing.T) {
	path := filepath.Join("testdata", "gitleaks-history.sarif")
	data, err := os.ReadFile(path) // #nosec G304 -- a fixture of this package
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseGitleaks(data, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseGitleaksFile(path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Results) == 0 || !reflect.DeepEqual(got, want) {
		t.Errorf("from the file:\n%+v\nwhole:\n%+v", got, want)
	}
	for _, r := range got.Results {
		for k := range r.PartialFingerprints {
			if k != "commitSha" {
				t.Errorf("fingerprint %q kept; only the commit is", k)
			}
		}
	}
	if s, w := gitleaksSecretsFile(path), gitleaksSecrets(data); len(w) == 0 || !slices.Equal(s, w) {
		t.Errorf("secrets from the file %q, whole %q", s, w)
	}
}

func TestGitleaksSecretsFileReadsNothingItCannotRead(t *testing.T) {
	if got := gitleaksSecretsFile(filepath.Join(t.TempDir(), "absent.sarif")); got != nil {
		t.Errorf("a missing report gave %q", got)
	}
	bad := filepath.Join(t.TempDir(), "bad.sarif")
	if err := os.WriteFile(bad, []byte(`{"runs":[{"results":[1]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitleaksSecretsFile(bad); got != nil {
		t.Errorf("a result that is not an object gave %q", got)
	}
	if _, err := parseGitleaksFile(bad, "", nil); err == nil {
		t.Error("a report whose result is not an object parsed")
	}
}

// A tool that writes its report to standard output still leaves it in a file for the history
// pass, and a scanner that reads its report whole reads it from there.
func TestAHistoryReportOnStandardOutputIsReadFromItsFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gitleaks-history.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(context.Context, string, []string) ([]byte, error) { return data, nil }
	path, remove, err := runToReportFile(context.Background(), t.TempDir(), []string{"tool"}, run)
	if err != nil {
		t.Fatal(err)
	}
	s := repoScanner{info: plugin.ScannerInfo{Name: "gitleaks"}, parse: parseGitleaks, secrets: gitleaksSecrets}
	report, secrets, err := s.readHistory(path, "", nil)
	remove()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := parseGitleaks(data, "", nil)
	if !reflect.DeepEqual(report, want) || !slices.Equal(secrets, gitleaksSecrets(data)) {
		t.Errorf("read whole from the file: %d results, %d secrets", len(report.Results), len(secrets))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the report is still on disk after remove: %v", err)
	}

	failing := func(context.Context, string, []string) ([]byte, error) { return nil, os.ErrPermission }
	if _, _, err := runToReportFile(context.Background(), t.TempDir(), []string{"tool"}, failing); err == nil {
		t.Error("a run that failed left a report")
	}
	if _, _, err := runToReportFile(context.Background(), t.TempDir(), []string{"tool", ReportPathToken}, failing); err == nil {
		t.Error("a run that failed left a report")
	}
	if _, _, err := (repoScanner{info: plugin.ScannerInfo{Name: "x"}}).readHistory(filepath.Join(t.TempDir(), "absent"), "", nil); err == nil {
		t.Error("a missing report read without error")
	}
	sf := repoScanner{info: plugin.ScannerInfo{Name: "x"}, parseFile: func(string, string, plugin.Config) (sarif.Report, error) {
		return sarif.Report{}, os.ErrInvalid
	}}
	if _, _, err := sf.readHistory(path, "", nil); err == nil {
		t.Error("a report that did not parse read without error")
	}
}
