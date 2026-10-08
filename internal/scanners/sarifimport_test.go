package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// field reads one provenance field the import scanner wrote.
func field(t *testing.T, rep sarif.Report, key string) string {
	t.Helper()
	for _, p := range rep.Provenance {
		if p.Tool != plugin.ImportScanner {
			continue
		}
		for _, f := range p.Fields {
			if f.Key == key {
				return f.Value
			}
		}
	}
	t.Fatalf("no %q field in %+v", key, rep.Provenance)
	return ""
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.sarif")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A log in the shape the tests need, from a tool named for the purpose. Results carry a level, a
// security-severity, or both as the case asks, and the run may state the revision it scanned.
func exampleLog(results, extra string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"example-scanner","semanticVersion":"4.2.0",
"rules":[{"id":"EX1","properties":{"security-severity":"9.1"}},{"id":"EX2"}]}},` + extra + `
"results":[` + results + `]}]}`
}

const (
	scoredResult  = `{"ruleId":"EX1","level":"warning","message":{"text":"scored"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"}}}]}`
	leveledResult = `{"ruleId":"EX2","level":"note","message":{"text":"leveled"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"}}}]}`
)

// A real gosec run imports as written: every finding, the tool and version from the file, its
// severities from the SARIF level because gosec scores nothing, and no commit, so it is unbound.
func TestSARIFImportReadsARealToolsFile(t *testing.T) {
	ft := plugin.FileTarget{Path: "testdata/sarif-import/gosec.sarif", Component: "app"}
	rep, err := NewSARIFImport().Scan(context.Background(), ft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 || rep.Results[0].Tool != "gosec" {
		t.Fatalf("results = %d, tool %q, want gosec's three", len(rep.Results), rep.Results[0].Tool)
	}
	for key, want := range map[string]string{
		"tool": "gosec 2.29.0", "file": ft.Path, "severity": "SARIF level", "commit": notStated, "component": "app",
	} {
		if got := field(t, rep, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := field(t, rep, "written"); !strings.Contains(got, "modification time") {
		t.Errorf("written = %q, want the file's modification time, gosec stating no end time", got)
	}
	if len(field(t, rep, "sha256")) != 64 {
		t.Error("sha256 is not a digest")
	}
}

// Anything that keeps the file from being read is an error, as for a scanner that could not run.
func TestSARIFImportRefusesWhatItCannotRead(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"empty", "  \n", "is empty"},
		{"not JSON", "not json", "not a SARIF log"},
		{"not SARIF", `{"hello":"world"}`, "not a SARIF log"},
		{"another version", `{"version":"2.0.0","runs":[]}`, `states SARIF version "2.0.0"`},
		{"no runs", `{"version":"2.1.0","runs":[]}`, "holds no runs"},
	} {
		_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body)}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: "testdata/sarif-import/absent.sarif"}, nil); err == nil {
		t.Error("a missing file was read")
	}
	if _, err := NewSARIFImport().Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil); err == nil {
		t.Error("a host target was accepted")
	}
}

// The provenance says where severities came from, so a priority resting on a level says so.
func TestSARIFImportSaysWhereSeveritiesCameFrom(t *testing.T) {
	for _, c := range []struct{ name, results, want string }{
		{"scored", scoredResult, "security-severity"},
		{"leveled", leveledResult, "SARIF level"},
		{"both", scoredResult + "," + leveledResult, "security-severity for 1, SARIF level for 1"},
		{"none", "", "no findings"},
	} {
		rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, exampleLog(c.results, ""))}, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := field(t, rep, "severity"); got != c.want {
			t.Errorf("%s: severity = %q, want %q", c.name, got, c.want)
		}
	}
	rep, _ := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, exampleLog(scoredResult, ""))}, nil)
	if got := field(t, rep, "tool"); got != "example-scanner 4.2.0" {
		t.Errorf("tool = %q, want the semanticVersion", got)
	}
}

// A file that names the revision it scanned is held to the one this run reads: the same commit
// binds it, another commit is refused, and a repository the component does not declare is refused.
func TestSARIFImportHoldsAFileToTheRevisionScanned(t *testing.T) {
	const head = "0123456789abcdef0123456789abcdef01234567"
	scanner := sarifImport{resolve: func(_ context.Context, url, _ string) (string, error) {
		if url == "./broken" {
			return "", errors.New("no such repository")
		}
		return head, nil
	}}
	vcp := func(uri, rev string) string {
		return `"versionControlProvenance":[{"repositoryUri":"` + uri + `","revisionId":"` + rev + `"}],
"invocations":[{"endTimeUtc":"2026-10-07T12:30:00Z"}],`
	}
	one := []plugin.RepositoryTarget{{URL: "."}}
	two := []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}, {URL: "https://github.com/acme/web"}}
	for _, c := range []struct {
		name  string
		repos []plugin.RepositoryTarget
		extra string
		want  string // the commit field, or the error
		fails bool
	}{
		{"the same commit", one, vcp("https://github.com/acme/api", head), "0123456789ab", false},
		{"an abbreviated commit", one, vcp("https://github.com/acme/api", head[:10]), "0123456789ab", false},
		{"another commit", one, vcp("https://github.com/acme/api", "fedcba9876543210"), "was written for commit fedcba987654, and this run reads 0123456789ab", true},
		{"one of two repositories, by name", two, vcp("git@github.com:acme/web.git", head), "0123456789ab", false},
		{"a repository the component does not declare", two, vcp("https://github.com/acme/other", head), "states repository https://github.com/acme/other", true},
		{"a revision that cannot be resolved", []plugin.RepositoryTarget{{URL: "./broken"}}, vcp("x", head), "could not be resolved", true},
	} {
		ft := plugin.FileTarget{Path: writeFile(t, exampleLog(scoredResult, c.extra)), Component: "api", Repositories: c.repos}
		rep, err := scanner.Scan(context.Background(), ft, nil)
		if c.fails {
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := field(t, rep, "commit"); got != c.want {
			t.Errorf("%s: commit = %q, want %q", c.name, got, c.want)
		}
		if got := field(t, rep, "written"); got != "2026-10-07 12:30 UTC" {
			t.Errorf("%s: written = %q, want the run's end time", c.name, got)
		}
	}
}

func TestSARIFImportHelpers(t *testing.T) {
	if !sameCommit("ABCDEF1234", "abcdef1") || sameCommit("abcdef1", "abcdef2") || sameCommit("abc", "abcd") {
		t.Error("sameCommit compares abbreviations wrongly")
	}
	if short("0123456789abcdef") != "0123456789ab" || short("abc") != "abc" {
		t.Error("short")
	}
	for raw, want := range map[string]string{
		"https://github.com/acme/web.git": "web", "git@github.com:acme/web": "web", "./services/web/": "web",
	} {
		if got := repoName(raw); got != want {
			t.Errorf("repoName(%q) = %q, want %q", raw, got, want)
		}
	}
	info := NewSARIFImport().Info()
	if info.Name != plugin.ImportScanner || len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetFile {
		t.Errorf("info = %+v", info)
	}
}
