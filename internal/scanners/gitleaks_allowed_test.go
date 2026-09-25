package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gitleaksPasses answers each Gitleaks pass with a report by mode, and by whether allow comments
// were ignored, writing it to the path the pass was given. It records every command it ran.
type gitleaksPasses struct {
	reports map[string]string // "dir", "dir+all", "git", "git+all"
	calls   []string
}

func (p *gitleaksPasses) run(_ context.Context, _ string, argv []string) ([]byte, error) {
	mode := argv[1]
	if slices.Contains(argv, gitleaksIgnoreAllowArg) {
		mode += "+all"
	}
	p.calls = append(p.calls, mode)
	report, ok := p.reports[mode]
	if !ok {
		return nil, errors.New("no report for " + mode)
	}
	return nil, os.WriteFile(argv[slices.Index(argv, "--report-path")+1], []byte(report), 0o600)
}

func gitleaksVersion(v string) func(context.Context) string {
	return func(context.Context) string { return v }
}

// A secret on a line carrying `gitleaks:allow` reaches the report suppressed in source, and the
// secret Gitleaks reported arrives as it did. Two repositories, each scanned on its own, so an
// allow comment in one says nothing about the other.
func TestAnAllowedSecretArrivesSuppressedInSource(t *testing.T) {
	for _, repo := range []string{"./api", "./web"} {
		dir := t.TempDir()
		active := leak{"aws-access-token", filepath.Join(dir, repo, "app.py"), 4, "AKIAIOSFODNN7EXAMPLE"}
		allowed := leak{"aws-access-token", filepath.Join(dir, repo, "app.py"), 3, "AKIAIOSFODNN6EXAMPLE"}
		passes := &gitleaksPasses{reports: map[string]string{
			"dir":     gitleaksReport(active),
			"dir+all": gitleaksReport(allowed, active),
		}}
		s := NewGitleaks().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		s.cacheVersion = nil
		s.run = gitleaksRun(passes.run, gitleaksVersion("8.30.1"))
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(passes.calls, ",") != "dir,dir+all" {
			t.Errorf("%s: passes %v, want the tree scanned as it is and with allow comments ignored", repo, passes.calls)
		}
		if len(rep.Results) != 2 {
			t.Fatalf("%s: %d results, want the reported secret and the allowed one", repo, len(rep.Results))
		}
		for _, r := range rep.Results {
			want := strings.TrimPrefix(repo, "./") + "/app.py"
			if r.Location.URI != want || r.Repository != repo {
				t.Errorf("%s: result at %s in %s", repo, r.Location.URI, r.Repository)
			}
			switch r.Location.StartLine {
			case 4:
				if r.Suppression != nil {
					t.Errorf("%s: the secret Gitleaks reported arrived suppressed", repo)
				}
			case 3:
				if sup := r.Suppression; sup == nil || sup.Kind != "inSource" || sup.Origin != sarif.OriginTool {
					t.Errorf("%s: allowed secret suppression %+v, want a directive in the file", repo, sup)
				}
			default:
				t.Errorf("%s: unexpected result at line %d", repo, r.Location.StartLine)
			}
		}
	}
}

// An allow comment added to a line after its secret was committed covers the tree, and the commit
// that introduced the secret without it is still reported, as its own finding.
func TestAnAllowCommentDoesNotCoverTheCommitThatIntroducedTheSecret(t *testing.T) {
	dir := t.TempDir()
	secret := leak{"generic-api-key", filepath.Join(dir, "settings.py"), 3, "live-key"}
	introduced := leak{"generic-api-key", "settings.py", 3, "live-key"}
	passes := &gitleaksPasses{reports: map[string]string{
		"dir":     gitleaksReport(),
		"dir+all": gitleaksReport(secret),
		"git":     gitleaksReport(introduced),
		"git+all": gitleaksReport(introduced),
	}}
	s := NewGitleaks().(repoScanner)
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	s.cacheVersion = nil
	s.run = gitleaksRun(passes.run, gitleaksVersion("8.30.1"))
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "./api"}, plugin.Config{"history": true})
	if err != nil {
		t.Fatal(err)
	}
	var tree, history int
	for _, r := range rep.Results {
		switch {
		case r.Historical && r.Suppression == nil:
			history++
		case !r.Historical && r.Suppression != nil && r.Suppression.Origin == sarif.OriginTool:
			tree++
		default:
			t.Errorf("unexpected result %+v", r)
		}
	}
	if tree != 1 || history != 1 {
		t.Errorf("tree %d history %d, want the allowed line and the commit that introduced it", tree, history)
	}
}

// A Gitleaks without --ignore-gitleaks-allow, or one whose version cannot be read, runs each pass
// once and its report is handed through as written.
func TestAnOlderGitleaksRunsEachPassOnce(t *testing.T) {
	for _, v := range []string{"8.18.0", ""} {
		dir := t.TempDir()
		path := filepath.Join(dir, "report.sarif")
		passes := &gitleaksPasses{reports: map[string]string{"dir": gitleaksReport(leak{"a", "x", 1, "s"})}}
		argv := []string{"gitleaks", "dir", dir, "--report-path", path}
		if _, err := gitleaksRun(passes.run, gitleaksVersion(v))(context.Background(), dir, argv); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(path) // #nosec G304 -- a path under the test's own temporary directory
		if len(passes.calls) != 1 || string(got) != passes.reports["dir"] {
			t.Errorf("version %q: passes %v, report %s", v, passes.calls, got)
		}
	}
}

// A second run that fails, or a report either run leaves unreadable, is the error: the scan is not
// read as having no allowed secrets.
func TestAGitleaksRunWhoseAllowedSecretsCannotBeReadFails(t *testing.T) {
	good := gitleaksReport(leak{"a", "x", 1, "s"})
	for name, reports := range map[string]map[string]string{
		"second run fails":          {"dir": good},
		"second report unreadable":  {"dir": good, "dir+all": "not json"},
		"first report unreadable":   {"dir": "not json", "dir+all": good},
		"a result that is no shape": {"dir": good, "dir+all": `{"runs":[{"results":["x"]}]}`},
	} {
		dir := t.TempDir()
		argv := []string{"gitleaks", "dir", dir, "--report-path", filepath.Join(dir, "report.sarif")}
		passes := &gitleaksPasses{reports: reports}
		if _, err := gitleaksRun(passes.run, gitleaksVersion("8.30.1"))(context.Background(), dir, argv); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// The first run failing is Gitleaks' own error, and nothing runs after it.
	passes := &gitleaksPasses{}
	argv := []string{"gitleaks", "dir", "/tree", "--report-path", "/nonexistent/report.sarif"}
	if _, err := gitleaksRun(passes.run, gitleaksVersion("8.30.1"))(context.Background(), "/tree", argv); err == nil || len(passes.calls) != 1 {
		t.Errorf("err %v after %v, want the first run's error alone", err, passes.calls)
	}
}

// A secret written twice on one line and allowed once is added once, and a report the second run
// adds nothing to is returned as it was.
func TestWithGitleaksAllowedCountsWhatItMatches(t *testing.T) {
	twice := leak{"a", "x", 1, "s"}
	reported := gitleaksReport(twice)
	out, err := withGitleaksAllowed([]byte(reported), []byte(gitleaksReport(twice, twice)))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 || rep.Results[0].Suppression != nil || rep.Results[1].Suppression == nil {
		t.Errorf("results %+v, want the reported one and one allowed copy", rep.Results)
	}
	if out, err := withGitleaksAllowed([]byte(reported), []byte(reported)); err != nil || string(out) != reported {
		t.Errorf("out %s err %v, want the report untouched", out, err)
	}
}
