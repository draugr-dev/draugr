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
	if slices.Contains(argv, gitleaksIgnorePathArg) {
		mode += "+noignore"
	}
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

// withoutLog gives a fake pass that writes only a report the shape of the tree pass's exec, with
// a log that names nothing.
func withoutLog(run func(context.Context, string, []string) ([]byte, error)) func(context.Context, string, []string) ([]byte, []byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, []byte, error) {
		out, err := run(ctx, dir, argv)
		return out, nil, err
	}
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
		s.runLogged = gitleaksTree(withoutLog(passes.run), gitleaksVersion("8.30.1"))
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
	secret := leak{"generic-api-key", "settings.py", 3, "live-key"}
	introduced := leak{"generic-api-key", "settings.py", 3, "live-key"}
	// Gitleaks names the commit in a history finding's message, as "… at commit <sha>.", which is
	// what keeps it apart from the tree's finding at the same path and line.
	committed := strings.Replace(gitleaksReport(introduced), " detected", " detected at commit abc123", 1)
	passes := &gitleaksPasses{reports: map[string]string{
		"dir":     gitleaksReport(),
		"dir+all": gitleaksReport(secret),
		"git":     committed,
		"git+all": committed,
	}}
	s := NewGitleaks().(repoScanner)
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	s.cacheVersion = nil
	s.run = gitleaksRun(passes.run, gitleaksVersion("8.30.1"))
	s.runLogged = gitleaksTree(withoutLog(passes.run), gitleaksVersion("8.30.1"))
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

// A secret a .gitleaksignore entry covers reaches the report suppressed as the scanner's own
// exclusion, beside an allow comment's and the secret Gitleaks reported. The run that puts the file
// out of reach names the checkout by its absolute path, and its findings compare as the others do.
func TestASecretTheGitleaksignoreFileCoversArrivesSuppressedByTheScanner(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte("app.py:aws-access-token:2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	active := leak{"aws-access-token", "app.py", 4, "AKIAIOSFODNN7EXAMPLE"}
	ignored := leak{"aws-access-token", filepath.Join(dir, "app.py"), 2, "AKIAIOSFODNN5EXAMPLE"}
	activeAbs := leak{"aws-access-token", filepath.Join(dir, "app.py"), 4, "AKIAIOSFODNN7EXAMPLE"}
	allowedAbs := leak{"aws-access-token", filepath.Join(dir, "app.py"), 3, "AKIAIOSFODNN6EXAMPLE"}
	passes := &gitleaksPasses{reports: map[string]string{
		"dir":              gitleaksReport(active),
		"dir+noignore":     gitleaksReport(ignored, activeAbs),
		"dir+noignore+all": gitleaksReport(ignored, allowedAbs, activeAbs),
	}}
	s := NewGitleaks().(repoScanner)
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	s.cacheVersion = nil
	s.runLogged = gitleaksTree(withoutLog(passes.run), gitleaksVersion("8.30.1"))
	rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "./api"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(passes.calls, ","); got != "dir,dir+noignore,dir+noignore+all" {
		t.Errorf("passes %s, want the tree as it is, with the file out of reach, then with allow comments ignored too", got)
	}
	byLine := map[int]*sarif.Suppression{}
	for _, r := range rep.Results {
		if r.Location.URI != "app.py" {
			t.Errorf("result at %q, want app.py", r.Location.URI)
		}
		byLine[r.Location.StartLine] = r.Suppression
	}
	if len(byLine) != 3 {
		t.Fatalf("%d results, want the reported secret, the ignored one and the allowed one", len(rep.Results))
	}
	if sup := byLine[4]; sup != nil {
		t.Errorf("the reported secret arrived suppressed: %+v", sup)
	}
	if sup := byLine[2]; sup == nil || sup.Kind != "external" || sup.Origin != sarif.OriginScanner {
		t.Errorf("the ignored secret: %+v, want the scanner's own exclusion", sup)
	}
	if sup := byLine[3]; sup == nil || sup.Kind != "inSource" || sup.Origin != sarif.OriginTool {
		t.Errorf("the allowed secret: %+v, want a directive in the file", sup)
	}
}

// The file is put out of reach only where Gitleaks can be pointed at the same tree without it: the
// checkout's own path for the tree, its .git directory for history. A checkout whose .git is a file,
// as a linked worktree's is, and an argv not of Draugr's shape, have no such path.
func TestTheGitleaksignoreFileIsPutOutOfReachOnlyWhereThereIsAPath(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.WriteFile(filepath.Join(linked, ".git"), []byte("gitdir: elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, dir string
		argv      []string
		source    string
	}{
		{"tree", repo, []string{"gitleaks", "dir", ".", "--no-banner"}, repo},
		{"history", repo, []string{"gitleaks", "git", ".", "--no-banner"}, filepath.Join(repo, ".git")},
		{"history in a linked worktree", linked, []string{"gitleaks", "git", ".", "--no-banner"}, ""},
		{"a source already named", repo, []string{"gitleaks", "dir", repo}, ""},
		{"another mode", repo, []string{"gitleaks", "stdin", "."}, ""},
	} {
		got, ok := gitleaksIgnoreOutOfReach(c.argv, c.dir, "/empty")
		if c.source == "" {
			if ok {
				t.Errorf("%s: %v, want no run", c.name, got)
			}
			continue
		}
		if !ok || got[2] != c.source || !slices.Equal(got[len(got)-2:], []string{gitleaksIgnorePathArg, "/empty"}) {
			t.Errorf("%s: %v, want source %s and the empty ignore path", c.name, got, c.source)
		}
	}
}
