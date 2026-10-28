package scanners

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The unread fixtures are two runs of Semgrep 1.182.1 with the rules in unread-rules.yaml mounted
// at /rules/rules.yaml, each over one repository mounted at /src/<name>, with the argv semgrepArgs
// builds and `--timeout 1` added so the slow rules time out in a second rather than five:
//
//	semgrep scan --sarif --json-output <file> --verbose --max-target-bytes 1000000
//	  --timeout-threshold 3 --no-error --metrics=off --timeout 1 --config /rules/rules.yaml /src/<name>
//
// one holds src/big.js over the size limit with an eval in it, src/slow.js that slow-0 times out
// on, and data.json and notes.txt over the limit, which no rule reads. two holds src/big.js again,
// src/big.py over the limit, and src/many.js that slow-0, slow-1 and slow-2 time out on, after
// which Semgrep runs no further rule on it, js-eval among them.

// unreadFixture is the recorded run over repository name, with its paths moved to dir and its rule
// ids prefixed as Semgrep prefixes rules loaded from config.
func unreadFixture(t *testing.T, name, dir, config string) (sarifDoc, jsonDoc string) {
	t.Helper()
	read := func(ext string) string {
		raw, err := os.ReadFile(filepath.Join("testdata", "semgrep", "unread-"+name+ext)) // #nosec G304 -- a fixture this test names
		if err != nil {
			t.Fatal(err)
		}
		doc := strings.ReplaceAll(string(raw), "/src/"+name, dir)
		return strings.ReplaceAll(doc, "rules.", dottedPrefix(filepath.Dir(config)))
	}
	return read(".sarif"), read(".json")
}

// unreadRules copies the fixtures' rules to a directory of their own and returns the file's path.
func unreadRules(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "semgrep", "unread-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "rules", "rules.yaml")
	if err := os.MkdirAll(filepath.Dir(config), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, raw, 0o600); err != nil { // #nosec G703 -- a path under the test's own temp dir
		t.Fatal(err)
	}
	return config
}

// fakeSemgrepRepos is a Semgrep scanner whose checkout of each repository is its own directory and
// whose run prints that repository's recorded output.
func fakeSemgrepRepos(t *testing.T, config string, repos ...string) plugin.Scanner {
	t.Helper()
	dirs := map[string]string{}
	for _, r := range repos {
		dirs[r] = t.TempDir()
	}
	s := NewSemgrep().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "semgrep@1.182.1" }
	s.checkout = func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	s.run = func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		for url, d := range dirs {
			if d == dir {
				sarifDoc, jsonDoc := unreadFixture(t, url, dir, config)
				return fakeSemgrep(sarifDoc, jsonDoc, nil)(ctx, dir, argv)
			}
		}
		t.Fatalf("no recorded run for %s", dir)
		return nil, nil
	}
	return s
}

// Each file Semgrep skipped for its size or did not finish reaches the report as an unread input,
// per repository, while the findings from the files it did check stand.
func TestASkippedOrUnfinishedSemgrepFileIsReportedUnread(t *testing.T) {
	config := unreadRules(t)
	cfg := plugin.Config{"config": config}
	s := fakeSemgrepRepos(t, config, "one", "two")
	want := map[string][]sarif.Input{
		"one": {
			{Scanner: "semgrep", Repository: "one", Path: "src/big.js", Unread: "over 1 MB, not scanned"},
			{Scanner: "semgrep", Repository: "one", Path: "src/slow.js", Unread: `1 rule timed out, not checked: "slow-0"`},
		},
		"two": {
			{Scanner: "semgrep", Repository: "two", Path: "src/big.js", Unread: "over 1 MB, not scanned"},
			{Scanner: "semgrep", Repository: "two", Path: "src/big.py", Unread: "over 1 MB, not scanned"},
			{Scanner: "semgrep", Repository: "two", Path: "src/many.js",
				Unread: `3 rules timed out, other rules not run: "slow-0", "slow-1", "slow-2"`},
		},
	}
	results := map[string][]string{
		"one": {"js-eval src/ok.js", "js-eval src/slow.js"},
		"two": {"js-eval src/ok.js"},
	}
	for _, repo := range []string{"one", "two"} {
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rep.Inputs, want[repo]) {
			t.Errorf("%s: inputs\n%+v\nwant\n%+v", repo, rep.Inputs, want[repo])
		}
		var got []string
		for _, r := range rep.Results {
			got = append(got, r.RuleID+" "+r.Location.URI)
		}
		slices.Sort(got)
		if !slices.Equal(got, results[repo]) {
			t.Errorf("%s: results %v, want %v", repo, got, results[repo])
		}
	}
}

// sastController plans one scanner over every repository a component declares, with cfg.
type sastController struct {
	scanner string
	cfg     plugin.Config
}

func (c sastController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sast", Scope: plugin.ScopeComponent, DefaultScanners: []string{c.scanner}}
}

func (c sastController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, r := range comp.Repositories {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.scanner, Target: plugin.RepositoryTarget{URL: r.URL}, Config: c.cfg})
	}
	return jobs, nil
}

func (c sastController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "sast", Report: sarif.Merge(reports...)}, nil
}

// One component over both repositories: src/big.js is skipped in each, and each is reported under
// its own repository rather than folded into one.
func TestSemgrepUnreadFilesOfTwoRepositoriesStayApart(t *testing.T) {
	config := unreadRules(t)
	reg := engine.NewRegistry()
	reg.RegisterController(sastController{scanner: "semgrep", cfg: plugin.Config{"config": config}})
	reg.RegisterScanner(fakeSemgrepRepos(t, config, "one", "two"))
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"sast": {"enabled": true},
		}},
		Components: []saga.Component{{Name: "app", Repositories: []saga.Repository{{URL: "one"}, {URL: "two"}}}},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	want := []engine.InputCoverage{{
		Component: "app", Control: "sast", Scanners: []string{"semgrep"},
		Unread: []engine.UnreadInput{
			{Repository: "one", Path: "src/big.js", Reason: "over 1 MB, not scanned"},
			{Repository: "one", Path: "src/slow.js", Reason: `1 rule timed out, not checked: "slow-0"`},
			{Repository: "two", Path: "src/big.js", Reason: "over 1 MB, not scanned"},
			{Repository: "two", Path: "src/big.py", Reason: "over 1 MB, not scanned"},
			{Repository: "two", Path: "src/many.js", Reason: `3 rules timed out, other rules not run: "slow-0", "slow-1", "slow-2"`},
		},
	}}
	if !reflect.DeepEqual(res.Inputs, want) {
		t.Errorf("Inputs =\n%+v\nwant\n%+v", res.Inputs, want)
	}
}

// A run that skipped nothing and finished every file reports no inputs, so the sast control is not
// listed as having read anything either way.
func TestASemgrepRunThatFinishedEveryFileReportsNoInputs(t *testing.T) {
	got, err := semgrepUnread([]byte(noSemgrepResults), t.TempDir(), semgrepLanguages{all: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("inputs %+v, want none", got)
	}
}

// The files a deliberate exclusion left out are not unread: Semgrep was told to skip them.
func TestSemgrepUnreadIgnoresWhatSemgrepWasToldToSkip(t *testing.T) {
	doc := `{"errors":[{"type":["PartialParsing",[{"path":"a.js"}]],"rule_id":null,"path":"a.js","level":"warn"}],
		"paths":{"scanned":["a.js"],"skipped":[
			{"path":"tests/t.js","reason":"semgrepignore_patterns_match"},
			{"path":"dist/app.min.js","reason":"gitignore_patterns_match"},
			{"path":"a.js","reason":"analysis_failed_parser_or_internal_error"}]}}`
	got, err := semgrepUnread([]byte(doc), "/work", semgrepLanguages{all: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("inputs %+v, want none", got)
	}
}

func TestSemgrepTimeoutReason(t *testing.T) {
	for _, tc := range []struct {
		rules []string
		want  string
	}{
		{nil, "a rule timed out, not checked"},
		{[]string{"b"}, `1 rule timed out, not checked: "b"`},
		{[]string{"b", "a"}, `2 rules timed out, not checked: "a", "b"`},
		{[]string{"c", "b", "a", "d"}, `4 rules timed out, other rules not run: "a", "b", "c", "d"`},
	} {
		if got := semgrepTimeoutReason(tc.rules); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.rules, got, tc.want)
		}
	}
}

// A timeout entry naming no rule, or a file over the limit that also timed out, still reports the
// file, once, with every reason.
func TestSemgrepUnreadJoinsReasonsForOneFile(t *testing.T) {
	doc := `{"errors":[
			{"type":"Timeout","rule_id":"x.r1","path":"/work/a.js"},
			{"type":"Timeout","rule_id":"x.r1","path":"/work/a.js"},
			{"type":"Timeout","path":"/work/b.js"},
			{"type":"Timeout","rule_id":"x.r2"}],
		"paths":{"skipped":[{"path":"/work/a.js","reason":"too_big"}]}}`
	got, err := semgrepUnread([]byte(doc), "/work", semgrepLanguages{all: true}, []string{"x."})
	if err != nil {
		t.Fatal(err)
	}
	want := []sarif.Input{
		{Path: "a.js", Unread: `over 1 MB, not scanned, 1 rule timed out, not checked: "r1"`},
		{Path: "b.js", Unread: "a rule timed out, not checked"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("inputs\n%+v\nwant\n%+v", got, want)
	}
}

func TestSemgrepUnreadRefusesAReportThatIsNotJSON(t *testing.T) {
	if _, err := semgrepUnread([]byte("not json"), "/work", semgrepLanguages{all: true}, nil); err == nil {
		t.Error("want an error for a report that is not JSON")
	}
	sarifDoc, err := os.ReadFile(filepath.Join("testdata", "semgrep", "unread-one.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseSemgrep(semgrepReportsOf(t, sarifDoc, []byte(`{"results":[],"errors":{}}`)), "/work", plugin.Config{})
	if err == nil {
		t.Error("parseSemgrep: want an error for errors that are not a list")
	}
}

func TestSemgrepErrorType(t *testing.T) {
	for raw, want := range map[string]string{
		`"Timeout"`:                    "Timeout",
		`["PartialParsing",[{"a":1}]]`: "PartialParsing",
		`[]`:                           "",
		`{"x":1}`:                      "",
	} {
		if got := semgrepErrorType([]byte(raw)); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
}

// What the configured rules read decides which skipped files are reported: a ruleset that cannot be
// read here, or one with a rule of any language, reads every file.
func TestSemgrepRuleLanguages(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	jsOnly := write("js/rules.yaml", "rules:\n  - id: a\n    languages: [javascript, TypeScript]\n")
	write("set/py.yml", "rules:\n  - id: a\n    languages: [python]\n")
	write("set/docker.json", `{"rules":[{"id":"b","languages":["dockerfile"]}]}`)
	write("set/.hidden/any.yaml", "rules:\n  - id: c\n    languages: [regex]\n")
	write("set/README.md", "not rules")
	regex := write("regex/rules.yaml", "rules:\n  - id: a\n    languages: [python, regex]\n")
	unknown := write("unknown/rules.yaml", "rules:\n  - id: a\n    languages: [cobol]\n")
	empty := write("empty/rules.yaml", "rules: []\n")
	broken := write("broken/rules.yaml", "rules: [\n")

	for _, tc := range []struct {
		config string
		all    bool
		langs  []string
	}{
		{"p/default", true, nil},
		{"https://example.com/rules.yaml", true, nil},
		{"relative/rules.yaml", true, nil},
		{filepath.Join(dir, "missing.yaml"), true, nil},
		{jsOnly, false, []string{"js", "ts"}},
		{filepath.Join(dir, "set"), false, []string{"dockerfile", "python"}},
		{regex, true, nil},
		{unknown, true, nil},
		{empty, true, nil},
		{broken, true, nil},
	} {
		got := semgrepRuleLanguages(tc.config)
		var langs []string
		for l := range got.langs {
			langs = append(langs, l)
		}
		slices.Sort(langs)
		if got.all != tc.all || !slices.Equal(langs, tc.langs) {
			t.Errorf("%s: all %v, languages %v; want all %v, languages %v", tc.config, got.all, langs, tc.all, tc.langs)
		}
	}
}

// A file is matched to a language as Semgrep matches it: by extension, by name, or by the
// interpreter its first line names.
func TestSemgrepLanguagesReads(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bin/tool":    "#!/usr/bin/env -S node --harmony\nx()\n",
		"bin/run":     "#!/bin/bash\necho\n",
		"bin/bare":    "#!\n",
		"bin/envonly": "#!/usr/bin/env\n",
		"bin/plain":   "no shebang\n",
		"bin/empty":   "",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	js := semgrepLanguages{langs: map[string]bool{"js": true, "dockerfile": true}}
	for p, want := range map[string]bool{
		"src/app.mjs":      true,
		"src/app.py":       false,
		"Dockerfile":       true,
		"infra/Dockerfile": true,
		"bin/tool":         true,
		"bin/run":          false,
		"bin/bare":         false,
		"bin/envonly":      false,
		"bin/plain":        false,
		"bin/empty":        false,
		"bin/missing":      false,
		"../outside.js":    true,
		"../outside":       false,
		"data.json":        false,
	} {
		if got := js.reads(dir, p); got != want {
			t.Errorf("%s: reads %v, want %v", p, got, want)
		}
	}
	if !(semgrepLanguages{all: true}).reads(dir, "anything.bin") {
		t.Error("a ruleset reading every file reads anything.bin")
	}
}
