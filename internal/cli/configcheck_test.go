package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/config"
)

// configHome points HOME at a fresh directory holding ~/.draugr/config.yaml with body, or none when
// body is empty, and clears DRAUGR_CONFIG so the discovered files are the ones read.
func configHome(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(config.EnvVar, "")
	if body != "" {
		if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".draugr", "config.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// `config set` refuses what `draugr validate` refuses in a descriptor, in the same words, and
// writes nothing.
func TestConfigSetRefusesWhatValidateRefuses(t *testing.T) {
	for _, c := range []struct{ key, value, want string }{
		{"controls.sats.semgrep.config", "x",
			`controls: "sats" is not a control this build of Draugr provides, did you mean "sast"?`},
		// The older spelling is held to the same checks, reported under the name it loads as.
		{"controllers.sats.semgrep.config", "x",
			`controls: "sats" is not a control this build of Draugr provides, did you mean "sast"?`},
		{"controls.secrets.gitleakz.foo", "x",
			`controls.secrets: "gitleakz" is not a scanner of the "secrets" control`},
		{"controls.secrets.gitleakz.foo", "x", `did you mean "gitleaks"?`},
		{"controls.sca.trivy-fs.pkgTypes", "x", `"trivy-fs" is not a scanner of the "sca" control`},
		{"controls.sca.trivy-fs.pkgTypes", "x", `did you mean "trivyFs"?`},
		{"controls.sca.trivyFs.pkgTypes", "library", `controls.sca.trivyFs: `},
		{"controls.sca.trivyFs.pkgTypes", "[library, 5]", `controls.sca.trivyFs: `},
		{"tools.trivvy.version", "1.0.0",
			`tools: "trivvy" is not a tool this build of Draugr installs, did you mean "trivy"?`},
		{"output.top", "-5", `output.top: expected a whole number of 0 or more, got -5`},
		{"output.view", "banana", `output.view: "banana" is not findings, actions or compact`},
		{"output.view", "actoins", `did you mean "actions"?`},
		{"cache.ttl", "-1h", `cache.ttl: expected a duration of 0s or more, got -1h`},
		{"cache.ttl", "5", `cache.ttl: expected a duration such as 12h, got 5`},
		{"output.veiw", "x", `output: "veiw" is not a setting Draugr has, did you mean "view"?`},
		{"scan.jobs", "-2", `scan.jobs: expected a whole number of 0 or more, got -2`},
		{"scan.jobs", "many", `scan.jobs: expected a whole number, got many`},
		{"log.level", "verbose", `log.level: "verbose" is not trace, debug, info, warn or error`},
		{"log.level", "debgu", `log.level: "debgu" is not trace, debug, info, warn or error, did you mean "debug"?`},
		{"log.format", "jsno", `log.format: "jsno" is not console, json or text, did you mean "json"?`},
		{"log.levl", "debug", `log: "levl" is not a setting Draugr has, did you mean "level"?`},
		{"output.tips", "sometimes", `output.tips: expected true or false, got sometimes`},
		{"offline", "maybe", `offline: expected true or false, got maybe`},
	} {
		dir := t.TempDir()
		configHome(t, "")
		out, err := runConfig(t, dir, "set", "--", c.key, c.value)
		if err == nil {
			t.Errorf("set %s %s was accepted: %s", c.key, c.value, out)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing was written") {
			t.Errorf("set %s %s:\n%v\nwant %q", c.key, c.value, err, c.want)
		}
		if strings.Contains(err.Error(), "init --force") {
			t.Errorf("set %s %s offered to wipe a file it never wrote: %v", c.key, c.value, err)
		}
		// The list of keys answers a key the file cannot hold, not a value it refuses.
		keyProblem := strings.HasPrefix(c.key, "tools.") || c.key == "output.veiw" || c.key == "log.levl"
		if hinted := strings.Contains(err.Error(), config.KeysURL); hinted != keyProblem {
			t.Errorf("set %s %s: keys hint present = %v:\n%v", c.key, c.value, hinted, err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, config.FileName)); !os.IsNotExist(statErr) {
			t.Errorf("set %s %s wrote the file despite refusing", c.key, c.value)
		}
	}
}

// `config validate` checks every file rather than stopping at the first, and names each problem.
func TestConfigValidateChecksEveryFile(t *testing.T) {
	configHome(t, "tools:\n  trivvy:\n    version: \"1\"\n")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, config.FileName),
		[]byte("output:\n  view: banana\ncontrollers:\n  sats: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfig(t, dir, "validate")
	if err == nil || err.Error() != "2 of 2 files did not validate" {
		t.Errorf("err = %v, want both files counted", err)
	}
	for _, want := range []string{
		"✗ ~/.draugr/config.yaml",
		`tools: "trivvy" is not a tool this build of Draugr installs, did you mean "trivy"?`,
		`controls: "sats" is not a control this build of Draugr provides, did you mean "sast"?`,
		`output.view: "banana" is not findings, actions or compact`,
		"run `draugr controls` to see what this build provides",
		config.KeysURL,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestConfigValidateNamedFiles(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("output:\n  evidence: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")
	out, err := runConfig(t, dir, "validate", good, missing)
	if err == nil || err.Error() != "1 of 2 files did not validate" {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(out, "✓ ./good.yaml") || !strings.Contains(out, "✗ ./missing.yaml") {
		t.Errorf("each file should be reported:\n%s", out)
	}
}

// The user's file sets true and 12h, the project's sets false and 0s, through `config set` as
// somebody would. The project wins every key except the one-way settings, and `set` says so for
// those instead of printing a bare `wrote`.
func TestConfigSetReportsAOneWaySettingItCannotTurnOff(t *testing.T) {
	configHome(t, "output:\n  evidence: true\ncache:\n  ttl: 12h\n  readOnly: true\n")
	dir := t.TempDir()

	out, err := runConfig(t, dir, "set", "cache.readOnly", "false")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "overridden: cache.readOnly stays true; ~/.draugr/config.yaml sets it\n") {
		t.Errorf("set did not report the override:\n%s", out)
	}
	if strings.Contains(out, oneWayRule) {
		t.Errorf("set repeated the rule `show` states:\n%s", out)
	}
	for _, kv := range [][2]string{{"output.evidence", "false"}, {"cache.ttl", "0s"}} {
		out, err := runConfig(t, dir, "set", kv[0], kv[1])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "overridden") {
			t.Errorf("set %s %s reported an override that does not exist:\n%s", kv[0], kv[1], out)
		}
		got, err := runConfig(t, dir, "get", kv[0])
		if err != nil || strings.TrimSpace(got) != kv[1] {
			t.Errorf("get %s = %q %v, want the project's %s", kv[0], got, err, kv[1])
		}
	}

	out, err = runConfig(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	// The Files list names the files as the tables do: under the working directory relative to
	// it, and under the home directory by ~.
	if !strings.Contains(out, "Files, least specific first:\n  ~/.draugr/config.yaml\n  ./draugr.config.yaml\n") {
		t.Errorf("the Files list does not name both files as the tables do:\n%s", out)
	}
	// Columns are padded to the widest cell, so rows are compared with their spacing collapsed.
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"Overridden:",
		"cache.readOnly false ./draugr.config.yaml ~/.draugr/config.yaml",
		"cache.readOnly true ~/.draugr/config.yaml",
		"output.evidence false ./draugr.config.yaml",
		oneWayRule,
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
}

// What a scan does with the files above: the project's false and 0s reach the options, the
// one-way true stays.
func TestAScanAppliesTheProjectsFalseAndZero(t *testing.T) {
	configHome(t, "output:\n  evidence: true\ncache:\n  ttl: 12h\n  readOnly: true\n")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, config.FileName),
		[]byte("output:\n  evidence: false\ncache:\n  ttl: 0s\n  readOnly: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := scanOptions{evidence: true, cacheTTL: 24 * time.Hour, setFlags: map[string]bool{}}
	outputOptionsFrom(&opts, res.File.Output)
	cacheOptionsFrom(&opts, res.File.Cache)
	if opts.evidence {
		t.Error("output.evidence: the project's false did not reach the scan")
	}
	if opts.cacheTTL != 0 {
		t.Errorf("cache.ttl = %v, want the project's 0s (no expiry)", opts.cacheTTL)
	}
	if !opts.cacheReadOnly {
		t.Error("cache.readOnly: the user's true was turned off")
	}
}

// Run from a directory with no project file, `config show` says which directory it looked in, so a
// run from a parent directory does not read as a project with no settings.
func TestConfigShowNamesTheDirectoryItSearched(t *testing.T) {
	configHome(t, "output:\n  top: 5\n")
	parent := t.TempDir()
	notice := "No " + config.FileName + " in " + parent + " (the working directory)."

	out, err := runConfig(t, parent, "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, notice) {
		t.Errorf("show did not name the directory it searched:\n%s", out)
	}

	// Nothing configured anywhere: still said, beside the built-in defaults.
	configHome(t, "")
	if out, _ = runConfig(t, parent, "show"); !strings.Contains(out, notice) {
		t.Errorf("show with no files did not name the directory it searched:\n%s", out)
	}

	// A project file there: listed, and no notice.
	if err := os.WriteFile(filepath.Join(parent, config.FileName), []byte("output:\n  top: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, _ = runConfig(t, parent, "show"); strings.Contains(out, "(the working directory)") {
		t.Errorf("a project file was found and the notice still printed:\n%s", out)
	}

	// An explicit file is read alone, so nothing was searched for and nothing is said about it.
	t.Setenv(config.EnvVar, filepath.Join(parent, config.FileName))
	if out, _ = runConfig(t, t.TempDir(), "show"); strings.Contains(out, "(the working directory)") {
		t.Errorf("an explicit file still produced the notice:\n%s", out)
	}
}

// A key the file cannot hold and a control this build does not provide are reported in one pass,
// with both places to look next.
func TestParseConfigReportsParseAndRegistryProblemsTogether(t *testing.T) {
	_, err := parseConfig(builtins.Registry(), "x.yaml",
		[]byte("output:\n  veiw: actions\ncontrols:\n  sats: {}\n"))
	var p *config.Problems
	if !errors.As(err, &p) {
		t.Fatalf("want *config.Problems, got %v", err)
	}
	want := []string{
		`output: "veiw" is not a setting Draugr has, did you mean "view"?`,
		`controls: "sats" is not a control this build of Draugr provides, did you mean "sast"?`,
	}
	if strings.Join(p.List, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems = %q, want %q", p.List, want)
	}
	if !strings.Contains(p.Hint, "draugr controls") || !strings.Contains(p.Hint, config.KeysURL) {
		t.Errorf("hint = %q, want both", p.Hint)
	}
}

func TestLoadConfigReportsAMissingExplicitFile(t *testing.T) {
	configHome(t, "")
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	t.Setenv(config.EnvVar, missing)
	if _, err := loadConfig(t.TempDir()); err == nil || !strings.Contains(err.Error(), "read "+missing) {
		t.Errorf("want the missing file named, got %v", err)
	}
}

func TestToolProblemsWithNothingClose(t *testing.T) {
	got := toolProblems(map[string]config.ToolSettings{"zzzzzzzzzz": {}, "trivy": {}})
	if len(got) != 1 || got[0] != "tools: \"zzzzzzzzzz\" is not a tool this build of Draugr installs (`draugr tools list` names them)" {
		t.Errorf("got %q", got)
	}
}

func TestCheckConfigAcceptsAValidFile(t *testing.T) {
	f := config.File{
		Tools:   map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}},
		Output:  config.OutputSettings{View: "actions", Top: 5, Tips: new(false)},
		Cache:   config.CacheSettings{TTL: new(time.Duration)},
		Scan:    config.ScanSettings{Jobs: new(0)},
		Log:     config.LogSettings{Level: "warn", Format: "json"},
		Offline: new(true),
	}
	if err := checkConfig(builtins.Registry(), "x.yaml", f); err != nil {
		t.Errorf("a valid file was refused: %v", err)
	}
}

func TestProblemLinesAndHintForAnotherKindOfError(t *testing.T) {
	err := errors.New("read x.yaml: permission denied")
	if got := problemLines(err); got != "  read x.yaml: permission denied" {
		t.Errorf("problemLines = %q", got)
	}
	if got := problemHint(err); got != "" {
		t.Errorf("problemHint = %q, want none", got)
	}
}

// A file with two mistakes is mended one `unset` at a time: each edit adds no problem, so each is
// written, and `set` says how many are left until none are.
func TestConfigUnsetMendsABrokenFileOneKeyAtATime(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte("controllers:\n  sats: {}\ntools:\n  trivvy:\n    version: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runConfig(t, dir, "unset", "controllers.sats")
	if err != nil {
		t.Fatalf("an edit that adds no problem was refused: %v", err)
	}
	if !strings.Contains(out, "still has 1 problem; `draugr config validate` lists them") {
		t.Errorf("the problem left was not said:\n%s", out)
	}
	// An edit that neither adds nor removes one is written too.
	if _, err := runConfig(t, dir, "set", "output.view", "actions"); err != nil {
		t.Fatalf("an edit beside an existing problem was refused: %v", err)
	}

	out, err = runConfig(t, dir, "unset", "tools.trivvy")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "still has") {
		t.Errorf("a file with no problems left was reported as having some:\n%s", out)
	}
	if out, err := runConfig(t, dir, "validate"); err != nil {
		t.Errorf("the mended file does not validate: %v\n%s", err, out)
	}
}

// An edit that adds a problem is refused even when the file had one already, and the refusal names
// only the problem the edit would add.
func TestConfigSetRefusesAnEditThatAddsAProblem(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	path := filepath.Join(dir, config.FileName)
	before := []byte("tools:\n  trivvy:\n    version: \"1\"\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := runConfig(t, dir, "set", "output.view", "banana")
	if err == nil {
		t.Fatal("an edit that adds a problem was written")
	}
	if !strings.Contains(err.Error(), "that edit would add a problem to the file, so nothing was written:\n  "+
		`output.view: "banana" is not findings, actions or compact`) {
		t.Errorf("the added problem is not named: %v", err)
	}
	if strings.Contains(err.Error(), "trivvy") {
		t.Errorf("the refusal named a problem the file already had: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(before) { // #nosec G304 -- this test's own temp file
		t.Errorf("the file changed despite the refusal:\n%s", got)
	}
}

func TestAddedProblemsTreatsAnotherErrorAsNew(t *testing.T) {
	if got := addedProblems(nil, errors.New("boom")); len(got) != 1 || got[0] != "boom" {
		t.Errorf("got %q", got)
	}
}

// The file takes the spellings the schema completes, exactly. A case slip names the spelling it meant,
// since the flags accept it and somebody copying a command line into the file will make it.
func TestConfigLogSettingsTakeTheSchemasSpelling(t *testing.T) {
	f := config.File{Log: config.LogSettings{Level: "WARN", Format: "Json"}}
	err := checkConfig(builtins.Registry(), "x.yaml", f)
	if err == nil {
		t.Fatal("an upper-case level and format were accepted")
	}
	for _, want := range []string{
		`log.level: "WARN" is not trace, debug, info, warn or error, did you mean "warn"?`,
		`log.format: "Json" is not console, json or text, did you mean "json"?`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}
