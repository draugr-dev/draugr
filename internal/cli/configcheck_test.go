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
		{"controllers.sats.semgrep.config", "x",
			`controllers: "sats" is not a control this build of Draugr provides, did you mean "sast"?`},
		{"controllers.secrets.gitleakz.foo", "x",
			`controllers.secrets: "gitleakz" is not a scanner of the "secrets" control`},
		{"controllers.secrets.gitleakz.foo", "x", `did you mean "gitleaks"?`},
		{"controllers.sca.trivy-fs.pkgTypes", "x", `"trivy-fs" is not a scanner of the "sca" control`},
		{"controllers.sca.trivy-fs.pkgTypes", "x", `did you mean "trivyFs"?`},
		{"controllers.sca.trivyFs.pkgTypes", "library", `controllers.sca.trivyFs: `},
		{"tools.trivvy.version", "1.0.0",
			`tools: "trivvy" is not a tool this build of Draugr installs, did you mean "trivy"?`},
		{"output.top", "-5", `output.top: expected a whole number of 0 or more, got -5`},
		{"output.view", "banana", `output.view: "banana" is not findings, actions or compact`},
		{"output.view", "actoins", `did you mean "actions"?`},
		{"cache.ttl", "-1h", `cache.ttl: expected a duration of 0s or more, got -1h0m0s`},
		{"cache.ttl", "5", `cache.ttl: expected a duration such as 12h, got 5`},
		{"output.veiw", "x", `output: "veiw" is not a setting Draugr has, did you mean "view"?`},
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
		`controllers: "sats" is not a control this build of Draugr provides, did you mean "sast"?`,
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
	if !strings.Contains(out, "✓ "+good) || !strings.Contains(out, "✗ "+missing) {
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
	if !strings.Contains(out, "overridden: cache.readOnly stays true, set by ~/.draugr/config.yaml") {
		t.Errorf("set did not report the override:\n%s", out)
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
	project := filepath.Join(dir, config.FileName)
	// Columns are padded to the widest cell, so rows are compared with their spacing collapsed.
	out = strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"Overridden:",
		"cache.readOnly false " + project + " ~/.draugr/config.yaml",
		"cache.readOnly true ~/.draugr/config.yaml",
		"output.evidence false " + project,
		oneWayRule,
	} {
		if !strings.Contains(out, want) {
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

// A key the file cannot hold and a control this build does not provide are reported in one pass,
// with both places to look next.
func TestParseConfigReportsParseAndRegistryProblemsTogether(t *testing.T) {
	_, err := parseConfig(builtins.Registry(), "x.yaml",
		[]byte("output:\n  veiw: actions\ncontrollers:\n  sats: {}\n"))
	var p *config.Problems
	if !errors.As(err, &p) {
		t.Fatalf("want *config.Problems, got %v", err)
	}
	want := []string{
		`output: "veiw" is not a setting Draugr has, did you mean "view"?`,
		`controllers: "sats" is not a control this build of Draugr provides, did you mean "sast"?`,
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
		Tools:  map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}},
		Output: config.OutputSettings{View: "actions", Top: 5},
		Cache:  config.CacheSettings{TTL: new(time.Duration)},
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
