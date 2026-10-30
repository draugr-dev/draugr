package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// projectBeside is a fresh directory holding ./draugr.config.yaml with body, leaving HOME and the
// working directory as they are, so the user file a test wrote stays the one read beside it.
func projectBeside(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runRoot runs a whole command line from dir, through the root command's startup, and returns what
// it printed to stdout and the buffer the logger it started with writes to.
//
// The logger and the network policy are the process's own, so both are put back afterwards.
func runRoot(t *testing.T, dir string, args ...string) (string, *bytes.Buffer, error) {
	t.Helper()
	t.Chdir(dir)
	prev, prevConfig := slog.Default(), rootConfigPath
	t.Cleanup(func() {
		slog.SetDefault(prev)
		rootConfigPath = prevConfig
		netpolicy.Decide(nil, "")
	})
	root := newRootCommand()
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), &stderr, err
}

// lineWith is the line of s that holds want, or "".
func lineWith(s, want string) string {
	for line := range strings.Lines(s) {
		if strings.Contains(line, want) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// Each key is refused for a value its flag refuses, in the shape the keys beside it use, and from
// either file.
func TestConfigValidateRefusesABadMachineValueInEitherFile(t *testing.T) {
	configHome(t, "log:\n  level: verbose\n  format: jsno\n")
	dir := projectBeside(t, "scan:\n  jobs: -1\n")

	out, err := runConfig(t, dir, "validate")
	if err == nil || err.Error() != "2 of 2 files did not validate" {
		t.Errorf("err = %v, want both files counted", err)
	}
	for _, want := range []string{
		"✗ ~/.draugr/config.yaml",
		`log.level: "verbose" is not trace, debug, info, warn or error`,
		`log.format: "jsno" is not console, json or text, did you mean "json"?`,
		"✗ ./draugr.config.yaml",
		"scan.jobs: expected a whole number of 0 or more, got -1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// Every problem is a value, and each line already says what the key takes.
	if strings.Contains(out, config.KeysHint) {
		t.Errorf("the list of keys was offered for values, not keys:\n%s", out)
	}
}

// `show` names the file each machine setting came from, two files deep, and lists the project's
// offline: false under Overridden with the file that outranks it.
func TestConfigShowNamesEachMachineSettingAndItsFile(t *testing.T) {
	configHome(t, "scan:\n  jobs: 4\nlog:\n  format: json\noutput:\n  tips: true\noffline: true\n")
	dir := projectBeside(t, "log:\n  level: debug\noutput:\n  tips: false\n")

	out, err := runConfig(t, dir, "set", "offline", "false")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "overridden: offline stays true; ~/.draugr/config.yaml sets it\n") {
		t.Errorf("set did not report that offline stays on:\n%s", out)
	}

	out, err = runConfig(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"scan.jobs 4 ~/.draugr/config.yaml",
		"log.format json ~/.draugr/config.yaml",
		"log.level debug ./draugr.config.yaml",
		"output.tips false ./draugr.config.yaml",
		"offline true ~/.draugr/config.yaml",
		"Overridden:",
		"offline false ./draugr.config.yaml ~/.draugr/config.yaml",
		"cache.readOnly, cache.requireDigest and offline only turn on across files.",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}

	for key, want := range map[string]string{
		"scan.jobs": "4", "log.format": "json", "log.level": "debug", "output.tips": "false", "offline": "true",
	} {
		got, err := runConfig(t, dir, "get", key)
		if err != nil || strings.TrimSpace(got) != want {
			t.Errorf("get %s = %q %v, want %s", key, got, err, want)
		}
	}
}

// Each key is written, read back as resolved, and removed, by the commands that edit the file.
func TestConfigSetsAndUnsetsEachMachineSetting(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	for key, value := range map[string]string{
		"scan.jobs": "3", "log.level": "debug", "log.format": "text", "output.tips": "false", "offline": "true",
	} {
		if out, err := runConfig(t, dir, "set", key, value); err != nil {
			t.Fatalf("set %s %s: %v\n%s", key, value, err, out)
		}
		if got, err := runConfig(t, dir, "get", key); err != nil || strings.TrimSpace(got) != value {
			t.Errorf("get %s = %q %v, want %s", key, got, err, value)
		}
		if out, err := runConfig(t, dir, "unset", key); err != nil {
			t.Errorf("unset %s: %v\n%s", key, err, out)
		}
		if _, err := runConfig(t, dir, "get", key); err == nil || !strings.Contains(err.Error(), "is not set") {
			t.Errorf("get %s after unset: %v", key, err)
		}
	}
}

// scan.jobs reaches the engine from the more specific file, and a typed --jobs wins over both,
// 0 included.
func TestAScanRunsTheConfiguredJobs(t *testing.T) {
	configHome(t, "scan:\n  jobs: 5\n")
	dir := projectBeside(t, "scan:\n  jobs: 3\n")
	t.Chdir(dir)

	concurrency := func(opts scanOptions) string {
		t.Helper()
		opts.failOn, opts.format = "error", "json"
		var buf bytes.Buffer
		if err := runScan(context.Background(), writeSaga(t, sagaWithImage), opts, fakeRegistry(sarif.LevelNote), &buf); err != nil {
			t.Fatal(err)
		}
		return lineWith(buf.String(), `"concurrency"`)
	}
	if got := concurrency(scanOptions{}); got != `"concurrency": 3,` {
		t.Errorf("with no flag, %s; want the project's 3", got)
	}
	if got := concurrency(scanOptions{jobs: 1, setFlags: map[string]bool{"jobs": true}}); got != `"concurrency": 1,` {
		t.Errorf("with --jobs 1, %s; want the flag's 1", got)
	}

	opts := scanOptions{jobs: 0, setFlags: map[string]bool{"jobs": true}}
	scanSettingsFrom(&opts, config.ScanSettings{Jobs: new(4)})
	if opts.jobs != 0 {
		t.Errorf("--jobs 0 was overridden by the configuration: jobs = %d", opts.jobs)
	}
	opts = scanOptions{jobs: 7}
	scanSettingsFrom(&opts, config.ScanSettings{})
	if opts.jobs != 7 {
		t.Errorf("a file that sets no jobs changed them to %d", opts.jobs)
	}
}

// Tips are decided by the first source that answers: --no-tips as typed, then DRAUGR_NO_TIPS, then
// output.tips across both files.
func TestTipsFollowTheFlagThenTheEnvironmentThenTheFiles(t *testing.T) {
	slow := engine.Result{Stats: engine.Stats{Duration: 3 * time.Minute}}
	shown := func(opts *scanOptions, cfg config.OutputSettings) bool {
		t.Helper()
		outputOptionsFrom(opts, cfg)
		on := scanSuggestions(tips(unclassifiedModel(), slow, opts)) != nil
		if on == opts.tipsOff() {
			t.Errorf("the tips and tipsOff disagree: tips shown = %v, tipsOff = %v", on, opts.tipsOff())
		}
		return on
	}

	configHome(t, "output:\n  tips: false\n")
	res, err := loadConfig(projectBeside(t, "output:\n  view: actions\n"))
	if err != nil {
		t.Fatal(err)
	}
	if shown(&scanOptions{format: "console"}, res.File.Output) {
		t.Error("the user's tips: false did not survive a project file that does not mention it")
	}
	configHome(t, "output:\n  tips: false\n")
	if res, err = loadConfig(projectBeside(t, "output:\n  tips: true\n")); err != nil {
		t.Fatal(err)
	}
	if !shown(&scanOptions{format: "console"}, res.File.Output) {
		t.Error("the project's tips: true did not override the user's false")
	}

	typedOn := map[string]bool{"no-tips": true}
	if !shown(&scanOptions{format: "console", setFlags: typedOn}, config.OutputSettings{Tips: new(false)}) {
		t.Error("--no-tips=false lost to output.tips: false")
	}
	if shown(&scanOptions{format: "console", noTips: true, setFlags: typedOn}, config.OutputSettings{Tips: new(true)}) {
		t.Error("--no-tips lost to output.tips: true")
	}

	t.Setenv("DRAUGR_NO_TIPS", "1")
	if shown(&scanOptions{format: "console"}, config.OutputSettings{Tips: new(true)}) {
		t.Error("DRAUGR_NO_TIPS lost to output.tips: true")
	}
	if !shown(&scanOptions{format: "console", setFlags: typedOn}, config.OutputSettings{}) {
		t.Error("--no-tips=false lost to DRAUGR_NO_TIPS")
	}
}

// The root command starts its logger from log.level and log.format, the project's over the
// user's, and a typed flag over both.
func TestTheRootCommandStartsWithTheConfiguredLog(t *testing.T) {
	configHome(t, "log:\n  level: error\n  format: text\n")
	dir := projectBeside(t, "log:\n  level: debug\n  format: json\n")

	_, stderr, err := runRoot(t, dir, "version")
	if err != nil {
		t.Fatal(err)
	}
	slog.Debug("probe")
	var rec map[string]any
	if err := json.Unmarshal([]byte(lineWith(stderr.String(), "probe")), &rec); err != nil ||
		rec["level"] != "DEBUG" || rec["msg"] != "probe" {
		t.Errorf("the project's debug and json did not reach the logger: %q", stderr.String())
	}

	// The user's file alone, from a directory with no project file.
	_, stderr, err = runRoot(t, t.TempDir(), "version")
	if err != nil {
		t.Fatal(err)
	}
	slog.Warn("hidden")
	slog.Error("shown")
	if got := stderr.String(); strings.Contains(got, "hidden") || !strings.Contains(got, "level=ERROR msg=shown") {
		t.Errorf("the user's error and text did not reach the logger: %q", got)
	}

	_, stderr, err = runRoot(t, dir, "--log-level", "warn", "--log-format", "text", "version")
	if err != nil {
		t.Fatal(err)
	}
	slog.Info("hidden")
	slog.Warn("shown")
	if got := stderr.String(); strings.Contains(got, "hidden") || !strings.Contains(got, "level=WARN msg=shown") {
		t.Errorf("the typed flags lost to the files: %q", got)
	}
}

// A log value the logger refuses does not stop a command starting, the one that mends it included,
// and the commands that read the file name it.
func TestALogValueTheLoggerRefusesIsLeftForValidateToName(t *testing.T) {
	configHome(t, "")
	dir := projectBeside(t, "log:\n  level: verbose\n  format: json\n")

	if _, _, err := runRoot(t, dir, "version"); err != nil {
		t.Fatalf("a mistyped log.level stopped `version`: %v", err)
	}
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("an unreadable level was read as something more verbose than the default")
	}
	out, _, err := runRoot(t, dir, "config", "validate")
	if err == nil || !strings.Contains(out, `log.level: "verbose" is not trace, debug, info, warn or error`) {
		t.Errorf("validate did not name the level: %v\n%s", err, out)
	}
	if out, _, err = runRoot(t, dir, "config", "unset", "log.level"); err != nil {
		t.Fatalf("unset could not mend the file: %v\n%s", err, out)
	}
	if out, _, err = runRoot(t, dir, "config", "validate"); err != nil {
		t.Errorf("the mended file does not validate: %v\n%s", err, out)
	}

	// Each file contributes what decodes from it, and one that is not YAML contributes nothing.
	configHome(t, "offline: [\n")
	t.Chdir(projectBeside(t, "nope: 1\nlog:\n  format: json\n"))
	res := startupConfig("")
	if res.File.Log.Format != "json" || res.File.Offline != nil {
		t.Errorf("startupConfig = %+v", res.File)
	}
	if got := startupConfig(filepath.Join(t.TempDir(), "missing.yaml")); len(got.Sources) != 0 {
		t.Errorf("a named file that does not exist contributed %+v", got.Sources)
	}
}

// offline in a file holds for every command the process runs, `doctor` and a refusal included,
// and the flag and the environment outrank it.
func TestTheRootCommandStartsOfflineFromTheConfiguration(t *testing.T) {
	t.Setenv(netpolicy.EnvVar, "")
	configHome(t, "offline: true\n")
	dir := projectBeside(t, "offline: false\n")

	if _, _, err := runRoot(t, dir, "version"); err != nil {
		t.Fatal(err)
	}
	if !netpolicy.Offline() {
		t.Fatal("the user's offline: true did not hold over the project's false")
	}

	out, _, err := runRoot(t, dir, "doctor", writeSaga(t, doctorSagaNoControls))
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	if !strings.Contains(out, "(offline: none of these will happen)") {
		t.Errorf("doctor did not run offline:\n%s", out)
	}

	_, _, err = runRoot(t, dir, "tools", "install", "trivy", "-y")
	if err == nil || !strings.Contains(err.Error(), "tools install needs the network; ~/.draugr/config.yaml sets offline: true") {
		t.Errorf("the refusal does not name the file that put the run offline: %v", err)
	}

	if _, _, err := runRoot(t, dir, "--offline=false", "version"); err != nil {
		t.Fatal(err)
	}
	if netpolicy.Offline() {
		t.Error("--offline=false lost to the configuration")
	}
	t.Setenv(netpolicy.EnvVar, "0")
	if _, _, err := runRoot(t, dir, "version"); err != nil {
		t.Fatal(err)
	}
	if netpolicy.Offline() {
		t.Error("DRAUGR_OFFLINE=0 lost to the configuration")
	}
}

// A project file may turn offline on, and its refusal names it as a reader standing in it would.
func TestAProjectFileMayTurnOfflineOn(t *testing.T) {
	t.Setenv(netpolicy.EnvVar, "")
	configHome(t, "")
	dir := projectBeside(t, "offline: true\n")
	if _, _, err := runRoot(t, dir, "version"); err != nil {
		t.Fatal(err)
	}
	if got := netpolicy.Because(); got != "./draugr.config.yaml sets offline: true" {
		t.Errorf("Because() = %q", got)
	}
}
