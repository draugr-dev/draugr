package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// `config --help` is where somebody looks first, so it names every file the command reads, the
// override for both, the command that shows what is in effect and where every key is listed.
func TestConfigHelpNamesTheFilesAndWhereTheKeysAre(t *testing.T) {
	long := newConfigCommand().Long
	for _, want := range []string{
		"~/.draugr/config.yaml", "./draugr.config.yaml", "--config <path>", config.EnvVar,
		"`draugr config show`", config.KeysURL,
	} {
		if !strings.Contains(long, want) {
			t.Errorf("config --help does not name %q:\n%s", want, long)
		}
	}
}

func TestConfigShowNamesWhereEachValueCame(t *testing.T) {
	// The reason `show` exists. A three-layer merge is undebuggable without it: "why is Trivy
	// 0.68?" has one useful answer, and it is a filename.
	res := config.Resolved{
		Sources: []config.Source{
			{Path: "/home/u/.draugr/config.yaml", File: config.File{
				Tools:    map[string]config.ToolSettings{"trivy": {Version: "0.60.0"}},
				Controls: map[string]saga.ControllerSettings{"sast": {"semgrep": map[string]any{"config": "p/default"}}},
			}},
			{Path: "/repo/draugr.config.yaml", File: config.File{
				Tools: map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}},
			}},
		},
	}
	res.File = config.File{
		Tools:    map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}},
		Controls: map[string]saga.ControllerSettings{"sast": {"semgrep": map[string]any{"config": "p/default"}}},
	}

	var buf bytes.Buffer
	writeConfigShow(&buf, res, "/repo")
	out := buf.String()

	if !strings.Contains(out, "0.69.3") || !strings.Contains(out, "./draugr.config.yaml") {
		t.Errorf("the winning value is not attributed:\n%s", out)
	}
	// A nested setting must render as a dotted path, not as a Go map dumped into a column.
	if !strings.Contains(out, "controls.sast.semgrep.config") {
		t.Errorf("nested settings not flattened:\n%s", out)
	}
	if strings.Contains(out, "map[") {
		t.Errorf("a subtree was printed raw:\n%s", out)
	}
}

func TestConfigShowSaysNothingIsConfigured(t *testing.T) {
	var buf bytes.Buffer
	writeConfigShow(&buf, config.Resolved{}, "/repo")
	if !strings.Contains(buf.String(), "built-in defaults") {
		t.Errorf("an unconfigured machine should say so plainly:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "config init") {
		t.Errorf("no route forward offered:\n%s", buf.String())
	}
}

func TestEditConfigRefusesToWriteSomethingUnloadable(t *testing.T) {
	// The guarantee that makes these commands a recovery path: whatever they write, a scan loads.
	dir := t.TempDir()
	t.Chdir(dir)

	var buf bytes.Buffer
	err := editConfig(&buf, false, func([]byte) ([]byte, error) {
		return []byte("toolz: {}\n"), nil // a key the schema does not know
	})
	if err == nil {
		t.Fatal("an unloadable file was written")
	}
	if !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("error should say the file is untouched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, config.FileName)); !os.IsNotExist(err) {
		t.Error("a file was created despite the failure")
	}
}

func TestApplyConfigDefaultsMergesUnderTheDescriptor(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", t.TempDir())
	if err := os.WriteFile(filepath.Join(dir, config.FileName),
		[]byte("controllers:\n  sca:\n    trivyFs:\n      detectionPriority: comprehensive\n      includeDevDeps: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The descriptor has an opinion about detectionPriority and none about includeDevDeps.
	m := &saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"sca": {"trivyFs": map[string]any{"detectionPriority": "precise"}},
	}}}
	if _, err := applyConfigDefaults(context.Background(), m); err != nil {
		t.Fatal(err)
	}

	block, ok := blockOf(m.Config.Controls["sca"]["trivyFs"])
	if !ok {
		t.Fatalf("no trivyFs block: %+v", m.Config.Controls["sca"])
	}
	if block["detectionPriority"] != "precise" {
		t.Errorf("the descriptor did not win: %+v", block)
	}
	if block["includeDevDeps"] != true {
		t.Errorf("the org default was not inherited: %+v", block)
	}
}

// A scan refuses a configuration file that names a control this build does not provide, as
// `draugr validate` refuses one in a descriptor, rather than running without the setting.
func TestApplyConfigDefaultsRefusesAnUnknownControl(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(config.EnvVar, "")
	if err := os.WriteFile(filepath.Join(dir, config.FileName),
		[]byte("controllers:\n  sats:\n    semgrep:\n      config: p/org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := applyConfigDefaults(context.Background(), &saga.Model{})
	want := `controls: "sats" is not a control this build of Draugr provides, did you mean "sast"?`
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), config.FileName) {
		t.Errorf("want the file and %q, got %v", want, err)
	}
}

func TestApplyConfigDefaultsIsANoOpWithoutAFile(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	m := &saga.Model{}
	if _, err := applyConfigDefaults(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(m.Config.Controls) != 0 {
		t.Errorf("controllers invented from nowhere: %+v", m.Config.Controls)
	}
}

// runConfig executes the config command in dir with a temporary home, returning its output.
func runConfig(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	t.Chdir(dir)
	var buf bytes.Buffer
	cmd := newConfigCommand()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestConfigCommandRoundTrip(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	if out, err := runConfig(t, dir, "init"); err != nil {
		t.Fatalf("init: %v %s", err, out)
	}
	// A second init refuses rather than overwriting, and says how to mean it.
	_, err := runConfig(t, dir, "init")
	if err == nil {
		t.Error("init overwrote an existing file")
	} else if !strings.Contains(err.Error(), "--force") {
		t.Errorf("no route to replacing it: %v", err)
	}
	if out, err := runConfig(t, dir, "init", "--force"); err != nil {
		t.Fatalf("init --force: %v %s", err, out)
	}

	if _, err := runConfig(t, dir, "set", "controls.sast.semgrep.config", "p/ci"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"get", "controls.sast.semgrep.config"}, "p/ci"},
		{[]string{"show"}, "p/ci"},
		{[]string{"validate"}, "✓"},
	} {
		out, err := runConfig(t, dir, c.args...)
		if err != nil || !strings.Contains(out, c.want) {
			t.Errorf("%v returned %q %v, want it to mention %q", c.args, out, err, c.want)
		}
	}

	if _, err := runConfig(t, dir, "unset", "controls.sast.semgrep.config"); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfig(t, dir, "get", "controls.sast.semgrep.config"); err == nil {
		t.Error("get found a key that was unset")
	}
}

// Removing a key nobody set writes nothing: no file is created, so `config init` still writes the
// starter afterwards, and the answer tells a typo from a setting that is simply absent.
func TestConfigUnsetRefusesAnAbsentKey(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	project := filepath.Join(dir, config.FileName)

	_, err := runConfig(t, dir, "unset", "output.vew")
	if err == nil || !strings.Contains(err.Error(), `"output.vew" is not a setting Draugr has`) {
		t.Errorf("unset of a misspelled key: %v", err)
	}
	_, err = runConfig(t, dir, "unset", "output.view")
	if err == nil || err.Error() != `"output.view" is not set in ./draugr.config.yaml, so nothing was written` {
		t.Errorf("unset of an absent key: %v", err)
	}
	if _, statErr := os.Stat(project); !os.IsNotExist(statErr) {
		t.Fatal("unset of an absent key created the file")
	}
	if out, err := runConfig(t, dir, "init"); err != nil {
		t.Errorf("init after a refused unset: %v %s", err, out)
	}
	before, err := os.ReadFile(project) // #nosec G304 -- a test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runConfig(t, dir, "unset", "tools.trivy.version"); err == nil {
		t.Error("unset of a key the starter does not set succeeded")
	}
	if after, _ := os.ReadFile(project); !bytes.Equal(before, after) { // #nosec G304 -- as above
		t.Errorf("a refused unset rewrote the file:\n%s", after)
	}
	_, err = runConfig(t, dir, "unset", "--global", "output.view")
	if err == nil || err.Error() != `"output.view" is not set in ~/.draugr/config.yaml, so nothing was written` {
		t.Errorf("unset --global of an absent key: %v", err)
	}
}

// The starter's sections are written into as blocks, its comments survive, and emptying a section
// keeps the comment that explains it.
func TestConfigStarterTakesAFirstSetAsABlock(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	if _, err := runConfig(t, dir, "init"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(starterConfig, "controllers") {
		t.Error("the starter writes the older spelling")
	}
	for _, kv := range [][2]string{
		{"controls.sast.semgrep.config", "p/owasp-top-ten"},
		{"publish.apiUrl", "https://draugr.acme.example"},
	} {
		if _, err := runConfig(t, dir, "set", kv[0], kv[1]); err != nil {
			t.Fatalf("set %s: %v", kv[0], err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, config.FileName)) // #nosec G304 -- a test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"#   controls:\n",
		"controls:\n  sast:\n    semgrep:\n      config: p/owasp-top-ten\n",
		"publish:\n  apiUrl: https://draugr.acme.example\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, ": {sast") || strings.Contains(got, ": {apiUrl") {
		t.Errorf("a first set was written in flow style:\n%s", got)
	}
	if _, err := runConfig(t, dir, "unset", "controls.sast.semgrep.config"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, config.FileName)) // #nosec G304 -- as above
	if !strings.Contains(string(data), "#         config: p/owasp-top-ten\ncontrols: {}\n") {
		t.Errorf("emptying the section discarded its comment:\n%s", data)
	}
	if out, err := runConfig(t, dir, "validate"); err != nil {
		t.Errorf("the edited starter does not validate: %v %s", err, out)
	}
}

// `set` writes a flow list where a scanner option takes one, and `get` prints it as `set` takes it.
func TestConfigSetWritesAList(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	if _, err := runConfig(t, dir, "set", "controls.sca.trivyFs.pkgTypes", "[library, os]"); err != nil {
		t.Fatal(err)
	}
	if out, err := runConfig(t, dir, "get", "controls.sca.trivyFs.pkgTypes"); err != nil || out != "[library, os]\n" {
		t.Errorf("get = %q %v, want [library, os]", out, err)
	}
	_, err := runConfig(t, dir, "set", "controls.sca.trivyFs.pkgTypes", "[library")
	want := `"[library" starts with "[", so it is read as a YAML list and is not one; write a list as [a, b]`
	if err == nil || err.Error() != want {
		t.Errorf("a malformed list: %v, want %q", err, want)
	}
}

// A file written with `controllers:` loads, reads back under `controls`, and answers either name.
func TestConfigReadsTheOlderSpelling(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, config.FileName),
		[]byte("controllers:\n  sast:\n    semgrep:\n      config: p/ci\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"controls.sast.semgrep.config", "controllers.sast.semgrep.config"} {
		if out, err := runConfig(t, dir, "get", key); err != nil || out != "p/ci\n" {
			t.Errorf("get %s = %q %v", key, out, err)
		}
	}
	if out, err := runConfig(t, dir, "show"); err != nil || !strings.Contains(out, "controls.sast.semgrep.config") {
		t.Errorf("show = %q %v", out, err)
	}
	if _, err := runConfig(t, dir, "unset", "controls.sast.semgrep.config"); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfig(t, dir, "get", "controllers.sast.semgrep.config"); err == nil {
		t.Error("unset under the current name left the older one in force")
	}
}

// A file --config or DRAUGR_CONFIG skips is named, because the list of files read cannot show it.
func TestConfigShowNamesTheFilesANamedOneSkips(t *testing.T) {
	configHome(t, "output:\n  top: 5\n")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte("output:\n  top: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	named := filepath.Join(dir, "ci", "draugr.yaml")
	if err := os.MkdirAll(filepath.Dir(named), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(named, []byte("cache:\n  ttl: 12h\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(config.EnvVar, named)
	out, err := runConfig(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Files, least specific first:\n  ./ci/draugr.yaml\n",
		"Skipped while DRAUGR_CONFIG is set:\n  ~/.draugr/config.yaml\n  ./draugr.config.yaml\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if flat := strings.Join(strings.Fields(out), " "); !strings.Contains(flat, "cache.ttl 12h ./ci/draugr.yaml") {
		t.Errorf("cache.ttl is not written as the file writes it:\n%s", out)
	}

	// --config names it, and naming the project file itself skips only the home one.
	t.Setenv(config.EnvVar, "")
	rootConfigPath = config.FileName
	t.Cleanup(func() { rootConfigPath = "" })
	out, err = runConfig(t, dir, "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Skipped while --config is set:\n  ~/.draugr/config.yaml\n\n") {
		t.Errorf("show does not skip exactly the home file:\n%s", out)
	}
}

func TestDisplayPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wd := filepath.Join(home, "repo")
	for path, want := range map[string]string{
		filepath.Join(wd, config.FileName):            "./" + config.FileName,
		filepath.Join(wd, "ci", "draugr.yaml"):        "./ci/draugr.yaml",
		filepath.Join(home, ".draugr", "config.yaml"): "~/.draugr/config.yaml",
		filepath.Join(home+"x", "draugr.config.yaml"): filepath.Join(home+"x", "draugr.config.yaml"),
		filepath.Join(wd+"x", "draugr.config.yaml"):   "~/repox/draugr.config.yaml",
		"/etc/draugr.yaml":                            "/etc/draugr.yaml",
	} {
		if got := displayPath(path, wd); got != want {
			t.Errorf("displayPath(%q) = %q, want %q", path, got, want)
		}
	}
	if got := displayPath("/etc/draugr.yaml", ""); got != "/etc/draugr.yaml" {
		t.Errorf("with no working directory: %q", got)
	}
}

func TestConfigSetGlobalWritesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	out, err := runConfig(t, dir, "set", "--global", "controllers.sca.trivyFs.detectionPriority", "precise")
	if err != nil {
		t.Fatal(err)
	}
	// Which file, always: with two destinations a silent success is a guess.
	if !strings.Contains(out, "~/.draugr/config.yaml") {
		t.Errorf("did not name the file it wrote: %q", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".draugr", "config.yaml")); err != nil {
		t.Errorf("global file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, config.FileName)); !os.IsNotExist(err) {
		t.Error("--global wrote the project file")
	}
}

func TestConfigValidateReportsABrokenFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte("toolz: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfig(t, dir, "validate")
	if err == nil {
		t.Fatal("a file with an unknown key validated")
	}
	// The key, the nearest real one, and where every key is listed. Not `config init --force`,
	// which discards everything else the file says.
	for _, want := range []string{`"toolz" is not a setting Draugr has, did you mean "tools"?`, config.KeysURL} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "init --force") {
		t.Errorf("validate offered to wipe the file:\n%s", out)
	}
}

func TestConfigValidateWithNothingConfigured(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	out, err := runConfig(t, t.TempDir(), "validate")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "nothing to check") {
		t.Errorf("got %q", out)
	}
}

func TestShortHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got := shortHome(filepath.Join(home, ".draugr", "config.yaml")); got != "~/.draugr/config.yaml" {
		t.Errorf("got %q", got)
	}
	if got := shortHome("/etc/draugr.yaml"); got != "/etc/draugr.yaml" {
		t.Errorf("a path outside home was rewritten: %q", got)
	}
}

func TestConfigShowRendersCacheSettings(t *testing.T) {
	// `config show` exists so "why is my cache behaving like that" has a filename for an answer.
	// A setting it does not render is one the command cannot answer for.
	got := flatten(config.File{Cache: config.CacheSettings{
		Dir: "/var/cache/draugr", TTL: new(2 * time.Hour), ReadOnly: new(true), RequireDigest: new(false),
	}})
	want := map[string]string{
		"cache.dir":           "/var/cache/draugr",
		"cache.ttl":           "2h",
		"cache.readOnly":      "true",
		"cache.requireDigest": "false",
	}
	if len(got) != len(want) {
		t.Fatalf("rendered %d settings, want %d: %+v", len(got), len(want), got)
	}
	for _, kv := range got {
		if want[kv.key] != kv.value {
			t.Errorf("%s = %q, want %q", kv.key, kv.value, want[kv.key])
		}
	}
}

func TestConfigShowOmitsCacheSettingsNobodySet(t *testing.T) {
	// A zero field is the absence of a setting, not a setting whose value is zero. Printing
	// `cache.ttl 0s` beside a file that never mentions caching invites someone to wonder why
	// their cache expires immediately.
	if got := flatten(config.File{}); len(got) != 0 {
		t.Errorf("an empty config rendered %+v", got)
	}
	got := flatten(config.File{Cache: config.CacheSettings{Dir: "x"}})
	if len(got) != 1 || got[0].key != "cache.dir" {
		t.Errorf("only the set field should render, got %+v", got)
	}
}

func TestConfigShowReachesEveryField(t *testing.T) {
	// `config show` is the command somebody runs when a setting is not taking effect. A field it
	// cannot see is reported as "they set nothing", which is the most misleading answer available:
	// the file plainly contains the setting, and the tool built to explain it denies it exists.
	//
	// Walks the struct rather than listing fields, so one added and forgotten fails here.
	populated := reflect.New(reflect.TypeOf(config.File{})).Elem()
	fillConfig(t, populated)

	flat := flatten(populated.Interface().(config.File))
	shown := map[string]bool{}
	for _, entry := range flat {
		// "publish.apiUrl" -> "publish"
		shown[strings.SplitN(entry.key, ".", 2)[0]] = true
	}

	typ := reflect.TypeOf(config.File{})
	for i := range typ.NumField() {
		name := typ.Field(i).Tag.Get("yaml")
		name = strings.SplitN(name, ",", 2)[0]
		// The older spelling of controls is folded into it by config.Parse, so no File that reaches
		// `show` holds it; TestParseFoldsTheOlderSpelling in pkg/config holds the fold.
		if name == "" || name == "-" || name == "controllers" {
			continue
		}
		if !shown[name] {
			t.Errorf("`config show` never prints anything under %q, a setting there reads as "+
				"'they set nothing', which is the opposite of true", name)
		}
	}
}

// fillConfig gives every field a non-zero value, recursively.
func fillConfig(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		key := reflect.New(v.Type().Key()).Elem()
		fillConfig(t, key)
		val := reflect.New(v.Type().Elem()).Elem()
		switch val.Kind() {
		case reflect.Struct:
			fillConfig(t, val)
		case reflect.Interface, reflect.Map:
			// ControllerSettings is map[string]any, so there is no typed shape to walk, a synthetic
			// nested value stands in for the free-form tree a real one holds.
			val.Set(reflect.ValueOf(map[string]any{"scanner": map[string]any{"key": "value"}}))
		default:
			fillConfig(t, val)
		}
		v.SetMapIndex(key, val)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Field(i).CanSet() {
				fillConfig(t, v.Field(i))
			}
		}
	}
}
