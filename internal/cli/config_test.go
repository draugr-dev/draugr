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

func TestConfigShowNamesWhereEachValueCame(t *testing.T) {
	// The reason `show` exists. A three-layer merge is undebuggable without it: "why is Trivy
	// 0.68?" has one useful answer, and it is a filename.
	res := config.Resolved{
		Sources: []config.Source{
			{Path: "/home/u/.draugr/config.yaml", File: config.File{
				Tools:       map[string]config.ToolSettings{"trivy": {Version: "0.60.0"}},
				Controllers: map[string]saga.ControllerSettings{"sast": {"semgrep": map[string]any{"config": "p/default"}}},
			}},
			{Path: "/repo/draugr.config.yaml", File: config.File{
				Tools: map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}},
			}},
		},
	}
	res.File = config.File{
		Tools:       map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}},
		Controllers: map[string]saga.ControllerSettings{"sast": {"semgrep": map[string]any{"config": "p/default"}}},
	}

	var buf bytes.Buffer
	writeConfigShow(&buf, res)
	out := buf.String()

	if !strings.Contains(out, "0.69.3") || !strings.Contains(out, "/repo/draugr.config.yaml") {
		t.Errorf("the winning value is not attributed:\n%s", out)
	}
	// A nested setting must render as a dotted path, not as a Go map dumped into a column.
	if !strings.Contains(out, "controllers.sast.semgrep.config") {
		t.Errorf("nested settings not flattened:\n%s", out)
	}
	if strings.Contains(out, "map[") {
		t.Errorf("a subtree was printed raw:\n%s", out)
	}
}

func TestConfigShowSaysNothingIsConfigured(t *testing.T) {
	var buf bytes.Buffer
	writeConfigShow(&buf, config.Resolved{})
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
		[]byte("controllers:\n  sast:\n    semgrep:\n      config: p/org\n      timeout: 300\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The descriptor has an opinion about config and none about timeout.
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"sast": {"semgrep": map[string]any{"config": "p/mine"}},
	}}}
	if _, err := applyConfigDefaults(context.Background(), m); err != nil {
		t.Fatal(err)
	}

	sem, _ := m.Config.Controllers["sast"]["semgrep"].(map[string]any)
	if sem == nil {
		if s, ok := m.Config.Controllers["sast"]["semgrep"].(saga.ControllerSettings); ok {
			sem = s
		}
	}
	if sem["config"] != "p/mine" {
		t.Errorf("the descriptor did not win: %+v", sem)
	}
	if sem["timeout"] != 300 {
		t.Errorf("the org default was not inherited: %+v", sem)
	}
}

func TestApplyConfigDefaultsIsANoOpWithoutAFile(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	m := &saga.Model{}
	if _, err := applyConfigDefaults(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if len(m.Config.Controllers) != 0 {
		t.Errorf("controllers invented from nowhere: %+v", m.Config.Controllers)
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

	if _, err := runConfig(t, dir, "set", "controllers.sast.semgrep.config", "p/ci"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"get", "controllers.sast.semgrep.config"}, "p/ci"},
		{[]string{"show"}, "p/ci"},
		{[]string{"validate"}, "✓"},
	} {
		out, err := runConfig(t, dir, c.args...)
		if err != nil || !strings.Contains(out, c.want) {
			t.Errorf("%v returned %q %v, want it to mention %q", c.args, out, err, c.want)
		}
	}

	if _, err := runConfig(t, dir, "unset", "controllers.sast.semgrep.config"); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfig(t, dir, "get", "controllers.sast.semgrep.config"); err == nil {
		t.Error("get found a key that was unset")
	}
}

func TestConfigSetGlobalWritesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	out, err := runConfig(t, dir, "set", "--global", "controllers.sca.trivyFs.timeout", "300")
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
	_, err := runConfig(t, dir, "validate")
	if err == nil {
		t.Fatal("a file with an unknown key validated")
	}
	// Recovery has to be in the message: a config that fails is only safe if fixing it is easy.
	if !strings.Contains(err.Error(), "config init --force") {
		t.Errorf("no recovery offered: %v", err)
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
		Dir: "/var/cache/draugr", TTL: 2 * time.Hour, ReadOnly: true, RequireDigest: true,
	}})
	want := map[string]string{
		"cache.dir":           "/var/cache/draugr",
		"cache.ttl":           "2h0m0s",
		"cache.readOnly":      "true",
		"cache.requireDigest": "true",
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
		if name == "" || name == "-" {
			continue
		}
		if !shown[name] {
			t.Errorf("`config show` never prints anything under %q — a setting there reads as "+
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
			// ControllerSettings is map[string]any, so there is no typed shape to walk — a
			// synthetic nested value stands in for the free-form tree a real one holds.
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
