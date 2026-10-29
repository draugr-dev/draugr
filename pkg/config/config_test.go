package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestParseRejectsUnknownKeys(t *testing.T) {
	// A misspelled setting that is silently dropped is one somebody believes is in force, and this
	// file exists to make behavior uniform, so a typo that quietly opts one machine out defeats
	// the point of having it.
	_, err := Parse([]byte("toolz:\n  trivy:\n    version: \"1\"\n"), "x.yaml")
	if err == nil {
		t.Fatal("an unknown top-level key was accepted")
	}
	// The error names the key in the file's terms, the nearest real one, and where every key is
	// listed. Not a Go type, and not `config init --force`, which discards the whole file.
	for _, want := range []string{`x.yaml:`, `"toolz" is not a setting Draugr has, did you mean "tools"?`, KeysURL} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	for _, unwanted := range []string{"config.File", "init --force"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("error carries %q: %v", unwanted, err)
		}
	}
}

// Every mistake in the file is reported at once, each by the key it is about.
func TestParseNamesEveryProblemByItsKey(t *testing.T) {
	doc := "output:\n  veiw: actions\n  evidence: 3\n" +
		"cache:\n  ttl: 5\n" +
		"tools:\n  trivy:\n    versio: \"1\"\n" +
		"publish:\n  zzzzzz: x\n"
	_, err := Parse([]byte(doc), "x.yaml")
	var p *Problems
	if !errors.As(err, &p) {
		t.Fatalf("want *Problems, got %T: %v", err, err)
	}
	want := []string{
		`output: "veiw" is not a setting Draugr has, did you mean "view"?`,
		`output.evidence: expected true or false, got 3`,
		`cache.ttl: expected a duration such as 12h, got 5`,
		`tools.trivy: "versio" is not a setting Draugr has, did you mean "version"?`,
		`publish: "zzzzzz" is not a setting Draugr has (it has apiUrl)`,
	}
	if !reflect.DeepEqual(p.List, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(p.List, "\n"), strings.Join(want, "\n"))
	}
}

func TestParseReportsBrokenYAMLAsTheDecoderDoes(t *testing.T) {
	_, err := Parse([]byte("output: [unclosed\n"), "x.yaml")
	var p *Problems
	if !errors.As(err, &p) || len(p.List) != 1 || !strings.Contains(p.List[0], "line") {
		t.Errorf("want one problem naming the line, got %v", err)
	}
	if strings.HasPrefix(p.List[0], "yaml: ") {
		t.Errorf("the decoder's package prefix was kept: %q", p.List[0])
	}
}

func TestExpectedNamesWhatAKeyTakes(t *testing.T) {
	for goType, want := range map[string]string{
		"time.Duration": "a duration such as 12h", "bool": "true or false", "int": "a whole number",
		"uint8": "a whole number", "string": "a string", "[]string": "a list",
		"map[string]config.ToolSettings": "a mapping", "config.OutputSettings": "a mapping",
	} {
		if got := expected(goType); got != want {
			t.Errorf("expected(%q) = %q, want %q", goType, got, want)
		}
	}
}

func TestDescribeKeepsAMessageItCannotPlace(t *testing.T) {
	// A message that names a line holding no such key is passed through as written: a guess at the
	// key would send the reader to the wrong line.
	for _, msg := range []string{
		"line 9: field nope not found in type config.File",
		"line 9: cannot unmarshal !!int `5` into time.Duration",
		"something else entirely",
	} {
		if got := describe([]byte("output:\n  view: actions\n"), []string{msg}); got[0] != msg {
			t.Errorf("describe(%q) = %q", msg, got[0])
		}
	}
}

func TestFieldsAtFollowsTheStruct(t *testing.T) {
	if got := fieldsAt([]string{"cache"}); !got["readOnly"] || !got["ttl"] || len(got) != 4 {
		t.Errorf("cache: %v", got)
	}
	if got := fieldsAt([]string{"tools", "trivy"}); !got["version"] {
		t.Errorf("tools.trivy: %v", got)
	}
	for _, path := range [][]string{{"nope"}, {"output", "view"}, {"controllers", "sast"}} {
		if got := fieldsAt(path); got != nil {
			t.Errorf("fieldsAt(%v) = %v, want nil", path, got)
		}
	}
}

func TestLoadReportsEveryBrokenFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvVar, "")
	if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".draugr", "config.yaml"), "toolz: {}\n")
	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), "outptu: {}\n")
	_, err := Load("", proj)
	if err == nil || !strings.Contains(err.Error(), `"toolz"`) || !strings.Contains(err.Error(), `"outptu"`) {
		t.Errorf("want both files reported, got %v", err)
	}
}

func TestFilesListsTheExplicitFileAloneOrWhatExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvVar, "")
	proj := t.TempDir()
	if got := Files("", proj); len(got) != 0 {
		t.Errorf("no files exist, got %v", got)
	}
	write(t, ProjectFile(proj), "")
	if got := Files("", proj); !reflect.DeepEqual(got, []string{ProjectFile(proj)}) {
		t.Errorf("got %v", got)
	}
	if got := Files("/named.yaml", proj); !reflect.DeepEqual(got, []string{"/named.yaml"}) {
		t.Errorf("the explicit file is listed alone, existing or not: %v", got)
	}
}

func TestParseEmptyIsValid(t *testing.T) {
	// A file that says nothing overrides nothing. Treating it as broken would make `touch` a
	// way to break a machine.
	for _, in := range []string{"", "\n", "# just a comment\n"} {
		if _, err := Parse([]byte(in), "x.yaml"); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestLoadLayersHomeUnderProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".draugr", "config.yaml"),
		"tools:\n  trivy: { version: \"0.60.0\" }\n  gitleaks: { version: \"8.0.0\" }\n")

	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), "tools:\n  trivy: { version: \"0.69.3\" }\n")

	got, err := Load("", proj)
	if err != nil {
		t.Fatal(err)
	}
	// The project has an opinion about trivy and none about gitleaks.
	if got.File.Tools["trivy"].Version != "0.69.3" {
		t.Errorf("project did not win: %+v", got.File.Tools)
	}
	if got.File.Tools["gitleaks"].Version != "8.0.0" {
		t.Errorf("home value was lost: %+v", got.File.Tools)
	}
	if len(got.Sources) != 2 {
		t.Errorf("expected both files recorded, got %d", len(got.Sources))
	}
}

func TestLoadExplicitReplacesRatherThanLayers(t *testing.T) {
	// Explicit means explicit: a runner image naming a config expects that config, not that one
	// layered over whatever happens to be in the working directory.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".draugr", "config.yaml"), "tools:\n  gitleaks: { version: \"8.0.0\" }\n")

	proj := t.TempDir()
	write(t, filepath.Join(proj, FileName), "tools:\n  trivy: { version: \"0.1.0\" }\n")
	only := filepath.Join(proj, "other.yaml")
	write(t, only, "tools:\n  trivy: { version: \"9.9.9\" }\n")

	got, err := Load(only, proj)
	if err != nil {
		t.Fatal(err)
	}
	if got.File.Tools["trivy"].Version != "9.9.9" {
		t.Errorf("explicit file not used: %+v", got.File.Tools)
	}
	if _, ok := got.File.Tools["gitleaks"]; ok {
		t.Error("explicit config was layered over the discovered ones")
	}
}

func TestLoadEnvVar(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "from-env.yaml")
	write(t, path, "tools:\n  trivy: { version: \"7.7.7\" }\n")
	t.Setenv(EnvVar, path)

	got, err := Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.File.Tools["trivy"].Version != "7.7.7" {
		t.Errorf("%s ignored: %+v", EnvVar, got.File.Tools)
	}
}

func TestLoadMissingFilesAreFine(t *testing.T) {
	// A machine with no configuration is the normal case, not an error.
	t.Setenv("HOME", t.TempDir())
	got, err := Load("", t.TempDir())
	if err != nil || len(got.Sources) != 0 {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestLoadNamedFileMustExist(t *testing.T) {
	// Naming a file that is not there is a mistake worth reporting: the caller believes settings
	// are in force that are not.
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), t.TempDir()); err == nil {
		t.Error("a missing explicit config was accepted")
	}
}

func TestDeepMergeOverridesOnlyNamedKeys(t *testing.T) {
	base := map[string]any{"mend": map[string]any{"apiUrl": "https://corp", "policy": "strict"}}
	over := map[string]any{"mend": map[string]any{"policy": "relaxed"}}

	got := DeepMerge(base, over)
	mend, _ := asSettings(got["mend"])
	if mend["policy"] != "relaxed" {
		t.Errorf("override lost: %+v", mend)
	}
	if mend["apiUrl"] != "https://corp" {
		t.Errorf("inherited key lost: %+v", mend)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCacheSettingsLayerFieldByField(t *testing.T) {
	// A project file setting only `ttl` must keep the `dir` the machine file supplied. Replacing
	// the struct wholesale would make the more specific file silently discard settings it never
	// mentioned, the opposite of what layering is for.
	home := File{Cache: CacheSettings{Dir: "/var/cache/draugr", TTL: new(time.Hour), RequireDigest: new(true)}}
	project := File{Cache: CacheSettings{TTL: new(15 * time.Minute)}}

	got := merge(home, project).Cache
	if got.Dir != "/var/cache/draugr" {
		t.Errorf("the project file discarded the machine's cache dir: %q", got.Dir)
	}
	if got.TTL == nil || *got.TTL != 15*time.Minute {
		t.Errorf("TTL = %v, want the project's", got.TTL)
	}
	if !On(got.RequireDigest) {
		t.Error("requireDigest was dropped by a file that never mentioned it")
	}
}

func TestCacheReadOnlyOnlyEverTurnsOn(t *testing.T) {
	// A machine that declares its results untrustworthy should not have that undone by a project
	// file that simply does not discuss caching.
	got := merge(File{Cache: CacheSettings{ReadOnly: new(true)}}, File{Cache: CacheSettings{Dir: "x"}}).Cache
	if !On(got.ReadOnly) {
		t.Error("read-only was silently cleared")
	}
}

// The user's file sets true and 12h, the project's sets false and 0s, read from disk as a scan
// reads them. Every setting the project writes wins, except the two layered one way, and those are
// reported rather than dropped without a word.
func TestAnExplicitFalseOrZeroInTheProjectFileWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvVar, "")
	if err := os.MkdirAll(filepath.Join(home, ".draugr"), 0o750); err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(home, ".draugr", "config.yaml")
	write(t, user, "output:\n  evidence: true\n  offerInstall: true\n"+
		"cache:\n  ttl: 12h\n  readOnly: true\n  requireDigest: true\n")
	proj := t.TempDir()
	project := filepath.Join(proj, FileName)
	write(t, project, "output:\n  evidence: false\n  offerInstall: false\n"+
		"cache:\n  ttl: 0s\n  readOnly: false\n  requireDigest: false\n")

	res, err := Load("", proj)
	if err != nil {
		t.Fatal(err)
	}
	if f := res.File; f.Output.Evidence == nil || *f.Output.Evidence {
		t.Errorf("output.evidence = %v, want the project's false", f.Output.Evidence)
	}
	if res.File.Output.Offers() {
		t.Error("output.offerInstall: the project's false did not win")
	}
	if ttl := res.File.Cache.TTL; ttl == nil || *ttl != 0 {
		t.Errorf("cache.ttl = %v, want the project's 0s", ttl)
	}
	if !On(res.File.Cache.ReadOnly) || !On(res.File.Cache.RequireDigest) {
		t.Errorf("a one-way setting was turned off: %+v", res.File.Cache)
	}

	want := []Override{
		{Key: "cache.readOnly", Path: project, By: user},
		{Key: "cache.requireDigest", Path: project, By: user},
	}
	if got := res.Overrides(); !reflect.DeepEqual(got, want) {
		t.Errorf("Overrides() = %+v, want %+v", got, want)
	}
}

// A false with nothing turned on beneath it is a setting like any other, not an override, and a
// true above a false is ordinary precedence.
func TestOverridesReportsOnlyAFalseOverATrue(t *testing.T) {
	for name, sources := range map[string][]Source{
		"false alone":     {{Path: "p", File: File{Cache: CacheSettings{ReadOnly: new(false)}}}},
		"true over false": {{Path: "u", File: File{Cache: CacheSettings{ReadOnly: new(false)}}}, {Path: "p", File: File{Cache: CacheSettings{ReadOnly: new(true)}}}},
		"unset over true": {{Path: "u", File: File{Cache: CacheSettings{ReadOnly: new(true)}}}, {Path: "p"}},
	} {
		if got := (Resolved{Sources: sources}).Overrides(); len(got) != 0 {
			t.Errorf("%s: Overrides() = %+v, want none", name, got)
		}
	}
}

func TestMergeCarriesEveryField(t *testing.T) {
	// merge names each field explicitly, so a field added to File and forgotten here is dropped on
	// every load, not overridden, not defaulted, just gone, while the file on disk plainly
	// contains it and `config show` reports that it sets nothing. A setting that is present, valid
	// and ignored is the hardest kind to diagnose, because every place a reader looks says it is
	// fine.
	//
	// So this walks the struct rather than listing what to check: a new field fails here until
	// merge handles it, and the failure names the field.
	populated := reflect.New(reflect.TypeOf(File{})).Elem()
	fill(t, populated)
	source := populated.Interface().(File)
	source.Controllers = nil // Parse folds it, so it never reaches merge

	// Laid over an empty base: everything set must survive.
	merged := merge(File{}, source)
	assertEveryFieldSet(t, reflect.ValueOf(merged), "merge(empty, set)")

	// And laid under an empty overlay: a more specific file that mentions nothing must not erase
	// what the less specific one said.
	kept := merge(source, File{})
	assertEveryFieldSet(t, reflect.ValueOf(kept), "merge(set, empty)")
}

// fill gives every field of a struct a non-zero value, recursively.
func fill(t *testing.T, v reflect.Value) {
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
		fill(t, key)
		val := reflect.New(v.Type().Elem()).Elem()
		if val.Kind() == reflect.Struct {
			fill(t, val)
		}
		v.SetMapIndex(key, val)
	case reflect.Pointer:
		// A pointer is how a field tells "set to false" from "not set", so it is filled with a
		// value of its own rather than left nil, which would read as a field merge dropped.
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, v.Elem())
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Field(i).CanSet() {
				fill(t, v.Field(i))
			}
		}
	}
}

// foldedAtParse are the fields Parse moves onto another before a file is merged, which
// TestParseFoldsTheOlderSpelling holds to.
var foldedAtParse = map[string]bool{"Controllers": true}

// assertEveryFieldSet reports any field that came back at its zero value.
func assertEveryFieldSet(t *testing.T, v reflect.Value, what string) {
	t.Helper()
	typ := v.Type()
	for i := range v.NumField() {
		field, name := v.Field(i), typ.Field(i).Name
		if field.Kind() == reflect.Struct {
			assertEveryFieldSet(t, field, what+"."+name)
			continue
		}
		if foldedAtParse[name] {
			continue
		}
		if field.IsZero() {
			t.Errorf("%s dropped %s. Add it to merge(), or every config file that sets it is "+
				"silently ignored", what, name)
		}
	}
}

// Unset offers, an explicit false declines, and an explicit true offers: a pointer, because a file
// that says false has to be told apart from one that says nothing.
func TestOffersReadsAnUnsetKeyAsYes(t *testing.T) {
	no, yes := false, true
	for name, tc := range map[string]struct {
		v    *bool
		want bool
	}{"unset": {nil, true}, "false": {&no, false}, "true": {&yes, true}} {
		if got := (OutputSettings{OfferInstall: tc.v}).Offers(); got != tc.want {
			t.Errorf("%s: Offers() = %v, want %v", name, got, tc.want)
		}
	}
}

func TestExplicitPrefersTheFlagToTheEnvironment(t *testing.T) {
	t.Setenv(EnvVar, "/from/env.yaml")
	if got := Explicit("/from/flag.yaml"); got != "/from/flag.yaml" {
		t.Errorf("Explicit = %q, want the flag", got)
	}
	if got := Explicit(""); got != "/from/env.yaml" {
		t.Errorf("Explicit = %q, want the environment", got)
	}
	t.Setenv(EnvVar, "")
	if got := Explicit(""); got != "" {
		t.Errorf("Explicit = %q, want none", got)
	}
}

// A file written with `controllers:` loads as `controls:`, and one carrying both after a `config set`
// keeps every key either sets, with `controls` winning where both set one.
func TestParseFoldsTheOlderSpelling(t *testing.T) {
	doc := `controllers:
  sast:
    semgrep:
      config: p/ci
    gosec:
      enabled: true
  sca:
    enabled: true
controls:
  sast:
    semgrep:
      config: p/owasp-top-ten
  licenses:
    enabled: true
`
	f, err := Parse([]byte(doc), "draugr.config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Controllers != nil {
		t.Errorf("the older spelling is still populated after Parse: %v", f.Controllers)
	}
	want := map[string]saga.ControllerSettings{
		"sast": {
			"semgrep": saga.ControllerSettings{"config": "p/owasp-top-ten"},
			"gosec":   saga.ControllerSettings{"enabled": true},
		},
		"sca":      {"enabled": true},
		"licenses": {"enabled": true},
	}
	if !reflect.DeepEqual(normalize(f.Controls), normalize(want)) {
		t.Errorf("Controls = %#v\nwant %#v", f.Controls, want)
	}

	// The older spelling alone.
	f, err = Parse([]byte("controllers:\n  sca:\n    enabled: true\n"), "draugr.config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := normalize(f.Controls); got != normalize(map[string]saga.ControllerSettings{"sca": {"enabled": true}}) {
		t.Errorf("Controls = %s", got)
	}
}

// normalize renders settings through one type, since YAML decodes a nested mapping as the
// enclosing named type and a literal written here is a plain map.
func normalize(m map[string]saga.ControllerSettings) string {
	return fmt.Sprintf("%v", m)
}

func TestCurrentKeyReadsTheOlderSpellingAsControls(t *testing.T) {
	for key, want := range map[string]string{
		"controllers.sast.semgrep.config": "controls.sast.semgrep.config",
		"controllers":                     "controls",
		"controls.sast":                   "controls.sast",
		"controllersx.sast":               "controllersx.sast",
		"tools.trivy.version":             "tools.trivy.version",
	} {
		if got := CurrentKey(key); got != want {
			t.Errorf("CurrentKey(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestDiscoveredListsTheFilesANamedOneSkips(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	if got := Discovered(work); len(got) != 0 {
		t.Errorf("Discovered with no files = %v", got)
	}
	user := filepath.Join(home, ".draugr", "config.yaml")
	project := ProjectFile(work)
	for _, p := range []string{user, project} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := Discovered(work), []string{user, project}; !reflect.DeepEqual(got, want) {
		t.Errorf("Discovered = %v, want %v", got, want)
	}
	if got := Files("named.yaml", work); !reflect.DeepEqual(got, []string{"named.yaml"}) {
		t.Errorf("Files with a named file = %v", got)
	}
}
