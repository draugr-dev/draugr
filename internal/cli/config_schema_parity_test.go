package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// configParityFile writes every key draugr.config.yaml can hold as a live key.
const configParityFile = "testdata/parity/config/draugr.config.yaml"

// configJudges returns the two readers of a config file: `draugr config validate`, run on the file
// as written to disk, and the JSON Schema an editor validates it against.
func configJudges(t *testing.T) (validate func(any) error, editor func(any) error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), config.FileName)
	reg := builtins.Registry()
	validate = func(doc any) error {
		b, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return validateConfigFile(reg, path)
	}
	editor = func(doc any) error { return sagatest.ConfigSchemaError(t, doc) }
	return validate, editor
}

// TestTheEditorAndConfigValidateAgreeOnEveryField holds the draugr.config.yaml JSON Schema and
// `draugr config validate` to the same answer for every field of the file.
//
// The parity file is changed one field at a time, as the descriptor's parity test changes its
// corpus: each string into the wrong case, into a value nothing defines, into a number and into a
// boolean, each mapping given a key nothing defines, and each value set to null. Both readers judge
// every change and must agree, so a scanner option, a tool or an output value that one of them
// refuses and the other accepts fails here rather than in somebody's editor.
func TestTheEditorAndConfigValidateAgreeOnEveryField(t *testing.T) {
	raw, err := os.ReadFile(configParityFile)
	if err != nil {
		t.Fatal(err)
	}
	var base any
	if err := yaml.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	validate, editor := configJudges(t)
	if v, e := validate(base), editor(base); v != nil || e != nil {
		t.Fatalf("the parity file itself is refused\n  validate: %v\n  schema: %v", v, e)
	}
	mutations := sagatest.Mutations(base)
	if len(mutations) < 50 {
		t.Fatalf("only %d mutations of the parity file", len(mutations))
	}
	for _, m := range mutations {
		v, e := validate(m.Doc), editor(m.Doc)
		if (v == nil) != (e == nil) {
			t.Errorf("%s %s: draugr config validate accepts=%v, the schema accepts=%v; make them agree\n  validate: %v\n  schema: %v",
				m.Kind, m.Path, v == nil, e == nil, v, e)
		}
	}
}

// TestTheEditorAndConfigValidateAgreeOnTheCommonMistakes names the mistakes somebody makes in the
// file, so each is held to both readers by name rather than only as one mutation among many.
func TestTheEditorAndConfigValidateAgreeOnTheCommonMistakes(t *testing.T) {
	validate, editor := configJudges(t)
	cases := []struct {
		name string
		yaml string
		ok   bool
	}{
		{"an empty file", ``, true},
		{"a control default", "controls:\n  sast:\n    semgrep:\n      config: p/default\n", true},
		{"the older controllers spelling", "controllers:\n  sast:\n    semgrep:\n      config: p/default\n", true},
		{"both spellings", "controllers:\n  sast:\n    gosec: { enabled: true }\ncontrols:\n  sast:\n    semgrep: { config: p/default }\n", true},
		{"a tool pin written as a number", "tools:\n  trivy:\n    version: 0.69\n", true},
		{"a ttl of 0s", "cache:\n  ttl: 0s\n", true},
		{"a ttl of 1h30m", "cache:\n  ttl: 1h30m\n", true},

		{"an unknown top-level key", "outptu:\n  view: actions\n", false},
		{"an unknown key under output", "output:\n  veiw: actions\n", false},
		{"a wrong type", "output:\n  evidence: often\n", false},
		{"a mapping where a value goes", "cache:\n  dir: { path: /tmp }\n", false},
		{"an unknown control", "controls:\n  sats: {}\n", false},
		{"a renamed control", "controls:\n  containers: {}\n", false},
		{"an unknown scanner", "controls:\n  sca:\n    trivy-fs: { enabled: true }\n", false},
		{"an unknown scanner under controllers", "controllers:\n  sca:\n    trivy-fs: { enabled: true }\n", false},
		{"a reachability analyzer as a scanner", "controls:\n  sca:\n    govulncheck: { enabled: true }\n", false},
		{"a scanner given a value", "controls:\n  sast:\n    gosec: true\n", false},
		{"an option the scanner does not take", "controls:\n  sast:\n    semgrep:\n      rules: p/default\n", false},
		{"a bad scanner option value", "controls:\n  sca:\n    trivyFs:\n      pkgTypes: [kernel]\n", false},
		{"a bad control option value", "controls:\n  licenses:\n    deny: AGPL-3.0-only\n", false},
		{"an unknown tool", "tools:\n  trivvy:\n    version: 0.69.3\n", false},
		{"an unknown key under a tool", "tools:\n  trivy:\n    tag: 0.69.3\n", false},
		{"a view that is not a view", "output:\n  view: grouped\n", false},
		{"a negative top", "output:\n  top: -1\n", false},
		{"a negative ttl", "cache:\n  ttl: -1h\n", false},
		{"a ttl with no unit", "cache:\n  ttl: \"90\"\n", false},
		{"a ttl as a bare number", "cache:\n  ttl: 90\n", false},
		{"a key with no value", "tools:\noutput:\n  view: actions\n", false},
		{"a scanner block with no value", "controls:\n  sast:\n    enabled:\n", false},
	}
	for _, c := range cases {
		var doc any
		if err := yaml.Unmarshal([]byte(c.yaml), &doc); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if doc == nil {
			doc = map[string]any{}
		}
		v, e := validate(doc), editor(doc)
		if (v == nil) != c.ok || (e == nil) != c.ok {
			t.Errorf("%s: draugr config validate accepts=%v, the schema accepts=%v, want %v\n  validate: %v\n  schema: %v",
				c.name, v == nil, e == nil, c.ok, v, e)
		}
	}
}

// TestConfigInitPointsAnEditorAtTheSchema: the starter `config init` writes names the schema for
// this build on its first line, and both readers accept it, so the first thing an editor shows in
// a new file is not an error.
func TestConfigInitPointsAnEditorAtTheSchema(t *testing.T) {
	configHome(t, "")
	dir := t.TempDir()
	if _, err := runConfig(t, dir, "init"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, config.FileName)) // #nosec G304 -- a test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(data), "\n")
	if want := "# yaml-language-server: $schema=" + saga.ConfigSchemaURLFor(version.Version); first != want {
		t.Errorf("first line = %q, want %q", first, want)
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	validate, editor := configJudges(t)
	if v, e := validate(doc), editor(doc); v != nil || e != nil {
		t.Errorf("the starter is refused\n  validate: %v\n  schema: %v", v, e)
	}
	// An edit keeps the modeline, so the file stays pointed at the schema once somebody uses it.
	if _, err := runConfig(t, dir, "set", "output.view", "actions"); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dir, config.FileName)) // #nosec G304 -- a test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), first+"\n") {
		t.Errorf("config set dropped the modeline:\n%s", data)
	}
}

// TestEveryConfigFieldIsHeldToBothReaders requires every field of config.File to be written as a
// live key in the parity file, so TestTheEditorAndConfigValidateAgreeOnEveryField changes it.
// `controllers` is the exception: it is the older spelling, which no file should teach, and the
// common-mistakes test holds it to both readers.
func TestEveryConfigFieldIsHeldToBothReaders(t *testing.T) {
	raw, err := os.ReadFile(configParityFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var missing []string
	var walk func(tp reflect.Type, v any, path string)
	walk = func(tp reflect.Type, v any, path string) {
		for tp.Kind() == reflect.Pointer {
			tp = tp.Elem()
		}
		if tp.Kind() == reflect.Map && tp.Elem().Kind() == reflect.Struct {
			// A map of tool pins: every pin's fields, through whichever tool the file names first.
			m, _ := v.(map[string]any)
			names := make([]string, 0, len(m))
			for k := range m {
				names = append(names, k)
			}
			sort.Strings(names)
			if len(names) == 0 {
				missing = append(missing, path+".<name>")
				return
			}
			walk(tp.Elem(), m[names[0]], path+"."+names[0])
			return
		}
		if tp.Kind() != reflect.Struct {
			return
		}
		m, _ := v.(map[string]any)
		for i := range tp.NumField() {
			key, _, _ := strings.Cut(tp.Field(i).Tag.Get("yaml"), ",")
			if key == "" || key == "-" || (path == "" && key == "controllers") {
				continue
			}
			here := strings.TrimPrefix(path+"."+key, ".")
			val, ok := m[key]
			if !ok {
				missing = append(missing, here)
				continue
			}
			walk(tp.Field(i).Type, val, here)
		}
	}
	walk(reflect.TypeOf(config.File{}), doc, "")
	if len(missing) > 0 {
		t.Errorf("%s does not write %s, so the parity test never compares the two readers on it",
			configParityFile, strings.Join(missing, ", "))
	}
}
