package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// keysOutput runs `draugr config keys` with prefix and all, and returns what it printed.
func keysOutput(t *testing.T, prefix string, all bool) string {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	var b bytes.Buffer
	if err := runConfigKeys(&b, builtins.Registry(), prefix, all); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// rowOf is the Key, Accepts and Default columns of the line for key, or nil when none lists it.
func rowOf(out, key string) []string {
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, key+" ") {
			return regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), -1)
		}
	}
	return nil
}

// A field added to config.File is a key somebody can write, so `config keys` has to say what it
// accepts and what it defaults to, and the reference table has to describe it. Walks the struct
// rather than listing fields, so one added and forgotten fails here with the place to add it.
func TestEveryConfigFieldHasAKeysRow(t *testing.T) {
	names := machineKeyNames()
	// The walk reaches every top-level field outside `controls`, or the rows below prove nothing.
	reached := map[string]bool{}
	for _, n := range names {
		reached[strings.SplitN(n, ".", 2)[0]] = true
	}
	typ := reflect.TypeOf(config.File{})
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("yaml"), ",")
		if name == "controls" || name == "controllers" {
			continue
		}
		if !reached[name] {
			t.Errorf("machineKeyNames never reaches %q", name)
		}
	}
	for _, n := range names {
		if _, ok := machineKeys[n]; !ok {
			t.Errorf("config.File has %s, and `draugr config keys` cannot say what it accepts or defaults "+
				"to; add it to machineKeys in internal/cli/configkeys.go", n)
		}
	}
	for n := range machineKeys {
		if !slices.Contains(names, n) {
			t.Errorf("machineKeys describes %s, which config.File does not have", n)
		}
	}
	md, err := configKeysMarkdown(saga.ConfigSchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if !strings.Contains(md, "| `"+n+"` |") {
			t.Errorf("the reference table has no row for %s", n)
		}
	}
}

// Accepts is a promise about what `draugr config validate` takes, so each row is held to the
// refusal itself: a value of the wrong kind is written under the key, and some refusal of it has
// to say what the row says. A key no probe can upset takes any text, and its row must not claim a
// constraint nothing enforces.
func TestEveryConfigKeyAcceptsWhatValidateSays(t *testing.T) {
	reg := builtins.Registry()
	for _, r := range machineRows() {
		key := strings.Replace(r.key, toolPlaceholder, "trivy", 1)
		want, _, _ := strings.Cut(r.accepts, ";")
		var refusals []string
		for _, probe := range []string{"maybe", "5", "-1", "zz"} {
			doc, err := config.Set(nil, key, probe)
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			_, err = parseConfig(reg, "draugr.config.yaml", doc)
			var p *config.Problems
			if errors.As(err, &p) {
				refusals = append(refusals, p.List...)
			}
		}
		if len(refusals) == 0 {
			for _, claim := range []string{acceptsBool, acceptsDuration, acceptsCount, " or "} {
				if strings.Contains(r.accepts, claim) {
					t.Errorf("%s accepts any text, and the row says %q", r.key, r.accepts)
				}
			}
			continue
		}
		if !slices.ContainsFunc(refusals, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("%s says it accepts %q, and validate refuses it as:\n  %s", r.key, want,
				strings.Join(refusals, "\n  "))
		}
	}
}

// flagDefault is the default a command gives one of its flags.
func flagDefault(t *testing.T, cmd *cobra.Command, name string) string {
	t.Helper()
	f := cmd.Flags().Lookup(name)
	if f == nil {
		f = cmd.PersistentFlags().Lookup(name)
	}
	if f == nil {
		t.Fatalf("%s has no --%s", cmd.Name(), name)
	}
	return f.DefValue
}

// A default is what happens when the file is silent, which is the flag's own default or what the
// code does with nothing set, so each row is held to that. A key with no check here fails, so a
// key added later has to say where its default comes from.
func TestEveryConfigKeyDefaultIsTheOneTheCodeApplies(t *testing.T) {
	scan, diff, root := newScanCommand(), newDiffCommand(), newRootCommand()
	ttl, err := time.ParseDuration(flagDefault(t, scan, "cache-ttl"))
	if err != nil {
		t.Fatal(err)
	}
	notTips, err := strconv.ParseBool(flagDefault(t, scan, "no-tips"))
	if err != nil {
		t.Fatal(err)
	}
	top := flagDefault(t, scan, "top")
	if flagDefault(t, diff, "top") != "0" {
		t.Fatal("diff --top no longer lists every row by default")
	}
	if flagDefault(t, diff, "view") != flagDefault(t, scan, "view") {
		t.Fatal("scan and diff default to different views")
	}
	want := map[string]func(def string) bool{
		"cache.dir":           func(d string) bool { return flagDefault(t, scan, "cache-dir") == "" && strings.HasPrefix(d, "none") },
		"cache.readOnly":      func(d string) bool { return d == flagDefault(t, scan, "cache-read-only") },
		"cache.requireDigest": func(d string) bool { return d == flagDefault(t, scan, "cache-require-digest") },
		"cache.ttl":           func(d string) bool { return d == feeds.ShortDuration(ttl) },
		"log.format":          func(d string) bool { return d == flagDefault(t, root, "log-format") },
		"log.level":           func(d string) bool { return d == flagDefault(t, root, "log-level") },
		"offline":             func(d string) bool { return d == flagDefault(t, root, "offline") },
		"output.evidence":     func(d string) bool { return d == flagDefault(t, scan, "evidence") },
		"output.offerInstall": func(d string) bool { return d == strconv.FormatBool(config.OutputSettings{}.Offers()) },
		"output.tips":         func(d string) bool { return d == strconv.FormatBool(!notTips) },
		"output.top":          func(d string) bool { return d == top+" for scan, every row for diff" },
		"output.view":         func(d string) bool { return d == flagDefault(t, scan, "view") },
		// No URL is built in: the draugr-api publisher needs one from the file or $DRAUGR_API_URL.
		"publish.apiUrl": func(d string) bool { return d == "none" },
		"scan.jobs":      func(d string) bool { return d == flagDefault(t, scan, "jobs") },
		// Each tool's own pin, which the rows named per tool below hold.
		"tools.<tool>.version": func(d string) bool { return d == "Draugr's pin" },
	}
	for _, r := range machineRows() {
		check, ok := want[r.key]
		if !ok {
			t.Errorf("%s has no check here, so nothing holds its default %q to the code", r.key, r.def)
			continue
		}
		if !check(r.def) {
			t.Errorf("%s defaults to %q in `config keys`, which is not what the code applies", r.key, r.def)
		}
	}
	// Named per tool, a pin row's default is the pin itself.
	for _, name := range tools.Installable() {
		if row := rowOf(keysOutput(t, "tools."+name, false), "tools."+name+".version"); row == nil ||
			row[2] != tools.PinnedVersion(name) {
			t.Errorf("tools.%s.version: row %q, want the pin %s", name, row, tools.PinnedVersion(name))
		}
	}
}

// One control expanded lists every scanner the live registry has for it, opt-in ones included,
// each with whether it runs unasked and every option it declares.
func TestConfigKeysForAControlListsEveryScannerKey(t *testing.T) {
	out := keysOutput(t, "controls.sca", false)
	reg := builtins.Registry()
	defaults := map[string]bool{}
	for _, c := range reg.Controllers() {
		if c.Info().Name == "sca" {
			for _, d := range c.Info().DefaultScanners {
				defaults[d] = true
			}
		}
	}
	optIn := 0
	for _, s := range reg.Scanners() {
		info := s.Info()
		if !slices.Contains(info.Controls, "sca") || info.Reachability {
			if info.Reachability && strings.Contains(out, controllers.ScannerConfigKey(info.Name)) {
				t.Errorf("%s is enabled under config.reachability, and is listed as a block", info.Name)
			}
			continue
		}
		key := "controls.sca." + controllers.ScannerConfigKey(info.Name)
		wantDefault := "true"
		if !defaults[info.Name] {
			wantDefault = "false"
			optIn++
		}
		if row := rowOf(out, key+".enabled"); row == nil || row[1] != acceptsBool || row[2] != wantDefault {
			t.Errorf("%s.enabled: row %q, want %s by default", key, row, wantDefault)
		}
		for _, o := range plugin.Options(info.ConfigSchema) {
			if rowOf(out, key+"."+o.Name) == nil {
				t.Errorf("no row for %s.%s:\n%s", key, o.Name, out)
			}
		}
	}
	if optIn == 0 {
		t.Fatal("sca has no opt-in scanner, so this test no longer shows one is listed")
	}
	if !strings.Contains(out, "`draugr controls sca --options` says what each option does.") {
		t.Errorf("no pointer to what each option does:\n%s", out)
	}
	// The summary names the same keys, opt-in ones marked as `draugr controls` marks them.
	summary := keysOutput(t, "", false)
	if line := lineWith(summary, "controls.sca "); !strings.Contains(line, "trivyFs") || !strings.Contains(line, "grypeFs*") {
		t.Errorf("summary line for sca: %q", line)
	}
}

func TestConfigKeysNarrowsToAPrefix(t *testing.T) {
	cache := keysOutput(t, "cache.", false)
	for _, key := range []string{"cache.dir", "cache.readOnly", "cache.requireDigest", "cache.ttl"} {
		if rowOf(cache, key) == nil {
			t.Errorf("cache lists no %s:\n%s", key, cache)
		}
	}
	if strings.Contains(cache, "output.") || strings.Contains(cache, "--options") {
		t.Errorf("cache lists more than its own keys:\n%s", cache)
	}
	// The older spelling of the section reads as the current one, as get and unset take it.
	if got, want := keysOutput(t, "controllers.tls", false), keysOutput(t, "controls.tls", false); got != want {
		t.Errorf("controllers.tls:\n%s\nwant:\n%s", got, want)
	}
	all := keysOutput(t, "", true)
	for _, c := range builtins.Registry().Controllers() {
		if rowOf(all, "controls."+c.Info().Name+".enabled") == nil {
			t.Errorf("--all lists no controls.%s.enabled", c.Info().Name)
		}
	}
	if rowOf(all, "tools.trivy.version") == nil || strings.Contains(all, toolPlaceholder) {
		t.Errorf("--all names each tool rather than the placeholder:\n%s", all)
	}
	if !strings.Contains(all, "`draugr controls --options` says what each option does.") {
		t.Errorf("--all does not point at every control's options")
	}
}

func TestConfigKeysRefusesAPrefixThatNamesNothing(t *testing.T) {
	var b bytes.Buffer
	err := runConfigKeys(&b, builtins.Registry(), "outptu", false)
	want := `"outptu" is not a setting Draugr has, did you mean "output"? ` + config.KeysHint
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
	err = runConfigKeys(&b, builtins.Registry(), "zzzzzzzz", false)
	if want := `"zzzzzzzz" is not a setting Draugr has; ` + config.KeysHint; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
}

// The unknown-key error from get, set and unset names the nearest key and where every key is
// listed, so a typo is answered in the terminal it was typed in.
func TestAMistypedKeyIsAnsweredWithTheNearestOne(t *testing.T) {
	t.Setenv(config.EnvVar, "")
	dir := t.TempDir()
	want := `"output.veiw" is not a setting Draugr has, did you mean "output.view"? ` + config.KeysHint
	for _, args := range [][]string{{"get", "output.veiw"}, {"unset", "output.veiw"}} {
		if _, err := runConfig(t, dir, args...); err == nil || err.Error() != want {
			t.Errorf("config %s: %v\nwant %s", strings.Join(args, " "), err, want)
		}
	}
	_, err := runConfig(t, dir, "set", "output.veiw", "actions")
	if err == nil || !strings.HasSuffix(err.Error(), config.KeysHint) {
		t.Errorf("config set: %v\nwant it to end %q", err, config.KeysHint)
	}
}

// An option whose description states a default has to declare it, or `config keys` shows "-"
// beside a sentence saying what the default is; and a declared default has to be a value the
// option takes. Walks the live registry, so a scanner added later is held to it too.
func TestAnOptionThatStatesADefaultDeclaresIt(t *testing.T) {
	reg := builtins.Registry()
	schemas := map[string]json.RawMessage{}
	for _, s := range reg.Scanners() {
		schemas[s.Info().Name] = s.Info().ConfigSchema
	}
	for _, c := range reg.Controllers() {
		schemas["control "+c.Info().Name] = c.Info().OptionSchema
	}
	mentions := regexp.MustCompile(`(?i)\bdefault`)
	for owner, schema := range schemas {
		for _, o := range plugin.Options(schema) {
			text := o.Description
			for _, m := range o.Meanings {
				text += " " + m
			}
			declared := optionDefault(o) != "-"
			if mentions.MatchString(text) && !declared {
				t.Errorf("%s.%s says it has a default and declares none: %q", owner, o.Name, o.Description)
			}
			if !declared {
				continue
			}
			var node map[string]any
			if err := json.Unmarshal(o.Schema, &node); err != nil {
				t.Fatal(err)
			}
			one, err := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{o.Name: node}})
			if err != nil {
				t.Fatal(err)
			}
			// As a descriptor decodes it: JSON reads every number as a float, YAML a whole one as an int.
			def := node["default"]
			if f, ok := def.(float64); ok && f == float64(int(f)) {
				def = int(f)
			}
			if err := plugin.ValidateConfig(one, plugin.Config{o.Name: def}); err != nil {
				t.Errorf("%s.%s declares a default its own schema refuses: %v", owner, o.Name, err)
			}
		}
	}
}

func TestOptionAcceptsSaysWhatTheSchemaTakes(t *testing.T) {
	for _, tc := range []struct {
		opt  plugin.Option
		want string
	}{
		{plugin.Option{Type: "array", Enum: []string{"os", "library"}}, "a list of os, library"},
		{plugin.Option{Type: "string", Enum: []string{"precise", "comprehensive"}}, "precise or comprehensive"},
		{plugin.Option{Type: "string", Pattern: plugin.DurationPattern}, plugin.PatternName(plugin.DurationPattern)},
		{plugin.Option{Type: "string", Pattern: "^x$"}, "a string"},
		{plugin.Option{Type: "string", Required: true}, "a string, required"},
		{plugin.Option{Type: "integer"}, "a whole number"},
		{plugin.Option{Type: "object"}, "a mapping"},
		{plugin.Option{}, "a value"},
	} {
		if got := optionAccepts(tc.opt); got != tc.want {
			t.Errorf("optionAccepts(%+v) = %q, want %q", tc.opt, got, tc.want)
		}
	}
}

func TestOptionDefaultIsWrittenAsTyped(t *testing.T) {
	for schema, want := range map[string]string{
		`{"type":"array","default":["os","library"]}`: "os, library",
		`{"type":"integer","default":14}`:             "14",
		`{"type":"number","default":0.5}`:             "0.5",
		`{"type":"boolean","default":false}`:          "false",
		`{"type":"string","default":"p/default"}`:     "p/default",
		`{"type":"string"}`:                           "-",
		`{"type":"string","default":}`:                "-",
	} {
		if got := optionDefault(plugin.Option{Schema: json.RawMessage(schema)}); got != want {
			t.Errorf("optionDefault(%s) = %q, want %q", schema, got, want)
		}
	}
}

func TestWrapWordsBreaksBetweenWords(t *testing.T) {
	if got := wrapWords("aaa bbb ccc", 7); got != "aaa bbb\nccc" {
		t.Errorf("got %q", got)
	}
}

func TestTheReferenceTableNeedsADescriptionForEveryKey(t *testing.T) {
	if _, err := configKeysMarkdown([]byte(`{"properties":{}}`)); err == nil ||
		!strings.Contains(err.Error(), "configFields") {
		t.Errorf("a key the schema does not describe was accepted: %v", err)
	}
	if _, err := configKeysMarkdown([]byte(`not json`)); err == nil {
		t.Error("an unreadable schema was accepted")
	}
}

// configKeysBegin and configKeysEnd fence the table in docs/reference/cli.md that
// configKeysMarkdown writes.
const (
	configKeysBegin = "<!-- config keys: generated by `go test ./internal/cli -run TestTheReferenceListsEveryConfigKey -update`; edit internal/cli/configkeys.go or configFields in internal/schemagen/config.go -->\n"
	configKeysEnd   = "<!-- end of generated config keys -->\n"
)

// The reference page lists the keys `draugr config keys` lists, from the same rows and the
// schema's own descriptions, so the page, the command and an editor's hover cannot disagree.
func TestTheReferenceListsEveryConfigKey(t *testing.T) {
	const path = "../../docs/reference/cli.md"
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before, rest, ok := strings.Cut(string(doc), configKeysBegin)
	current, after, ok2 := strings.Cut(rest, configKeysEnd)
	if !ok || !ok2 {
		t.Fatalf("%s has no generated config keys table between %q and %q", path, configKeysBegin, configKeysEnd)
	}
	want, err := configKeysMarkdown(saga.ConfigSchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(path, []byte(before+configKeysBegin+want+configKeysEnd+after), 0o600); err != nil { // #nosec G703 -- the const path above
			t.Fatal(err)
		}
		return
	}
	if current != want {
		t.Errorf("the config keys table in %s is out of date; run "+
			"`go test ./internal/cli -run TestTheReferenceListsEveryConfigKey -update`\n--- want ---\n%s\n--- got ---\n%s",
			path, want, current)
	}
}
