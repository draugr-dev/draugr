package scanners

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// flagValue is the value after flag in argv, and whether the flag is there.
func flagValue(argv []string, flag string) (string, bool) {
	i := slices.Index(argv, flag)
	if i < 0 || i == len(argv)-1 {
		return "", false
	}
	return argv[i+1], true
}

// Each option reaches Nuclei as the flag it names, with the value the descriptor wrote.
func TestNucleiOptionsBecomeFlags(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	args, err := nucleiOptionArgs(plugin.Config{
		"rateLimit":   20,
		"concurrency": 5,
		"timeout":     "30s",
		"retries":     0,
		"tags":        []any{"cve", "exposure"},
		"excludeTags": []any{"wordpress"},
		"templates":   []any{"./ours", "checks/one.yaml"},
		"interactsh":  false,
	})
	if err != nil {
		t.Fatal(err)
	}
	for flag, want := range map[string]string{
		"-rl":      "20",
		"-c":       "5",
		"-timeout": "30",
		"-retries": "0",
		"-tags":    "cve,exposure",
		"-etags":   "headers,intrusive,wordpress",
	} {
		if got, ok := flagValue(args, flag); !ok || got != want {
			t.Errorf("%s = %q (present %v), want %q; argv %v", flag, got, ok, want, args)
		}
	}
	var templates []string
	for i, a := range args {
		if a == "-t" {
			templates = append(templates, args[i+1])
		}
	}
	want := []string{"'" + filepath.Join(dir, "ours") + "'", "'" + filepath.Join(dir, "checks", "one.yaml") + "'"}
	if !slices.Equal(templates, want) {
		t.Errorf("-t values = %v, want %v", templates, want)
	}
	if !slices.Contains(args, "-ni") {
		t.Errorf("interactsh: false should pass -ni: %v", args)
	}
}

// Unset options pass no flag, so Nuclei's own defaults apply, and interactsh: true is the default
// rather than a flag.
func TestNucleiUnsetOptionsPassNoFlag(t *testing.T) {
	for name, cfg := range map[string]plugin.Config{
		"nil":             nil,
		"empty":           {},
		"interactsh true": {"interactsh": true},
		"intrusive false": {"intrusive": false},
	} {
		args, err := nucleiOptionArgs(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := []string{"-etags", "headers,intrusive"}; !slices.Equal(args, want) {
			t.Errorf("%s: args = %v, want %v", name, args, want)
		}
	}
}

// intrusive: true is what lets those templates run, and the only thing that does.
func TestNucleiIntrusiveIsExcludedUnlessTheOptionIsSet(t *testing.T) {
	args, err := nucleiOptionArgs(plugin.Config{"intrusive": true})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := flagValue(args, "-etags"); got != "headers" {
		t.Errorf("-etags = %q with intrusive: true, want headers alone", got)
	}
	args, err = nucleiOptionArgs(plugin.Config{"intrusive": true, "tags": []any{"intrusive"}})
	if err != nil {
		t.Fatalf("tags: [intrusive] with intrusive: true should run: %v", err)
	}
	if got, _ := flagValue(args, "-tags"); got != "intrusive" {
		t.Errorf("-tags = %q, want intrusive", got)
	}
}

// The operator's exclusions are added to Draugr's, never in place of them.
func TestNucleiExcludeTagsAddToTheBuiltInOnes(t *testing.T) {
	args, err := nucleiOptionArgs(plugin.Config{"excludeTags": []any{"headers", "oast", "intrusive"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := flagValue(args, "-etags"); got != "headers,intrusive,oast" {
		t.Errorf("-etags = %q, want headers,intrusive,oast", got)
	}
	args, err = nucleiOptionArgs(plugin.Config{"intrusive": true, "excludeTags": []any{"oast"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := flagValue(args, "-etags"); got != "headers,oast" {
		t.Errorf("-etags = %q, want headers,oast", got)
	}
}

// A tags list that would run what the exclusions keep out, or select templates only to exclude
// them, is refused with the option to use instead.
func TestNucleiRefusesTagsThatUndoAnExclusion(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  plugin.Config
		want string
	}{
		"headers": {plugin.Config{"tags": []any{"cve", "headers"}}, "enable controls.headers instead"},
		"headers with intrusive": {plugin.Config{"intrusive": true, "tags": []any{"headers"}},
			"enable controls.headers instead"},
		"intrusive without the option": {plugin.Config{"tags": []any{"intrusive"}}, "intrusive: true"},
		"intrusive with the option off": {plugin.Config{"intrusive": false, "tags": []any{"intrusive"}},
			"intrusive: true"},
		"a tag in both lists": {plugin.Config{"tags": []any{"cve"}, "excludeTags": []any{"cve"}},
			`"cve" is in both tags and excludeTags`},
		"intrusive excluded and asked for": {plugin.Config{"intrusive": true, "excludeTags": []any{"intrusive"}},
			"excludeTags lists intrusive and intrusive is true"},
	} {
		if _, err := nucleiOptionArgs(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to say %q", name, err, tc.want)
		}
	}
}

// Each integer option takes its bounds and refuses one past either end, naming the option.
func TestNucleiIntegerOptionsAreBounded(t *testing.T) {
	for _, o := range nucleiIntOptions {
		for _, v := range []any{o.min, o.max, float64(o.max)} {
			if _, err := nucleiOptionArgs(plugin.Config{o.key: v}); err != nil {
				t.Errorf("%s: %v should be accepted: %v", o.key, v, err)
			}
		}
		for _, v := range []int{o.min - 1, o.max + 1} {
			_, err := nucleiOptionArgs(plugin.Config{o.key: v})
			if err == nil || !strings.Contains(err.Error(), "nuclei: "+o.key+":") {
				t.Errorf("%s: %d should be refused naming the option, got %v", o.key, v, err)
			}
		}
	}
}

func TestNucleiTimeoutIsWholeSecondsInRange(t *testing.T) {
	for raw, want := range map[string]string{"1s": "1", "30s": "30", "2m": "120", "10m": "600"} {
		args, err := nucleiOptionArgs(plugin.Config{"timeout": raw})
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if got, _ := flagValue(args, "-timeout"); got != want {
			t.Errorf("%s: -timeout %q, want %q", raw, got, want)
		}
	}
	for _, raw := range []string{"500ms", "1.5s", "0s", "11m", "soon"} {
		_, err := nucleiOptionArgs(plugin.Config{"timeout": raw})
		if err == nil || !strings.Contains(err.Error(), "nuclei: timeout:") {
			t.Errorf("%s: want a refusal naming timeout, got %v", raw, err)
		}
	}
}

func TestNucleiRefusesTemplatesItCannotPass(t *testing.T) {
	for entry, want := range map[string]string{
		"https://example.com/t.yaml": "is a URL",
		"it's.yaml":                  "holds a quote",
		"  ":                         "an entry is empty",
	} {
		_, err := nucleiOptionArgs(plugin.Config{"templates": []any{entry}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", entry, err, want)
		}
	}
}

// The schema an editor and `draugr validate` use refuses what Nuclei would read differently: a tag
// with a capital, which Nuclei lowercases, or a comma, which it splits on.
func TestNucleiSchemaRefusesATagNucleiWouldRewrite(t *testing.T) {
	schema := json.RawMessage(nucleiConfigSchema)
	for _, tag := range []string{"Intrusive", "cve,headers", "../x"} {
		if err := plugin.ValidateConfig(schema, plugin.Config{"tags": []any{tag}}); err == nil {
			t.Errorf("tags: [%q] passed the schema", tag)
		}
		if err := plugin.ValidateConfig(schema, plugin.Config{"excludeTags": []any{tag}}); err == nil {
			t.Errorf("excludeTags: [%q] passed the schema", tag)
		}
	}
	full := plugin.Config{
		"intrusive": true, "rateLimit": 10, "concurrency": 2, "timeout": "15s", "retries": 3,
		"tags": []any{"cve"}, "excludeTags": []any{"wp-plugin"}, "templates": []any{"./t"}, "interactsh": false,
	}
	if err := plugin.ValidateConfig(schema, full); err != nil {
		t.Errorf("a block setting every option was refused: %v", err)
	}
	if err := plugin.ValidateConfig(schema, plugin.Config{"severity": "high"}); err == nil {
		t.Error("severity filters findings and is not an option")
	}
	err := plugin.ValidateConfig(schema, plugin.Config{"tags": []any{"Headers"}})
	if err == nil || !strings.Contains(err.Error(), "is not a lowercase tag") {
		t.Errorf("a refused tag should be described in words, got %v", err)
	}
}

// The schema's patterns are the shared literals, so a refusal names them in words and the loader,
// the editor and the scanner accept the same strings.
func TestNucleiSchemaUsesTheSharedPatterns(t *testing.T) {
	var s struct {
		Properties map[string]struct {
			Pattern string `json:"pattern"`
			Items   struct {
				Pattern string `json:"pattern"`
			} `json:"items"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(nucleiConfigSchema), &s); err != nil {
		t.Fatal(err)
	}
	for key, got := range map[string]string{
		"tags":        s.Properties["tags"].Items.Pattern,
		"excludeTags": s.Properties["excludeTags"].Items.Pattern,
	} {
		if got != plugin.TagPattern {
			t.Errorf("%s pattern = %s, want plugin.TagPattern", key, got)
		}
	}
	if got := s.Properties["timeout"].Pattern; got != plugin.DurationPattern {
		t.Errorf("timeout pattern = %s, want plugin.DurationPattern", got)
	}
}

// A job declares mutate only where its block sets intrusive: true.
func TestNucleiDeclaresMutateOnlyWithIntrusive(t *testing.T) {
	info := NewNuclei().Info()
	kinds := func(cfg plugin.Config) []plugin.EffectKind {
		var out []plugin.EffectKind
		for _, e := range plugin.EffectsFor(info, cfg) {
			out = append(out, e.Kind)
		}
		return out
	}
	for name, cfg := range map[string]plugin.Config{
		"unset": nil, "false": {"intrusive": false}, "tags only": {"tags": []any{"cve"}},
		"templates only": {"templates": []any{"./t"}},
	} {
		if got := kinds(cfg); !slices.Equal(got, []plugin.EffectKind{plugin.EffectNetwork}) {
			t.Errorf("%s: effects = %v, want network alone", name, got)
		}
	}
	if got := kinds(plugin.Config{"intrusive": true}); !slices.Equal(got,
		[]plugin.EffectKind{plugin.EffectNetwork, plugin.EffectMutate}) {
		t.Errorf("intrusive: true: effects = %v, want network and mutate", got)
	}
}

// Scan hands the options to Nuclei on both paths, the crawl and the specification, and records
// them in the provenance.
func TestNucleiScanPassesItsOptions(t *testing.T) {
	var argvs [][]string
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run: func(_ context.Context, a []string) ([]byte, error) {
			argvs = append(argvs, a)
			return nil, nil
		},
	}
	cfg := plugin.Config{"intrusive": true, "rateLimit": 7, "tags": []any{"cve"}}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example.com"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{
		URL: "https://x.example.com", Spec: &plugin.HostSpec{Path: writeSpec(t, specWithWrites)},
	}, cfg); err != nil {
		t.Fatal(err)
	}
	for _, argv := range argvs {
		if got, _ := flagValue(argv, "-etags"); got != "headers" {
			t.Errorf("-etags = %q, want headers: %v", got, argv)
		}
		if got, _ := flagValue(argv, "-rl"); got != "7" {
			t.Errorf("-rl = %q, want 7: %v", got, argv)
		}
	}
	got := map[string]string{}
	for _, f := range rep.Provenance[0].Fields {
		got[f.Key] = f.Value
	}
	if got["intrusive"] != "true" || got["tags"] != "cve" {
		t.Errorf("provenance = %v, want intrusive and tags recorded", got)
	}
}

// A refused block stops the scan before Nuclei is started.
func TestNucleiScanRefusesBeforeRunning(t *testing.T) {
	ran := false
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run:  func(context.Context, []string) ([]byte, error) { ran = true; return nil, nil },
	}
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example.com"},
		plugin.Config{"tags": []any{"intrusive"}})
	if err == nil {
		t.Fatal("tags: [intrusive] without intrusive: true ran")
	}
	if ran {
		t.Error("nuclei started for a block that was refused")
	}
}

func TestNucleiOptionFieldsRecordOnlyWhatIsSet(t *testing.T) {
	if f := nucleiOptionFields(nil); len(f) != 0 {
		t.Errorf("a default block recorded %v", f)
	}
	f := nucleiOptionFields(plugin.Config{
		"excludeTags": []any{"a", "b"}, "templates": []any{"./t"}, "interactsh": false,
	})
	want := []sarif.Field{
		{Key: "excludeTags", Value: "a, b"}, {Key: "templates", Value: "./t"}, {Key: "interactsh", Value: "false"},
	}
	if !slices.Equal(f, want) {
		t.Errorf("fields = %v, want %v", f, want)
	}
}

// nucleiScanOnly is the scanner as the engine sees it with Info and Scan alone, so a run neither
// warms templates nor asks a binary for its version.
type nucleiScanOnly struct{ s nucleiScanner }

func (n nucleiScanOnly) Info() plugin.ScannerInfo { return n.s.Info() }

func (n nucleiScanOnly) Scan(ctx context.Context, t plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	return n.s.Scan(ctx, t, cfg)
}

// runDast scans two components, api and web, each with a host of its own, under the real dast
// control, and returns the run's error and the argv each host's Nuclei was given.
func runDast(t *testing.T, apiNuclei map[string]any, allow ...string) (map[string][]string, error) {
	t.Helper()
	var mu sync.Mutex
	argvs := map[string][]string{}
	s := nucleiScanner{
		info: NewNuclei().Info(),
		run: func(_ context.Context, a []string) ([]byte, error) {
			url, _ := flagValue(a, "-u")
			mu.Lock()
			argvs[url] = a
			mu.Unlock()
			return nil, nil
		},
	}
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewDAST())
	reg.RegisterScanner(nucleiScanOnly{s})
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"dast": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Hosts: []saga.Host{{Name: "api", URL: "https://api.example.com"}},
				Controls: map[string]saga.ControllerSettings{"dast": {"nuclei": apiNuclei}}},
			{Name: "web", Hosts: []saga.Host{{Name: "web", URL: "https://web.example.com"}}},
		},
	}
	_, err := engine.New(reg, engine.WithAllowedEffects(allow)).Run(context.Background(), model)
	return argvs, err
}

// Through the real dast control and the engine: intrusive: true on one of two components is refused
// unless the run accepts mutate, and the refusal names what the templates would do. Accepted, only
// that component's scan runs the intrusive templates.
func TestNucleiIntrusiveNeedsMutateAccepted(t *testing.T) {
	argvs, err := runDast(t, map[string]any{"intrusive": true})
	if err == nil || !strings.Contains(err.Error(), "uploading a file with PUT") {
		t.Fatalf("a run without mutate accepted: err = %v", err)
	}
	if _, ran := argvs["https://api.example.com"]; ran {
		t.Error("the intrusive scan ran without mutate accepted")
	}

	argvs, err = runDast(t, map[string]any{"intrusive": true}, string(plugin.EffectMutate))
	if err != nil {
		t.Fatalf("mutate accepted, and the run failed: %v", err)
	}
	for url, want := range map[string]string{
		"https://api.example.com": "headers",
		"https://web.example.com": "headers,intrusive",
	} {
		if got, _ := flagValue(argvs[url], "-etags"); got != want {
			t.Errorf("%s: -etags %q, want %q", url, got, want)
		}
	}
}

// Without intrusive, dast needs nothing accepted, as before.
func TestNucleiDefaultRunNeedsNothingAccepted(t *testing.T) {
	argvs, err := runDast(t, map[string]any{"rateLimit": 10})
	if err != nil {
		t.Fatalf("a dast run without intrusive needed something accepted: %v", err)
	}
	if got, _ := flagValue(argvs["https://api.example.com"], "-rl"); got != "10" {
		t.Errorf("api's -rl = %q, want 10", got)
	}
	if _, set := flagValue(argvs["https://web.example.com"], "-rl"); set {
		t.Error("web set no rate limit and got one")
	}
}
