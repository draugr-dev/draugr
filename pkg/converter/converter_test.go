package converter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// valid is a file setting every property a converter may, which each test changes in one place.
func valid() map[string]any {
	return map[string]any{
		"contract":   ID,
		"version":    float64(Version),
		"converter":  map[string]any{"name": "acme-deps", "version": "0.3.0"},
		"source":     map[string]any{"tool": "Acme Deps", "version": "4.1", "file": "acme.json", "sha256": strings.Repeat("ab", 32)},
		"commit":     "0123456789abcdef",
		"repository": "https://example.com/shop.git",
		"written":    "2026-11-17T12:00:00Z",
		"results": []any{map[string]any{
			"ruleId":    "GHSA-35jh-r3h4-6jhm",
			"message":   "Command injection in lodash",
			"severity":  "high",
			"score":     7.2,
			"location":  map[string]any{"path": "package-lock.json", "line": float64(12)},
			"package":   map[string]any{"name": "lodash", "version": "4.17.20", "fixedVersion": "4.17.21", "purl": "pkg:npm/lodash@4.17.20", "ecosystem": "npm"},
			"cwe":       []any{"CWE-77"},
			"labels":    map[string]any{"triage": "security-team"},
			"reachable": true,
			"raise":     map[string]any{"priority": "P1", "reason": "on the internal exploited list"},
		}},
	}
}

func encode(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// result is the first result of doc, to change.
func result(doc map[string]any) map[string]any {
	return doc["results"].([]any)[0].(map[string]any)
}

func TestReadsAFileSettingEveryAllowedProperty(t *testing.T) {
	doc, err := Read(encode(t, valid()), Properties)
	if err != nil {
		t.Fatal(err)
	}
	r := doc.Results[0]
	if !slices.Equal(r.Sets(), Properties) {
		t.Errorf("sets %v, want every property in the allow-list's order", r.Sets())
	}
	if doc.Converter.Name != "acme-deps" || doc.Commit != "0123456789abcdef" || r.Package.PURL != "pkg:npm/lodash@4.17.20" ||
		r.Raise.Priority != "P1" || !*r.Reachable || r.Labels["triage"] != "security-team" || r.Location.Line != 12 {
		t.Errorf("read %+v", doc)
	}
}

func TestAResultWithNoneOfDraugrsPropertiesNeedsNoGrant(t *testing.T) {
	doc := valid()
	r := result(doc)
	for _, p := range Properties {
		delete(r, string(p))
	}
	got, err := Read(encode(t, doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results[0].Sets()) != 0 {
		t.Errorf("sets %v, want none", got.Results[0].Sets())
	}
}

func TestTheContractVersionIsHeldExactly(t *testing.T) {
	for _, c := range []struct {
		name    string
		version any
		says    string
	}{
		{"older", float64(0), "contract version 0 is older than Draugr reads, version 1. Update the converter"},
		{"newer", float64(2), "contract version 2 is unknown here. Draugr reads version 1"},
		{"not a whole number", 1.5, "contract version 1.5 is not one Draugr reads. It reads 1"},
		{"a word", "one", `contract version "one" is not one Draugr reads. It reads 1`},
		{"missing", nil, "states no contract version. Draugr reads version 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := valid()
			if c.version == nil {
				delete(doc, "version")
			} else {
				doc["version"] = c.version
			}
			if _, err := Read(encode(t, doc), Properties); err == nil || err.Error() != c.says {
				t.Errorf("error %v, want %q", err, c.says)
			}
		})
	}
}

func TestAFileThatIsNotAConverterFileIsRefused(t *testing.T) {
	for name, data := range map[string]string{
		"not JSON":       "{",
		"a list":         "[]",
		"SARIF":          `{"version": "2.1.0", "runs": []}`,
		"another id":     `{"contract": "other", "version": 1}`,
		"an empty value": `{}`,
	} {
		if _, err := Read([]byte(data), Properties); err == nil || !strings.Contains(err.Error(), "not a converter file") {
			t.Errorf("%s: error %v, want not a converter file", name, err)
		}
	}
}

// TestEveryForbiddenPropertyIsRefusedByName holds each property no converter may set to an error
// naming it, on a result and at the top of the file, even where the descriptor would grant every
// allowed property: none of them is read and dropped.
func TestEveryForbiddenPropertyIsRefusedByName(t *testing.T) {
	for _, key := range Never {
		t.Run(key, func(t *testing.T) {
			doc := valid()
			result(doc)[key] = "anything"
			want := "results[0] sets " + key + ", which no converter may set"
			if _, err := Read(encode(t, doc), Properties); err == nil || err.Error() != want {
				t.Errorf("on a result: error %v, want %q", err, want)
			}
			doc = valid()
			doc[key] = []any{}
			want = "the file sets " + key + ", which no converter may set"
			if _, err := Read(encode(t, doc), Properties); err == nil || err.Error() != want {
				t.Errorf("on the file: error %v, want %q", err, want)
			}
		})
	}
}

func TestAnUnreachableVerdictIsRefusedAsALowering(t *testing.T) {
	doc := valid()
	result(doc)["reachable"] = false
	want := "results[0] sets reachable false, a lowering no converter may make"
	if _, err := Read(encode(t, doc), Properties); err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

func TestAPropertyTheDescriptorDoesNotGrantIsRefused(t *testing.T) {
	for _, p := range Properties {
		t.Run(string(p), func(t *testing.T) {
			granted := slices.DeleteFunc(slices.Clone(Properties), func(q Property) bool { return q == p })
			want := "results[0] sets " + string(p) + ", which converter.sets does not list"
			if _, err := Read(encode(t, valid()), granted); err == nil || err.Error() != want {
				t.Errorf("error %v, want %q", err, want)
			}
		})
	}
	// An empty value still sets the property.
	doc := valid()
	r := result(doc)
	for _, p := range Properties {
		delete(r, string(p))
	}
	r["cwe"] = []any{}
	if _, err := Read(encode(t, doc), nil); err == nil || !strings.Contains(err.Error(), "sets cwe") {
		t.Errorf("an empty cwe list: error %v, want it refused as setting cwe", err)
	}
}

func TestAVerdictNeedsAPackage(t *testing.T) {
	doc := valid()
	delete(result(doc), "package")
	want := "results[0] sets reachable with no package. A verdict is about a dependency"
	if _, err := Read(encode(t, doc), Properties); err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

// TestTheContractRefusesWhatItDoesNotDefine names the key and where it is, for a key the contract
// does not define at each level and for one it requires.
func TestTheContractRefusesWhatItDoesNotDefine(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(doc map[string]any)
		want   string
	}{
		{"unknown top key", func(d map[string]any) { d["runs"] = []any{} }, "the file has runs, a key contract version 1 does not define"},
		{"unknown result key", func(d map[string]any) { result(d)["level"] = "error" },
			"results[0] has level, a key contract version 1 does not define"},
		{"unknown package key", func(d map[string]any) { result(d)["package"].(map[string]any)["dev"] = true },
			"results[0].package has dev, a key contract version 1 does not define"},
		{"unknown converter key", func(d map[string]any) { d["converter"].(map[string]any)["sets"] = []any{"aside"} },
			"converter has sets, a key contract version 1 does not define"},
		{"missing commit", func(d map[string]any) { delete(d, "commit") }, "the file has no commit, which the contract requires"},
		{"missing rule", func(d map[string]any) { delete(result(d), "ruleId") }, "results[0] has no ruleId, which the contract requires"},
		{"missing raise reason", func(d map[string]any) { delete(result(d)["raise"].(map[string]any), "reason") },
			"results[0].raise has no reason, which the contract requires"},
		{"result not an object", func(d map[string]any) { d["results"] = []any{"x"} }, "results[0] is a string, and the contract takes an object"},
		{"severity", func(d map[string]any) { result(d)["severity"] = "urgent" }, `results[0].severity is "urgent", not one of critical, high, medium, low`},
		{"raise band", func(d map[string]any) { result(d)["raise"].(map[string]any)["priority"] = "P0" },
			`results[0].raise.priority is "P0", not one of P1, P2, P3, P4`},
		{"type", func(d map[string]any) { result(d)["message"] = 3.0 }, "results[0].message is a number, and the contract takes string"},
		{"pattern", func(d map[string]any) { result(d)["cwe"] = []any{"CWE78"} }, `results[0].cwe[0] is "CWE78", not in the form the contract takes`},
		{"purl", func(d map[string]any) { result(d)["package"].(map[string]any)["purl"] = "lodash" },
			`results[0].package.purl is "lodash", not in the form the contract takes`},
		{"empty", func(d map[string]any) { result(d)["ruleId"] = "" }, "results[0].ruleId is empty, and the contract takes a value"},
		{"score", func(d map[string]any) { result(d)["score"] = 11.0 }, "results[0].score is 11, outside 0 to 10"},
		{"twice", func(d map[string]any) { result(d)["cwe"] = []any{"CWE-77", "CWE-77"} }, "results[0].cwe lists one value twice"},
		{"line", func(d map[string]any) { result(d)["location"].(map[string]any)["line"] = 0.0 },
			"results[0].location.line is 0, below 1"},
		{"label", func(d map[string]any) { result(d)["labels"] = map[string]any{"team": 3.0} },
			"results[0].labels.team is a number, and the contract takes string"},
		{"labels not an object", func(d map[string]any) { result(d)["labels"] = []any{} },
			"results[0].labels is a list, and the contract takes an object"},
		{"fraction", func(d map[string]any) { result(d)["location"].(map[string]any)["line"] = 1.5 },
			"results[0].location.line is a number, and the contract takes integer"},
		{"written", func(d map[string]any) { d["written"] = "yesterday" }, `written is "yesterday", not in the form the contract takes`},
		{"reachable", func(d map[string]any) { result(d)["reachable"] = "yes" }, `results[0].reachable is "yes", and the contract takes only true`},
		{"results not a list", func(d map[string]any) { d["results"] = "none" }, "results is a string, and the contract takes array"},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := valid()
			c.change(doc)
			_, err := Read(encode(t, doc), Properties)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Errorf("error %v, want %q", err, c.want)
			}
		})
	}
}

// TestTheSchemaNamesExactlyTheAllowList keeps the contract's schema and the allow-list in step: a
// result's keys are the finding's own and the allowed properties, and no forbidden one is defined.
func TestTheSchemaNamesExactlyTheAllowList(t *testing.T) {
	var root struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(SchemaJSON, &root); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range root.Defs["result"].Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"location", "message", "ruleId", "score", "severity"}
	for _, p := range Properties {
		want = append(want, string(p))
	}
	sort.Strings(want)
	if !slices.Equal(keys, want) {
		t.Errorf("the schema's result keys are %v, want the finding's own and the allow-list, %v", keys, want)
	}
	for _, k := range Never {
		if Allowed(k) {
			t.Errorf("%s is both allowed and never allowed", k)
		}
	}
}

// TestTheReferenceNamesEveryKey holds docs/reference/converter-contract.md to the schema: every key
// the contract defines, and every property no converter may set, is on the page a converter's author
// reads.
func TestTheReferenceNamesEveryKey(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference", "converter-contract.md"))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	var walk func(node map[string]any)
	walk = func(node map[string]any) {
		props, _ := node["properties"].(map[string]any)
		for k, sub := range props {
			keys = append(keys, k)
			if m, ok := sub.(map[string]any); ok {
				walk(m)
			}
		}
	}
	c := contract()
	walk(c.root)
	for _, def := range c.defs {
		walk(def.(map[string]any))
	}
	for _, k := range append(keys, Never...) {
		named := false
		for _, form := range []string{"`" + k + "`", "." + k + "`", "`" + k + "."} {
			named = named || strings.Contains(string(page), form)
		}
		if !named {
			t.Errorf("the reference does not name %s", k)
		}
	}
}

func TestHowAnErrorNamesAValue(t *testing.T) {
	for v, want := range map[any]string{nil: "null", true: "a boolean", 1.0: "a number", "x": "a string", 3: "int"} {
		if got := kindOf(v); got != want {
			t.Errorf("kindOf(%v) = %q, want %q", v, got, want)
		}
	}
	if got := show(strings.Repeat("a", 60)); len(got) != 40 || !strings.HasSuffix(got, "...") {
		t.Errorf("show cut a long value to %q", got)
	}
	if got := show(map[string]any{"a": 1.0}); got != `{"a":1}` {
		t.Errorf("show(object) = %q", got)
	}
	if got := lastClause(`validating root: required: missing properties: ["x"]`); got != `["x"]` {
		t.Errorf("lastClause = %q", got)
	}
	if got := lastClause("no colon"); got != "no colon" {
		t.Errorf("lastClause = %q", got)
	}
}

func TestAllowedAndForbidden(t *testing.T) {
	if !Allowed("cwe") || Allowed("aside") || !Forbidden("aside") || Forbidden("cwe") {
		t.Error("Allowed and Forbidden disagree with the lists")
	}
}
