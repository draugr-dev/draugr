package sarif

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// readForeign reads one SARIF document for a test, failing it on an error.
func readForeign(t *testing.T, doc string, roots ...string) (Report, []string) {
	t.Helper()
	rep, outside, err := FromForeignSARIF([]byte(doc), roots)
	if err != nil {
		t.Fatalf("FromForeignSARIF: %v", err)
	}
	return rep, outside
}

func TestForeignSARIFReadsASecuritySeverityWrittenEitherWay(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"x","rules":[
			{"id":"str","properties":{"security-severity":"8.1"}},
			{"id":"num","properties":{"security-severity":9.8}},
			{"id":"word","properties":{"security-severity":"high"}},
			{"id":"obj","properties":{"security-severity":{"v":1}}}]}},
		"results":[
			{"ruleId":"str"},
			{"ruleId":"num"},
			{"ruleId":"word"},
			{"ruleId":"obj"},
			{"ruleId":"str","properties":{"security-severity":7.5}},
			{"ruleId":"num","properties":{"security-severity":null}}]}]}`)
	want := []struct {
		score float64
		has   bool
	}{{8.1, true}, {9.8, true}, {0, false}, {0, false}, {7.5, true}, {9.8, true}}
	for i, w := range want {
		r := rep.Results[i]
		if r.Score != w.score || r.HasScore != w.has {
			t.Errorf("result %d (%s): score %v %v, want %v %v", i, r.RuleID, r.Score, r.HasScore, w.score, w.has)
		}
	}
}

func TestForeignSARIFReadsNoneOfDraugrsOwnProperties(t *testing.T) {
	// Every one of these is a decision Draugr records about a finding it ranked. In somebody else's
	// file they are claims Draugr never made, and reading them would let the file set its own
	// findings aside or rank itself.
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"vendor"}},
		"results":[{"ruleId":"r","message":{"text":"m"},
			"properties":{"priority":"P4","aside":"generated","nonShipping":"test","tool":"gitleaks",
				"control":"secrets","component":"other","priorityCap":"P4","title":"t",
				"draugr/rating":{"severity":"low"},"correlation":{"countedUnder":"x"},
				"reachability":{"state":"unreachable"},"historical":true,"providerOperated":true,
				"labels":["a"],"package":"lib","escalation":{"to":"low"}},
			"suppressions":[{"kind":"external","justification":"fine",
				"properties":{"origin":"saga","acceptedBy":"someone","expires":"2099-01-01"}}]}]}]}`)
	r := rep.Results[0]
	if r.Tool != "vendor" || r.Priority != "" || r.Aside != "" || r.NonShipping != "" || r.Control != "" ||
		r.Component != "" || r.PriorityCap != "" || r.Rating != nil || r.Correlation != nil ||
		r.Reachability != nil || r.Historical || r.ProviderOperated || r.Package != nil || r.Escalation != nil ||
		r.Message != "m" {
		t.Errorf("read Draugr's own properties from a foreign file: %+v", r)
	}
	if r.Suppression == nil || r.Suppression.Origin != OriginScanner || r.Suppression.Justification != "fine" ||
		r.Suppression.Expires != "" {
		t.Errorf("suppression = %+v, want the scanner's own, with nothing read from its property bag", r.Suppression)
	}
}

func TestForeignSARIFResolvesARuleByIndex(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{
		"tool":{"driver":{"name":"x","rules":[
			{"id":"first"},
			{"id":"second","shortDescription":{"text":"Second rule"},"defaultConfiguration":{"level":"error"},
				"properties":{"security-severity":"9.0"}}]}},
		"results":[
			{"ruleIndex":1,"message":{"text":"Second rule"}},
			{"rule":{"index":0}},
			{"rule":{"id":"by-ref"}},
			{"ruleId":"named","ruleIndex":0},
			{"message":{"text":"no rule"}}]}]}`)
	got := []string{}
	for _, r := range rep.Results {
		got = append(got, r.RuleID)
	}
	if want := []string{"second", "first", "by-ref", "named", ""}; !slices.Equal(got, want) {
		t.Errorf("rule ids = %q, want %q", got, want)
	}
	if r := rep.Results[0]; r.Level != LevelError || !r.HasScore || r.Score != 9.0 {
		t.Errorf("a result named by index inherits nothing from its rule: %+v", r)
	}
	if rep.Rules["second"].ShortDescription != "Second rule" {
		t.Errorf("rules = %+v, want the run's rules kept", rep.Rules)
	}
}

func TestForeignSARIFRefusesAnIndexThatNamesNothing(t *testing.T) {
	for name, doc := range map[string]string{
		"rule":     `{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"r"}]}},"results":[{"ruleIndex":3}]}]}`,
		"rule ref": `{"version":"2.1.0","runs":[{"results":[{"rule":{"index":-1}}]}]}`,
		"artifact": `{"version":"2.1.0","runs":[{"artifacts":[{"location":{"uri":"a.go"}}],` +
			`"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"index":2}}}]}]}]}`,
	} {
		_, _, err := FromForeignSARIF([]byte(doc), nil)
		if err == nil || !strings.HasPrefix(err.Error(), "run 1, result 1: ") || !strings.Contains(err.Error(), " is not an entry of ") {
			t.Errorf("%s: err = %v, want the result and the index named", name, err)
		}
	}
}

func TestForeignSARIFRefusesWhatIsNotSARIF(t *testing.T) {
	for doc, want := range map[string]string{
		`junk`:                            "not a SARIF log",
		`{"a":1}`:                         `neither a "version" nor a "runs"`,
		`{"version":"2.0.0","runs":[{}]}`: `states SARIF version "2.0.0", and Draugr reads 2.1.0`,
		`{"runs":[{}]}`:                   `states no SARIF version, and Draugr reads 2.1.0`,
		`{"version":"2.1.0","runs":[]}`:   "holds no runs",
	} {
		_, _, err := FromForeignSARIF([]byte(doc), nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", doc, err, want)
		}
	}
	if _, _, err := FromForeignSARIF([]byte(`junk`), nil); !errors.Is(err, ErrNotSARIF) {
		t.Errorf("junk: err = %v, want ErrNotSARIF", err)
	}
}

// located reads one result at the artifact location given, in a run with the bases and artifacts
// given, and returns its path and whether it was reported as outside.
func located(t *testing.T, run, location string, roots ...string) (string, bool) {
	t.Helper()
	doc := `{"version":"2.1.0","runs":[{` + run + `"results":[{"ruleId":"r","locations":[{"physicalLocation":` +
		`{"artifactLocation":` + location + `,"region":{"startLine":7}}}]}]}]}`
	rep, outside := readForeign(t, doc, roots...)
	r := rep.Results[0]
	if r.Location.StartLine != 7 {
		t.Errorf("%s: line %d, want 7", location, r.Location.StartLine)
	}
	return r.Location.URI, slices.Contains(outside, r.Location.URI)
}

func TestForeignSARIFMakesPathsRelativeToTheCheckout(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	rootURI := "file://" + filepath.ToSlash(root) + "/"
	cases := []struct {
		name, run, location string
		want                string
		outside             bool
	}{
		{"relative", ``, `{"uri":"src/app.go"}`, "src/app.go", false},
		{"dot relative", ``, `{"uri":"./src/../src/app.go"}`, "src/app.go", false},
		{"escaped", ``, `{"uri":"src/my%20app.go"}`, "src/my app.go", false},
		{"undefined base", ``, `{"uri":"src/app.go","uriBaseId":"%SRCROOT%"}`, "src/app.go", false},
		{"base in the checkout", `"originalUriBaseIds":{"SRC":{"uri":"` + rootURI + `"}},`,
			`{"uri":"src/app.go","uriBaseId":"SRC"}`, "src/app.go", false},
		{"base below the checkout", `"originalUriBaseIds":{"SRC":{"uri":"` + rootURI + `svc/"}},`,
			`{"uri":"app.go","uriBaseId":"SRC"}`, "svc/app.go", false},
		{"base on a build machine", `"originalUriBaseIds":{"SRC":{"uri":"file:///home/runner/work/x/x/"}},`,
			`{"uri":"src/app.go","uriBaseId":"SRC"}`, "src/app.go", false},
		{"base relative to a base", `"originalUriBaseIds":{"SVC":{"uri":"svc/","uriBaseId":"ROOT"},"ROOT":{"uri":"` + rootURI + `"}},`,
			`{"uri":"app.go","uriBaseId":"SVC"}`, "svc/app.go", false},
		{"artifact by index", `"artifacts":[{"location":{"uri":"lib/a.go","uriBaseId":"%SRCROOT%"}}],`,
			`{"index":0}`, "lib/a.go", false},
		{"index beside a URI, no artifacts", ``, `{"uri":"lib/b.go","uriBaseId":"%SRCROOT%","index":0}`, "lib/b.go", false},
		{"URI beside a listed index", `"artifacts":[{"location":{"uri":"lib/a.go"}}],`, `{"uri":"lib/c.go","index":0}`, "lib/c.go", false},
		{"absolute in the checkout", ``, `{"uri":"` + filepath.ToSlash(root) + `/src/app.go"}`, "src/app.go", false},
		{"file URI in the checkout", ``, `{"uri":"` + rootURI + `src/app.go"}`, "src/app.go", false},
		{"in the second checkout", ``, `{"uri":"file://` + filepath.ToSlash(other) + `/lib/b.go"}`, "lib/b.go", false},
		{"absolute elsewhere", ``, `{"uri":"/opt/build/src/app.go"}`, "/opt/build/src/app.go", true},
		{"climbs out", ``, `{"uri":"../elsewhere/app.go"}`, "../elsewhere/app.go", true},
		{"another scheme", ``, `{"uri":"https://example.com/app.go"}`, "https://example.com/app.go", true},
		{"windows drive", ``, `{"uri":"C:/src/app.go"}`, "C:/src/app.go", true},
	}
	for _, c := range cases {
		got, outside := located(t, c.run, c.location, root, other)
		if got != c.want || outside != c.outside {
			t.Errorf("%s: %q outside=%v, want %q outside=%v", c.name, got, outside, c.want, c.outside)
		}
	}
}

func TestForeignSARIFListsEachOutsidePathOnce(t *testing.T) {
	loc := func(uri string) string {
		return `{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + uri + `"}}}]}`
	}
	_, outside := readForeign(t, `{"version":"2.1.0","runs":[{"results":[`+
		loc("/a/x.go")+`,`+loc("/a/x.go")+`,`+loc("in/repo.go")+`,`+loc("/b/y.go")+`]}]}`, t.TempDir())
	if want := []string{"/a/x.go", "/b/y.go"}; !slices.Equal(outside, want) {
		t.Errorf("outside = %q, want %q", outside, want)
	}
}

func TestForeignSARIFRefusesABaseLoop(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"originalUriBaseIds":{"A":{"uri":"a/","uriBaseId":"B"},"B":{"uri":"b/","uriBaseId":"A"}},` +
		`"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.go","uriBaseId":"A"}}}]}]}]}`
	if _, _, err := FromForeignSARIF([]byte(doc), nil); err == nil || !strings.Contains(err.Error(), "more than 8 entries of originalUriBaseIds") {
		t.Errorf("err = %v, want the loop refused", err)
	}
}

func TestForeignSARIFNamesEachRunsTool(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[
		{"tool":{"driver":{"name":"first"}},"results":[{"ruleId":"a","level":"note"}]},
		{"tool":{"driver":{"name":"second","rules":[{"id":"b","defaultConfiguration":{"level":"error"}}]}},
		 "results":[{"ruleId":"b"},{"ruleId":"c"}]}]}`)
	if rep.Tool != "first" {
		t.Errorf("report tool = %q, want the first run's", rep.Tool)
	}
	type got struct {
		tool  string
		level Level
	}
	var gots []got
	for _, r := range rep.Results {
		gots = append(gots, got{r.Tool, r.Level})
	}
	want := []got{{"first", LevelNote}, {"second", LevelError}, {"second", LevelWarning}}
	if !slices.Equal(gots, want) {
		t.Errorf("results = %+v, want %+v", gots, want)
	}
}

func TestForeignSARIFReadsAPackageOnlyInDraugrsShape(t *testing.T) {
	rep, _ := readForeign(t, `{"version":"2.1.0","runs":[{"results":[
		{"ruleId":"a","properties":{"package":{"name":"lodash","version":"4.17.15","fixedVersion":"4.17.21"}}},
		{"ruleId":"b","properties":{"package":"lodash"}},
		{"ruleId":"c","properties":{"package":["lodash"]}},
		{"ruleId":"d","properties":{"package":{}}}]}]}`)
	if p := rep.Results[0].Package; p == nil || p.Name != "lodash" || p.FixedVersion != "4.17.21" {
		t.Errorf("package object = %+v, want it read", p)
	}
	for _, r := range rep.Results[1:] {
		if r.Package != nil {
			t.Errorf("%s: package = %+v, want none from another shape", r.RuleID, r.Package)
		}
	}
}

func TestForeignSARIFSaysWhichIndexesARunHas(t *testing.T) {
	for doc, want := range map[string]string{
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"}]}},"results":[{"ruleIndex":7}]}]}`: "run 1, result 1: ruleIndex 7 is not an entry of tool.driver.rules, which has 4 rules (0 to 3)",
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"a"}]}},"results":[{"rule":{"index":1}}]}]}`:                             "run 1, result 1: rule.index 1 is not an entry of tool.driver.rules, which has 1 rule (index 0)",
		`{"version":"2.1.0","runs":[{"results":[{"ruleIndex":0}]}]}`:                                                                           "run 1, result 1: ruleIndex 0 is not an entry of tool.driver.rules, which has no rules",
		`{"version":"2.1.0","runs":[{"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"index":2}}}]}]}]}`:        "run 1, result 1: artifactLocation.index 2 has no uri beside it and is not an entry of artifacts, which has no artifacts; add a uri",
	} {
		if _, _, err := FromForeignSARIF([]byte(doc), nil); err == nil || err.Error() != want {
			t.Errorf("err = %v\nwant %s", err, want)
		}
	}
}
