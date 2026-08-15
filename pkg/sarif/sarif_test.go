package sarif

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMarshalSARIFStructure(t *testing.T) {
	r := Report{Tool: "trivy", Results: []Result{
		{RuleID: "CVE-1", Level: LevelError, Message: "boom", Location: Location{URI: "img", StartLine: 5}},
	}}
	data, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	// Must be valid JSON with the SARIF shape.
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if log["version"] != Version {
		t.Errorf("version = %v", log["version"])
	}
	if !strings.Contains(string(data), "\"$schema\"") || !strings.Contains(string(data), "artifactLocation") {
		t.Errorf("missing SARIF fields:\n%s", data)
	}
}

func TestMarshalSARIFTagsRulesWithScanner(t *testing.T) {
	r := Report{Results: []Result{
		{Tool: "semgrep", RuleID: "rule-a", Level: LevelError, Message: "x"},
		{Tool: "semgrep", RuleID: "rule-a", Level: LevelError, Message: "y"}, // same rule, deduped
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelWarning, Message: "z"},
	}}
	data, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	rules := log.Runs[0].Tool.Driver.Rules
	tagByRule := map[string][]string{}
	for _, rule := range rules {
		tagByRule[rule.ID] = rule.Properties.Tags
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 deduped rules, got %d", len(rules))
	}
	if got := tagByRule["rule-a"]; len(got) != 1 || got[0] != "scanner:semgrep" {
		t.Errorf("rule-a tags = %v, want [scanner:semgrep]", got)
	}
	if got := tagByRule["CVE-1"]; len(got) != 1 || got[0] != "scanner:trivy" {
		t.Errorf("CVE-1 tags = %v, want [scanner:trivy]", got)
	}
}

func TestMarshalSARIFTagsUnionMultipleScanners(t *testing.T) {
	// The same ruleId produced by two scanners → both tags, sorted.
	r := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-9", Level: LevelError, Message: "a"},
		{Tool: "trivy-fs", RuleID: "CVE-9", Level: LevelError, Message: "b"},
	}}
	data, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"scanner:trivy"`) || !strings.Contains(string(data), `"scanner:trivy-fs"`) {
		t.Errorf("expected both scanner tags:\n%s", data)
	}
}

func TestSARIFRoundTrip(t *testing.T) {
	orig := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelError, Message: "boom", Location: Location{URI: "img", StartLine: 5}},
		{Tool: "grype", RuleID: "CVE-2", Level: LevelWarning, Message: "meh"},
	}}
	data, err := orig.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 {
		t.Fatalf("round-trip results = %d, want 2", len(got.Results))
	}
	// Multi-tool grouping preserves per-result tool.
	tools := map[string]bool{}
	for _, res := range got.Results {
		tools[res.Tool] = true
	}
	if !tools["trivy"] || !tools["grype"] {
		t.Errorf("tools not preserved: %v", tools)
	}
	// Location round-trips.
	for _, res := range got.Results {
		if res.RuleID == "CVE-1" && (res.Location.URI != "img" || res.Location.StartLine != 5) {
			t.Errorf("location lost: %+v", res.Location)
		}
	}
}

// Some tools (e.g. Gitleaks) emit results with no "level". SARIF 2.1.0 says such a result
// defaults to "warning" when there's no rule configuration to say otherwise.
func TestFromSARIFDefaultsAbsentLevelToWarning(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "gitleaks"}},
			"results": [{"ruleId": "aws-key", "message": {"text": "leaked key"}}]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(got.Results))
	}
	if got.Results[0].Level != LevelWarning {
		t.Errorf("absent level = %q, want warning", got.Results[0].Level)
	}
}

// Semgrep-style SARIF: results omit "level" and inherit it from the rule's
// defaultConfiguration. The parser must resolve the rule level (and fall back to warning
// for a result whose rule has no configured level).
func TestFromSARIFResolvesLevelFromRule(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "semgrep",
				"rules": [
					{"id": "sql-injection", "defaultConfiguration": {"level": "error"}},
					{"id": "todo-comment", "defaultConfiguration": {"level": "note"}}
				]
			}},
			"results": [
				{"ruleId": "sql-injection", "message": {"text": "tainted query"}},
				{"ruleId": "todo-comment", "message": {"text": "TODO"}},
				{"ruleId": "unknown-rule", "message": {"text": "no rule config"}}
			]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Level{
		"sql-injection": LevelError,
		"todo-comment":  LevelNote,
		"unknown-rule":  LevelWarning, // rule not found → default
	}
	if len(got.Results) != len(want) {
		t.Fatalf("results = %d, want %d", len(got.Results), len(want))
	}
	for _, r := range got.Results {
		if r.Level != want[r.RuleID] {
			t.Errorf("%s level = %q, want %q", r.RuleID, r.Level, want[r.RuleID])
		}
	}
}

// An explicit result-level "level" wins over the rule's defaultConfiguration.
func TestFromSARIFResultLevelOverridesRule(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "t",
				"rules": [{"id": "r", "defaultConfiguration": {"level": "note"}}]
			}},
			"results": [{"ruleId": "r", "level": "error", "message": {"text": "x"}}]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 || got.Results[0].Level != LevelError {
		t.Fatalf("result level should override rule default, got %+v", got.Results)
	}
}

// A result the tool marks as suppressed (e.g. Semgrep's in-source `nosem`) is not an active
// finding and must be dropped during parsing.
func TestFromSARIFSkipsSuppressed(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "semgrep"}},
			"results": [
				{"ruleId": "kept", "level": "error", "message": {"text": "real"}},
				{"ruleId": "hidden", "level": "error", "message": {"text": "nosem"},
				 "suppressions": [{"kind": "inSource"}]}
			]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 {
		t.Fatalf("results = %d, want 1 (suppressed dropped)", len(got.Results))
	}
	if got.Results[0].RuleID != "kept" {
		t.Errorf("kept the wrong result: %q", got.Results[0].RuleID)
	}
}

// Trivy-style SARIF: the numeric score lives in the rule's properties as a
// "security-severity" string, keyed to results by ruleId. A result-level property overrides.
func TestFromSARIFParsesSecuritySeverity(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "trivy",
				"rules": [{"id": "CVE-1", "properties": {"security-severity": "7.5"}}]
			}},
			"results": [
				{"ruleId": "CVE-1", "level": "warning", "message": {"text": "from rule"}},
				{"ruleId": "CVE-1", "level": "warning", "message": {"text": "result override"},
				 "properties": {"security-severity": "9.3"}},
				{"ruleId": "no-score", "level": "warning", "message": {"text": "none"}}
			]
		}]
	}`)
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	byMsg := map[string]Result{}
	for _, r := range got.Results {
		byMsg[r.Message] = r
	}
	if r := byMsg["from rule"]; !r.HasScore || r.Score != 7.5 {
		t.Errorf("rule-inherited score = %v (has=%v), want 7.5", r.Score, r.HasScore)
	}
	if r := byMsg["result override"]; !r.HasScore || r.Score != 9.3 {
		t.Errorf("result override score = %v, want 9.3", r.Score)
	}
	if r := byMsg["none"]; r.HasScore {
		t.Errorf("finding with no score should have HasScore=false, got %v", r.Score)
	}
	// The scored finding normalizes to critical despite a "warning" level.
	if s := byMsg["result override"].Severity(""); s != SeverityCritical {
		t.Errorf("severity = %q, want critical", s)
	}
}

func TestSARIFScoreRoundTrips(t *testing.T) {
	orig := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelWarning, Message: "x", Score: 7.5, HasScore: true},
	}}
	data, err := orig.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 || !got.Results[0].HasScore || got.Results[0].Score != 7.5 {
		t.Fatalf("score did not round-trip: %+v", got.Results)
	}
}

func TestFromSARIFInvalid(t *testing.T) {
	if _, err := FromSARIF([]byte("{not json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestMarshalEmptyReport(t *testing.T) {
	data, err := Report{}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 0 {
		t.Errorf("empty report should round-trip to zero results, got %d", len(got.Results))
	}
}

func TestMarshalSARIFSingleDraugrTool(t *testing.T) {
	r := Report{Results: []Result{
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelError, Message: "m1", Location: Location{URI: "go.mod"}},
		{Tool: "semgrep", RuleID: "go.xss", Level: LevelWarning, Message: "m2", Location: Location{URI: "h.go", StartLine: 3}},
	}}
	data, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string } `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string                `json:"ruleId"`
				Properties struct{ Tool string } `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	// One consolidated "Draugr" tool holding every finding.
	if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "Draugr" {
		t.Fatalf("want a single Draugr run, got %d runs", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("want 2 results in the run, got %d", len(log.Runs[0].Results))
	}
	// Originating scanner preserved per-finding.
	got := map[string]string{}
	for _, res := range log.Runs[0].Results {
		got[res.RuleID] = res.Properties.Tool
	}
	if got["CVE-1"] != "trivy" || got["go.xss"] != "semgrep" {
		t.Errorf("per-finding tool not preserved: %v", got)
	}

	// Round-trip: reading Draugr's own SARIF restores each result's originating tool.
	back, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	rt := map[string]string{}
	for _, res := range back.Results {
		rt[res.RuleID] = res.Tool
	}
	if rt["CVE-1"] != "trivy" || rt["go.xss"] != "semgrep" {
		t.Errorf("round-trip lost the originating tool: %v", rt)
	}
}

// Scanners publish rule metadata; Draugr's job is to relay it, not to re-author it. Losing it
// is what leaves a reader staring at an opaque id.
func TestFromSARIFKeepsRuleMetadata(t *testing.T) {
	in := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep","rules":[
	  {"id":"py.audit.eval","name":"EvalUse",
	   "shortDescription":{"text":"eval() on user input"},
	   "fullDescription":{"text":"Passing untrusted input to eval() allows code execution."},
	   "help":{"text":"Use ast.literal_eval."},
	   "helpUri":"https://semgrep.dev/r/py.audit.eval"}]}},
	  "results":[{"ruleId":"py.audit.eval","level":"error","message":{"text":"eval here"}}]}]}`)
	rep, err := FromSARIF(in)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	got := rep.Rules["py.audit.eval"]
	want := Rule{
		Name:             "EvalUse",
		ShortDescription: "eval() on user input",
		FullDescription:  "Passing untrusted input to eval() allows code execution.",
		Help:             "Use ast.literal_eval.",
		HelpURI:          "https://semgrep.dev/r/py.audit.eval",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rule = %+v, want %+v", got, want)
	}
}

// A scanner that says nothing about its rules shouldn't leave empty husks behind.
func TestFromSARIFRecordsNoRuleWithoutMetadata(t *testing.T) {
	in := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Gitleaks","rules":[
	  {"id":"aws-key","defaultConfiguration":{"level":"error"}}]}},
	  "results":[{"ruleId":"aws-key","message":{"text":"key"}}]}]}`)
	rep, err := FromSARIF(in)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	if len(rep.Rules) != 0 {
		t.Errorf("Rules = %v, want none", rep.Rules)
	}
	// The level still had to be inherited from the rule.
	if rep.Results[0].Level != LevelError {
		t.Errorf("level = %q, want error", rep.Results[0].Level)
	}
}

func TestHelpURI(t *testing.T) {
	rep := Report{Rules: map[string]Rule{"DS-0002": {HelpURI: "https://avd.aquasec.com/misconfig/ds002"}}}
	cases := map[string]string{
		"DS-0002":              "https://avd.aquasec.com/misconfig/ds002", // what the scanner said
		"CVE-2021-36159":       "https://nvd.nist.gov/vuln/detail/CVE-2021-36159",
		"GHSA-abcd-1234-wxyz":  "https://github.com/advisories/GHSA-abcd-1234-wxyz",
		"python.lang.security": "", // nowhere honest to point
		"":                     "",
	}
	for id, want := range cases {
		if got := rep.HelpURI(id); got != want {
			t.Errorf("HelpURI(%q) = %q, want %q", id, got, want)
		}
	}
}

// Merging is how a run's controls become one report; rule metadata has to survive it, and the
// first scanner to describe a rule shouldn't be blanked by a later one that says less.
func TestMergeUnionsRuleMetadata(t *testing.T) {
	a := Report{
		Results: []Result{{RuleID: "r1", Message: "a"}},
		Rules:   map[string]Rule{"r1": {ShortDescription: "first"}},
	}
	b := Report{
		Results: []Result{{RuleID: "r2", Message: "b"}},
		Rules:   map[string]Rule{"r1": {ShortDescription: "second", HelpURI: "https://x"}, "r2": {Name: "Two"}},
	}
	got := Merge(a, b)
	if d := got.Rules["r1"].ShortDescription; d != "first" {
		t.Errorf("r1 shortDescription = %q, want the first one kept", d)
	}
	if u := got.Rules["r1"].HelpURI; u != "https://x" {
		t.Errorf("r1 helpUri = %q, want the later one filled in", u)
	}
	if n := got.Rules["r2"].Name; n != "Two" {
		t.Errorf("r2 name = %q, want Two", n)
	}
}

func TestMarshalSARIFEmitsRuleMetadata(t *testing.T) {
	rep := Report{
		Tool:    "semgrep",
		Results: []Result{{RuleID: "py.audit.eval", Level: LevelError, Message: "eval here", Location: Location{URI: "app/main.py", StartLine: 12}}},
		Rules: map[string]Rule{"py.audit.eval": {
			Name: "EvalUse", ShortDescription: "eval() on user input",
			FullDescription: "long", Help: "Use ast.literal_eval.",
			HelpURI: "https://semgrep.dev/r/py.audit.eval",
		}},
	}
	data, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatalf("MarshalSARIF: %v", err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string                 `json:"id"`
						Name             string                 `json:"name"`
						ShortDescription *struct{ Text string } `json:"shortDescription"`
						FullDescription  *struct{ Text string } `json:"fullDescription"`
						Help             *struct{ Text string } `json:"help"`
						HelpURI          string                 `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			OriginalURIBaseIDs map[string]struct {
				Description *struct{ Text string } `json:"description"`
			} `json:"originalUriBaseIds"`
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	r := rules[0]
	if r.Name != "EvalUse" || r.HelpURI != "https://semgrep.dev/r/py.audit.eval" {
		t.Errorf("name/helpUri = %q/%q", r.Name, r.HelpURI)
	}
	if r.ShortDescription == nil || r.ShortDescription.Text != "eval() on user input" {
		t.Errorf("shortDescription = %+v", r.ShortDescription)
	}
	if r.FullDescription == nil || r.Help == nil {
		t.Errorf("fullDescription/help missing: %+v %+v", r.FullDescription, r.Help)
	}
	// A relative path needs a declared base, or a viewer can't resolve it onto a real file.
	art := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if art.URIBaseID != "%SRCROOT%" {
		t.Errorf("uriBaseId = %q, want %%SRCROOT%%", art.URIBaseID)
	}
	base, ok := log.Runs[0].OriginalURIBaseIDs["%SRCROOT%"]
	if !ok || base.Description == nil || base.Description.Text == "" {
		t.Errorf("originalURIBaseIDs = %+v, want a described %%SRCROOT%%", log.Runs[0].OriginalURIBaseIDs)
	}
}

// An image reference or a URL already identifies its subject; joining it onto a source root
// would be nonsense.
func TestMarshalSARIFLeavesNonRelativeLocationsUnbased(t *testing.T) {
	for _, uri := range []string{"library/alpine:3.18", "https://example.com/health", "/etc/passwd"} {
		rep := Report{Results: []Result{{RuleID: "r", Level: LevelError, Location: Location{URI: uri}}}}
		data, err := rep.MarshalSARIF()
		if err != nil {
			t.Fatalf("MarshalSARIF: %v", err)
		}
		if strings.Contains(string(data), "uriBaseId") {
			t.Errorf("%q: got a uriBaseId, want none:\n%s", uri, data)
		}
	}
}

func TestClampDescription(t *testing.T) {
	if got := clampDescription("short"); got != "short" {
		t.Errorf("clampDescription(short) = %q", got)
	}
	long := strings.Repeat("é", 2000) // multi-byte: a naive cut would split a rune
	got := clampDescription(long)
	if len(got) > descriptionLimit {
		t.Errorf("len = %d, want <= %d", len(got), descriptionLimit)
	}
	if !utf8.ValidString(got) {
		t.Errorf("clamped text is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("want an ellipsis, got %q", got[len(got)-8:])
	}
}

// Compact is for a consumer that acts on the report rather than reads it: the prose goes, the
// pointer stays, and what's left is still valid SARIF with every finding intact.
func TestMarshalCompactDropsProseKeepsPointer(t *testing.T) {
	rep := Report{
		Tool: "semgrep",
		Results: []Result{
			{RuleID: "py.audit.eval", Level: LevelError, Message: "eval here",
				Location: Location{URI: "app/main.py", StartLine: 12}},
			{RuleID: "CVE-2021-1", Level: LevelWarning, Message: "old dep",
				Location: Location{URI: "go.mod", StartLine: 1}},
		},
		Rules: map[string]Rule{"py.audit.eval": {
			Name: "EvalUse", ShortDescription: "eval() on user input",
			FullDescription: strings.Repeat("prose ", 200), Help: strings.Repeat("remedy ", 200),
			HelpURI: "https://semgrep.dev/r/py.audit.eval",
		}},
	}
	full, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatalf("MarshalSARIF: %v", err)
	}
	lean, err := rep.MarshalSARIFWith(MarshalOptions{Compact: true})
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if len(lean) >= len(full) {
		t.Errorf("compact (%d) should be smaller than full (%d)", len(lean), len(full))
	}
	s := string(lean)
	for _, gone := range []string{"prose", "remedy", "shortDescription", "EvalUse"} {
		if strings.Contains(s, gone) {
			t.Errorf("compact output still carries %q", gone)
		}
	}
	// The pointer survives — a reader that can follow a link doesn't need the paragraphs.
	if !strings.Contains(s, "https://semgrep.dev/r/py.audit.eval") {
		t.Error("compact dropped helpUri; it's the whole reason the prose can go")
	}
	if strings.Contains(s, "\n") {
		t.Error("compact output should not be indented")
	}
	// Still SARIF, still every finding, and the derived helpUri still derived.
	back, err := FromSARIF(lean)
	if err != nil {
		t.Fatalf("compact output no longer parses as SARIF: %v", err)
	}
	if len(back.Results) != len(rep.Results) {
		t.Errorf("results = %d, want %d", len(back.Results), len(rep.Results))
	}
	if !strings.Contains(s, "https://nvd.nist.gov/vuln/detail/CVE-2021-1") {
		t.Error("compact should keep the derived advisory link too")
	}
	// The scanner tag is how a consumer knows which tool found it — not prose, keep it.
	if !strings.Contains(s, "scanner:semgrep") {
		t.Error("compact dropped the scanner tag")
	}
}

// Trivy's message repeats what every consumer already shows in its own column, and its first
// line is a filename — so an editor's Problems panel lists a manifest's findings as N identical
// rows. The advisory title is on the rule; prefer it.
func TestReadableMessagePrefersTheAdvisoryOverAFieldDump(t *testing.T) {
	dump := "Package: Flask\nInstalled Version: 0.12.2\nVulnerability CVE-2018-1000656\n" +
		"Severity: HIGH\nFixed Version: 0.12.3\nLink: [CVE-2018-1000656](https://avd.aquasec.com/nvd/cve-2018-1000656)"
	const summary = "python-flask: Denial of Service via crafted JSON file"
	if got := readableMessage(dump, summary); got != summary {
		t.Errorf("readableMessage = %q, want the advisory title", got)
	}
}

// Semgrep and Gitleaks write sentences. Some scanners publish a shortDescription that only
// restates the rule id, so preferring it unconditionally would make things worse.
func TestReadableMessageLeavesProseAlone(t *testing.T) {
	for _, msg := range []string{
		"GitHub Actions step uses a mutable tag or branch reference.",
		"private-key has detected secret for file test/fixture.go.",
	} {
		if got := readableMessage(msg, "Semgrep Finding: yaml.github-actions.security.x"); got != msg {
			t.Errorf("readableMessage(%q) = %q, want it untouched", msg, got)
		}
	}
}

// A field dump is poor, but it is what the scanner said. Blanking it would be worse.
func TestReadableMessageKeepsTheDumpWhenThereIsNoAlternative(t *testing.T) {
	dump := "Package: Flask\nInstalled Version: 0.12.2"
	if got := readableMessage(dump, ""); got != dump {
		t.Errorf("readableMessage = %q, want the original when the rule has no summary", got)
	}
}

// "Warning: the certificate expires" is prose, not a field dump. Requiring several lines is
// what separates them.
func TestReadableMessageIgnoresASingleLineColon(t *testing.T) {
	msg := "Warning: the certificate expires in 3 days."
	if got := readableMessage(msg, "something else entirely"); got != msg {
		t.Errorf("readableMessage = %q, want the original", got)
	}
}

// The whole point of normalizing at the decode boundary rather than in the console renderer:
// a machine consumer reads the same readable text a person does. This is the case that
// regressed unnoticed for as long as only the terminal was checked.
func TestFromSARIFRewritesFieldDumpMessages(t *testing.T) {
	const raw = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[
      {"id":"DS-0002","shortDescription":{"text":"Image user should not be 'root'"}}]}},
      "results":[{"ruleId":"DS-0002","level":"error",
        "message":{"text":"Artifact: app/Dockerfile\nType: dockerfile\nVulnerability DS-0002\nSeverity: HIGH"},
        "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/Dockerfile"},
          "region":{"startLine":1}}}]}]}]}`
	rep, err := FromSARIF([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(rep.Results))
	}
	if got := rep.Results[0].Message; got != "Image user should not be 'root'" {
		t.Errorf("decoded message = %q, want the rule's summary", got)
	}
	// The scanner's own detail has to survive somewhere a viewer can show it.
	if rep.Rules["DS-0002"].ShortDescription == "" {
		t.Error("the rule description should still be carried")
	}
}

// SARIF has a run-level property bag for exactly this, so the benchmark a report was measured
// against travels to any consumer that reads SARIF — not only to Draugr's own reporters.
func TestSARIFCarriesProvenance(t *testing.T) {
	r := Report{Tool: "draugr-k8s-policies", Provenance: []Provenance{{
		Tool: "draugr-k8s-policies", Version: "0.50.0",
		Fields: []Field{{Key: "benchmark", Value: "cis-1.12"}},
	}}}
	b, err := r.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	props, ok := run["properties"].(map[string]any)
	if !ok {
		t.Fatalf("no run properties: %s", b)
	}
	t.Logf("run.properties = %v", props)
	if props["draugr/provenance"] == nil {
		t.Error("provenance missing from the property bag")
	}
}

// Every scan that says nothing must not emit an empty bag.
func TestSARIFOmitsEmptyProvenance(t *testing.T) {
	b, _ := Report{Tool: "x"}.MarshalSARIF()
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	if _, has := doc["runs"].([]any)[0].(map[string]any)["properties"]; has {
		t.Error("a run with nothing to say must not carry an empty property bag")
	}
}

func TestProvenanceSurvivesASARIFRoundTrip(t *testing.T) {
	// A consumer that reloads a report has to be able to tell a scan of everything from a scan
	// of part of it, and the results alone never say which it was. Writing provenance and not
	// reading it back would be the same as not writing it.
	in := Report{Tool: "draugr", Results: []Result{{RuleID: "R", Level: LevelError}},
		Provenance: []Provenance{{
			Tool:    "draugr/scope",
			Version: "1.2.3",
			Fields:  []Field{{Key: "components", Value: "app"}, {Key: "controls", Value: "sca"}},
		}}}
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Provenance) != 1 {
		t.Fatalf("want one provenance entry, got %d: %+v", len(out.Provenance), out.Provenance)
	}
	got := out.Provenance[0]
	if got.Tool != "draugr/scope" || got.Version != "1.2.3" {
		t.Errorf("tool/version lost: %+v", got)
	}
	// Sorted: the bag is a JSON object, whose key order is not something a consumer may rely on,
	// so two loads of one file have to agree.
	want := []Field{{Key: "components", Value: "app"}, {Key: "controls", Value: "sca"}}
	if !reflect.DeepEqual(got.Fields, want) {
		t.Errorf("got %+v, want %+v", got.Fields, want)
	}
}

func TestFromSARIFWithoutProvenanceCarriesNone(t *testing.T) {
	out, err := FromSARIF([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"results":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Provenance) != 0 {
		t.Errorf("nothing to read back: %+v", out.Provenance)
	}
}

// TestImageAndOSSurviveTheFile is the round trip.
//
// A report is written and read back — by `draugr diff`, and by every platform format that reads
// the SARIF rather than the run that produced it. A field that exists only in memory is one all
// of those have to do without, and the loss is invisible: the first read is the one that works.
func TestImageAndOSSurviveTheFile(t *testing.T) {
	in := Report{
		Tool: "trivy",
		Results: []Result{{
			Tool:            "trivy",
			RuleID:          "CVE-2011-3374",
			Level:           LevelNote,
			Message:         "apt 2.2.4",
			Location:        Location{URI: "debian:11-slim"},
			Image:           "debian:11-slim",
			OperatingSystem: "debian 11.11",
		}, {
			Tool:    "trivy",
			RuleID:  "CVE-2020-8203",
			Level:   LevelError,
			Message: "lodash 4.17.15",
			Image:   "debian:11-slim",
			// No operating system: a language package is not a distribution finding.
		}},
	}

	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != len(in.Results) {
		t.Fatalf("read back %d results, wrote %d", len(out.Results), len(in.Results))
	}
	for i, want := range in.Results {
		got := out.Results[i]
		if got.Image != want.Image {
			t.Errorf("result %d: image = %q, want %q", i, got.Image, want.Image)
		}
		if got.OperatingSystem != want.OperatingSystem {
			t.Errorf("result %d: operating system = %q, want %q",
				i, got.OperatingSystem, want.OperatingSystem)
		}
	}
}
