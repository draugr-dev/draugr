package saga

import (
	"strings"
	"testing"
)

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing version",
			yaml: "release:\n  name: x\n",
			want: "release.version is required",
		},
		{
			name: "component without name",
			yaml: "release:\n  version: '1'\ncomponents:\n  - repositories:\n     - url: u\n",
			want: "name is required",
		},
		{
			name: "duplicate component",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n  - name: a\n",
			want: "duplicate component name",
		},
		{
			name: "repository missing url",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n    repositories:\n     - revision: r\n",
			want: "repositories[0].url is required",
		},
		{
			name: "image missing ref",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n    images:\n     - {}\n",
			want: "images[0].image is required",
		},
		{
			name: "host missing url",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n    hosts:\n     - name: h\n",
			want: "hosts[0].url is required",
		},
		{
			name: "malformed image digest",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n    images:\n     - image: repo/x:1\n       digest: notadigest\n",
			want: "images[0].digest \"notadigest\" must be of the form algorithm:hex",
		},
		{
			name: "invalid exposure",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n    exposure: web\n",
			want: "invalid exposure \"web\"",
		},
		{
			name: "invalid criticality",
			yaml: "release:\n  version: '1'\ncomponents:\n  - name: a\n    criticality: bc9\n",
			want: "invalid criticality \"bc9\"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsValidClassification(t *testing.T) {
	yaml := "release:\n  version: '1'\ncomponents:\n  - name: a\n    exposure: public\n    criticality: critical\n"
	m, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("valid classification should load, got %v", err)
	}
	if m.Components[0].Exposure.Value != ExposurePublic || m.Components[0].Criticality.Value != CriticalityCritical {
		t.Fatalf("classification not parsed: %+v", m.Components[0])
	}
}

func TestValidateAcceptsImageDigest(t *testing.T) {
	yaml := "release:\n  version: '1'\ncomponents:\n  - name: a\n    images:\n     - image: repo/x:1\n       digest: sha256:9b2a4c\n"
	m, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("valid digest should load, got %v", err)
	}
	if got := m.Components[0].Images[0].Digest; got != "sha256:9b2a4c" {
		t.Fatalf("digest not parsed, got %q", got)
	}
}

func TestClassificationOptional(t *testing.T) {
	// A component with no exposure/criticality is valid (unclassified).
	m, err := Load([]byte("release:\n  version: '1'\ncomponents:\n  - name: a\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Components[0].Exposure.Value != "" || m.Components[0].Criticality.Value != "" {
		t.Fatalf("unset classification should be empty, got %+v", m.Components[0])
	}
}

func TestExposureCriticalityValid(t *testing.T) {
	for _, e := range Exposures {
		if !e.Valid() {
			t.Errorf("%q should be valid", e)
		}
	}
	for _, c := range Criticalities {
		if !c.Valid() {
			t.Errorf("%q should be valid", c)
		}
	}
	if Exposure("").Valid() || Exposure("re5").Valid() {
		t.Error("empty/unknown exposure should be invalid")
	}
	if Criticality("").Valid() || Criticality("bc0").Valid() {
		t.Error("empty/unknown criticality should be invalid")
	}
}

func TestValidateReportsAndPublishers(t *testing.T) {
	yaml := "release:\n  version: '1'\nconfig:\n  reports:\n    - format: sarif\n    - format: markdown\n  publishers:\n    - kind: file\n      dir: ./out\n"
	m, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("valid reports/publishers should load, got %v", err)
	}
	if len(m.Config.Reports) != 2 || m.Config.Reports[0].Format != "sarif" {
		t.Fatalf("reports not parsed: %+v", m.Config.Reports)
	}
	if len(m.Config.Publishers) != 1 || m.Config.Publishers[0].Kind != "file" || m.Config.Publishers[0].Dir != "./out" {
		t.Fatalf("publishers not parsed: %+v", m.Config.Publishers)
	}
}

func TestValidateReportsPublishersRequireFields(t *testing.T) {
	yaml := "release:\n  version: '1'\nconfig:\n  reports:\n    - format: ''\n  publishers:\n    - dir: ./out\n"
	_, err := Load([]byte(yaml))
	if err == nil {
		t.Fatal("expected errors for empty report format and missing publisher kind")
	}
	for _, want := range []string{"config.reports[0].format is required", "config.publishers[0].kind is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

func TestValidateAggregatesMultiple(t *testing.T) {
	// Missing version AND a duplicate component name => both reported.
	_, err := Load([]byte("components:\n  - name: a\n  - name: a\n"))
	if err == nil {
		t.Fatal("expected errors")
	}
	msg := err.Error()
	if !strings.Contains(msg, "release.version") || !strings.Contains(msg, "duplicate") {
		t.Fatalf("expected aggregated errors, got: %v", msg)
	}
}

func TestValidateSBOMFormat(t *testing.T) {
	base := func(f SBOMFormat) *Model {
		return &Model{
			Release: Release{Name: "x", Version: "1"},
			Config:  Config{SBOM: &SBOMConfig{Enabled: true, Format: f}},
		}
	}
	for _, f := range SBOMFormats {
		if err := base(f).Validate(); err != nil {
			t.Errorf("format %q should validate: %v", f, err)
		}
	}
	// Empty means "the default", which callers resolve — it must not be rejected here.
	if err := base("").Validate(); err != nil {
		t.Errorf("an unset format should validate: %v", err)
	}
	// syft-json is a real Syft format we deliberately don't offer — vendor-specific rather than
	// an interchange standard — so it has to be rejected, not quietly passed through to Syft.
	err := base("syft-json").Validate()
	if err == nil {
		t.Fatal("want an error for an unsupported format")
	}
	// Naming the alternatives is the difference between a fixable error and a search.
	for _, want := range []string{"spdx-json", "cyclonedx-json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q: %v", want, err)
		}
	}
}

func TestSBOMConfigRoundTripsThroughLoad(t *testing.T) {
	m, err := Load([]byte("release:\n  name: x\n  version: \"1\"\nconfig:\n  sbom:\n    enabled: true\n    format: cyclonedx-json\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Config.SBOM == nil || !m.Config.SBOM.Enabled || m.Config.SBOM.Format != SBOMCycloneDXJSON {
		t.Errorf("sbom config = %+v", m.Config.SBOM)
	}
}

func TestExcludeRuleMatching(t *testing.T) {
	cases := []struct {
		name        string
		rule        ExcludeRule
		uri, ruleID string
		want        bool
	}{
		{"directory prefix", ExcludeRule{Paths: []string{"examples/"}}, "examples/a/b.yml", "any", true},
		{"directory prefix misses sibling", ExcludeRule{Paths: []string{"examples/"}}, "examplesx/b.yml", "any", false},
		{"exact path", ExcludeRule{Paths: []string{"test/fixture.go"}}, "test/fixture.go", "any", true},
		{"glob", ExcludeRule{Paths: []string{"*.md"}}, "README.md", "any", true},
		{"glob does not cross directories", ExcludeRule{Paths: []string{"*.md"}}, "docs/README.md", "any", false},
		{"rule only", ExcludeRule{Rules: []string{"private-key"}}, "anywhere.go", "private-key", true},
		{"rule only misses others", ExcludeRule{Rules: []string{"private-key"}}, "anywhere.go", "aws-key", false},
		// Both set is an AND. The alternative would silently widen "ignore this rule in the
		// fixture" into "ignore this rule everywhere", which is the dangerous reading.
		{"both must match", ExcludeRule{Paths: []string{"test/f.go"}, Rules: []string{"k"}}, "test/f.go", "k", true},
		{"both: wrong path", ExcludeRule{Paths: []string{"test/f.go"}, Rules: []string{"k"}}, "src/f.go", "k", false},
		{"both: wrong rule", ExcludeRule{Paths: []string{"test/f.go"}, Rules: []string{"k"}}, "test/f.go", "j", false},
		{"empty rule matches nothing", ExcludeRule{}, "a", "b", false},
		// An image finding has no file path. A path rule must not sweep it up by accident.
		{"no location", ExcludeRule{Paths: []string{"*"}}, "", "k", false},
	}
	for _, c := range cases {
		if got := c.rule.Matches(c.uri, c.ruleID); got != c.want {
			t.Errorf("%s: Matches(%q, %q) = %v, want %v", c.name, c.uri, c.ruleID, got, c.want)
		}
	}
}

func TestValidateExclude(t *testing.T) {
	base := func(e ExcludeRule) *Model {
		return &Model{Release: Release{Name: "x", Version: "1"}, Config: Config{Exclude: []ExcludeRule{e}}}
	}
	if err := base(ExcludeRule{Paths: []string{"examples/"}, Reason: "templates"}).Validate(); err != nil {
		t.Errorf("a well-formed exclusion should validate: %v", err)
	}
	// A reason is what makes an exclusion reviewable rather than an oversight.
	err := base(ExcludeRule{Paths: []string{"examples/"}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Errorf("want a missing-reason error, got %v", err)
	}
	if err := base(ExcludeRule{Paths: []string{"x"}, Reason: "   "}).Validate(); err == nil {
		t.Error("whitespace is not a reason")
	}
	// Neither selector would match everything.
	err = base(ExcludeRule{Reason: "because"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "suppress everything") {
		t.Errorf("want a no-selector error, got %v", err)
	}
	if err := base(ExcludeRule{Paths: []string{""}, Reason: "r"}).Validate(); err == nil {
		t.Error("an empty path should be rejected")
	}
}

func TestExcludeRuleWildcards(t *testing.T) {
	// A compound license id: the package itself contains slashes, which is exactly why `*` has
	// to cross separators here.
	const lic = "license/GPL-3.0-only/github.com/somelib/thing"

	cases := []struct {
		pattern string
		ruleID  string
		want    bool
	}{
		{"license/GPL-3.0-only/*", lic, true}, // this license, any package
		{"license/*", lic, true},              // every license finding
		{lic, lic, true},                      // exact, no wildcard
		{"license/MIT/*", lic, false},         // different license
		{"license/GPL-3.0-only/github.com/somelib/thing", lic, true},
		{"*/somelib/*", lic, true},     // wildcard on both sides
		{"license/*/thing", lic, true}, // suffix anchored
		{"license/*/other", lic, false},
		// Existing exact ids keep working — no scanner emits a literal `*`.
		{"private-key", "private-key", true},
		{"private-key", "aws-key", false},
		{"CVE-2019-*", "CVE-2019-20477", true},
		{"CVE-2020-*", "CVE-2019-20477", false},
		// A bare wildcard matches anything, which is why the suppression count exists.
		{"*", "anything-at-all", true},
		// Empty pattern must not match a non-empty id.
		{"", "x", false},
	}
	for _, c := range cases {
		got := ExcludeRule{Rules: []string{c.pattern}}.Matches("any/path", c.ruleID)
		if got != c.want {
			t.Errorf("pattern %q vs %q = %v, want %v", c.pattern, c.ruleID, got, c.want)
		}
	}
}

func TestExcludeRuleWildcardDoesNotOverreach(t *testing.T) {
	// The suffix must actually be present, not merely implied by the prefix matching.
	if (ExcludeRule{Rules: []string{"license/*/GPL-3.0-only"}}).Matches("p", "license/foo/GPL-3.0-only-extra") {
		t.Error("a trailing wildcard segment must anchor at the end")
	}
	// Overlapping literal segments must consume in order.
	if !(ExcludeRule{Rules: []string{"a*b*c"}}).Matches("p", "a-b-c") {
		t.Error("multiple wildcards should match in order")
	}
	if (ExcludeRule{Rules: []string{"a*b*c"}}).Matches("p", "a-c-b") {
		t.Error("segments out of order should not match")
	}
}

func TestExcludeRulePathsStillUsePathSemantics(t *testing.T) {
	// Paths are paths: `*` stops at a separator, so `*.md` does not sweep up every markdown
	// file in the tree. Only rule ids get the cross-separator wildcard.
	if (ExcludeRule{Paths: []string{"*.md"}}).Matches("docs/README.md", "r") {
		t.Error("a path glob should not cross directory separators")
	}
	if !(ExcludeRule{Paths: []string{"*.md"}}).Matches("README.md", "r") {
		t.Error("a path glob should still match in the top level")
	}
}

func TestValidateGateControls(t *testing.T) {
	base := func(controls map[string]string) *Model {
		reasoned := make(map[string]Reasoned[string], len(controls))
		for control, want := range controls {
			reasoned[control] = Unstated(want)
		}
		return &Model{Release: Release{Name: "x", Version: "1"}, Config: Config{Gate: &GateConfig{Controls: reasoned}}}
	}
	// The bands the report prints, which is the vocabulary a threshold is written in.
	if err := base(map[string]string{"licenses": "critical", "sast": "low"}).Validate(); err != nil {
		t.Errorf("severity bands should pass: %v", err)
	}
	// The SARIF levels a gate used to take. Still accepted, because a descriptor written against
	// the older vocabulary should keep working rather than fail on the day it is next validated.
	if err := base(map[string]string{"licenses": "error", "sast": "note"}).Validate(); err != nil {
		t.Errorf("the levels a gate used to take should still pass: %v", err)
	}
	err := base(map[string]string{"licenses": "urgent"}).Validate()
	if err == nil {
		t.Fatal("want an error for a word that is neither a band nor a level")
	}
	// The message names the bands rather than every accepted spelling: the older words work, but
	// telling somebody making a fresh mistake about them teaches the wrong vocabulary.
	for _, want := range []string{"critical", "high", "medium", "low"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "licenses") {
		t.Errorf("error should name the offending control: %v", err)
	}
}

// A descriptor key that matches nothing is the quiet kind of wrong: the scan runs, reports a
// verdict, and does less than its author asked for. Both shapes below are that key.
func TestValidateRejectsUnusableControllerKeys(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		settings ControllerSettings
		want     []string
	}{
		{
			name:     "hyphenated scanner key",
			settings: ControllerSettings{"kube-bench-job": map[string]any{"enabled": true}},
			want:     []string{"camelCase", "kubeBenchJob"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &Model{
				Release: Release{Version: "1.0"},
				Config:  Config{Controllers: map[string]ControllerSettings{"infrastructure": tc.settings}},
			}
			err := m.Validate()
			if err == nil {
				t.Fatal("want an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error should mention %q, got: %v", w, err)
				}
			}
		})
	}
}

// removedControllerKeys is empty today, so the mechanism is exercised with an entry of its own
// rather than with whatever legacy happens to be listed.
//
// It exists for the setting whose replacement is a different shape rather than a new name — the
// "no such scanner key" error can list what a control accepts, but it cannot explain that one
// setting became three blocks. Untested, an empty map is indistinguishable from a dead one, and
// the day it is needed is not the day to find out it stopped working.
func TestRemovedControllerKeysExplainTheReplacement(t *testing.T) {
	removedControllerKeys["infrastructure"] = map[string]string{
		"mode": "per-scanner blocks: `kubeBenchJob: { enabled: true }`",
	}
	t.Cleanup(func() { delete(removedControllerKeys, "infrastructure") })

	m := &Model{
		Release: Release{Version: "1.0"},
		Config: Config{Controllers: map[string]ControllerSettings{
			"infrastructure": {"mode": "job"},
		}},
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("a removed setting was accepted")
	}
	for _, want := range []string{"was removed", "kubeBenchJob"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

// The convention applies to a component's own controller block too, or half the descriptor is
// unchecked.
func TestValidateChecksComponentControllerKeys(t *testing.T) {
	t.Parallel()
	m := &Model{
		Release: Release{Version: "1.0"},
		Components: []Component{{
			Name:        "web",
			Controllers: map[string]ControllerSettings{"tls": {"draugr-tls": map[string]any{"enabled": false}}},
		}},
	}
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "draugrTls") {
		t.Errorf("want an error naming draugrTls, got: %v", err)
	}
}

// camelCase keys are the point; they must not be flagged.
func TestValidateAcceptsCamelCaseControllerKeys(t *testing.T) {
	t.Parallel()
	m := &Model{
		Release: Release{Version: "1.0"},
		Config: Config{Controllers: map[string]ControllerSettings{
			"infrastructure": {"enabled": true, "kubeBenchJob": map[string]any{"enabled": true}},
		}},
	}
	if err := m.Validate(); err != nil {
		t.Errorf("camelCase keys should validate, got: %v", err)
	}
}

func TestExploitabilityConfigRoundTripsThroughLoad(t *testing.T) {
	m, err := Load([]byte("release:\n  name: x\n  version: \"1\"\n" +
		"config:\n  exploitability:\n    kev: cache\n    epss: auto\n" +
		"    epssThreshold: 0.1\n    maxAge: 168h\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	x := m.Config.Exploitability
	if x == nil || x.KEV != "cache" || x.EPSS != FeedSourceAuto || x.MaxAge != "168h" {
		t.Fatalf("exploitability config = %+v", x)
	}
	if x.EPSSThreshold == nil || *x.EPSSThreshold != 0.1 {
		t.Errorf("threshold = %v, want 0.1", x.EPSSThreshold)
	}
}

func TestExploitabilityThresholdZeroIsNotAbsent(t *testing.T) {
	// Zero disables the EPSS bump while leaving KEV in force, which is a thing someone might
	// mean. It has to survive the round trip as a set value rather than as "unspecified".
	m, err := Load([]byte("release:\n  name: x\n  version: \"1\"\n" +
		"config:\n  exploitability:\n    kev: cache\n    epssThreshold: 0\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if x := m.Config.Exploitability; x == nil || x.EPSSThreshold == nil || *x.EPSSThreshold != 0 {
		t.Errorf("a deliberate zero was lost: %+v", x)
	}
}

func TestExploitabilityConfigValidation(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{
			"threshold above one",
			"config:\n  exploitability:\n    epssThreshold: 1.5\n",
			"probability",
		},
		{
			"negative threshold",
			"config:\n  exploitability:\n    epssThreshold: -0.1\n",
			"probability",
		},
		{
			"maxAge is not a duration",
			"config:\n  exploitability:\n    maxAge: \"3 days\"\n",
			"not a duration",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load([]byte("release:\n  name: x\n  version: \"1\"\n" + c.yaml))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error should say %q: %v", c.want, err)
			}
		})
	}

	// A path is not checkable here: a shared descriptor may name a file this machine does not
	// have, which is a scan-time error rather than a validation one.
	if _, err := Load([]byte("release:\n  name: x\n  version: \"1\"\n" +
		"config:\n  exploitability:\n    kev: ./kev.json\n    maxAge: 24h\n")); err != nil {
		t.Errorf("a file path should validate: %v", err)
	}
}

// A report may declare the band it was narrowed to; anything that is not a band is refused.
//
// Refused rather than ignored: the value decides what a code-scanning upload contains, and a typo
// that silently means "complete" is a reviewer quietly getting every finding in the repository
// back again, with nothing to say why.
func TestValidateReportMinPriority(t *testing.T) {
	for _, band := range []string{"P1", "P4"} {
		m := &Model{
			Release: Release{Version: "1"},
			Config:  Config{Reports: []ReportConfig{{Format: "sarif", MinPriority: band}}},
		}
		if err := m.Validate(); err != nil {
			t.Errorf("%s rejected: %v", band, err)
		}
	}
	m := &Model{
		Release: Release{Version: "1"},
		Config:  Config{Reports: []ReportConfig{{Format: "sarif", MinPriority: "urgent"}}},
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("a value that is not a priority band was accepted")
	}
	for _, want := range []string{"minPriority", "urgent", "P1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
	// Unset stays the common case and must not be reported.
	clean := &Model{
		Release: Release{Version: "1"},
		Config:  Config{Reports: []ReportConfig{{Format: "sarif"}}},
	}
	if err := clean.Validate(); err != nil {
		t.Errorf("a report with no band was rejected: %v", err)
	}
}

// TestValidateHostAuth covers the block whose whole purpose is that a credential cannot be written
// into a committed file — so every way of getting it wrong has to be caught at load.
func TestValidateHostAuth(t *testing.T) {
	for _, c := range []struct {
		name string
		auth *HostAuth
		want string
	}{
		{"absent is fine", nil, ""},
		{"bearer", &HostAuth{Type: "bearer", TokenEnv: "TOK"}, ""},
		{"named header", &HostAuth{Type: "header", Header: "X-API-Key", TokenEnv: "TOK"}, ""},
		{"header without a name", &HostAuth{Type: "header", TokenEnv: "TOK"}, "header is required"},
		{"bearer with a name", &HostAuth{Type: "bearer", Header: "X", TokenEnv: "TOK"}, "not used with type"},
		{"no type", &HostAuth{TokenEnv: "TOK"}, "type is required"},
		{"unknown type", &HostAuth{Type: "oauth", TokenEnv: "TOK"}, "not a kind Draugr supports"},
		{"no variable", &HostAuth{Type: "bearer"}, "tokenEnv is required"},
	} {
		t.Run(c.name, func(t *testing.T) {
			errs := validateHostAuth(c.auth, "hosts[0].auth")
			assertValidation(t, errs, c.want)
		})
	}
}

// TestValidateHostSpec covers the block that decides which requests a scan may send.
func TestValidateHostSpec(t *testing.T) {
	for _, c := range []struct {
		name string
		spec *HostSpec
		want string
	}{
		{"absent is fine", nil, ""},
		{"read-only", &HostSpec{Path: "openapi.yaml"}, ""},
		{"writes named", &HostSpec{Path: "openapi.yaml", Methods: []string{"GET", "post"}}, ""},
		{"no path", &HostSpec{Methods: []string{"get"}}, "path is required"},
		// Not "no restriction": it describes a scan that sends nothing, which is a descriptor
		// quietly not working.
		{"empty list", &HostSpec{Path: "openapi.yaml", Methods: []string{}}, "would scan nothing"},
		{"unknown method", &HostSpec{Path: "openapi.yaml", Methods: []string{"fetch"}},
			"not an HTTP method Draugr will exercise"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assertValidation(t, validateHostSpec(c.spec, "hosts[0].spec"), c.want)
		})
	}
}

func assertValidation(t *testing.T, errs []error, want string) {
	t.Helper()
	if want == "" {
		if len(errs) != 0 {
			t.Fatalf("expected no error, got %v", errs)
		}
		return
	}
	if len(errs) == 0 {
		t.Fatalf("expected an error mentioning %q", want)
	}
	var flat string
	for _, e := range errs {
		flat += e.Error() + "\n"
	}
	if !strings.Contains(flat, want) {
		t.Errorf("errors should mention %q, got:\n%s", want, flat)
	}
}

// TestValidateGateFailOnPriority: a band nobody can rank would widen or narrow the gate silently,
// depending on which way the comparison fell.
func TestValidateGateFailOnPriority(t *testing.T) {
	base := func(p string) *Model {
		return &Model{Release: Release{Name: "x", Version: "1"},
			Config: Config{Gate: &GateConfig{FailOnPriority: Unstated(p)}}}
	}
	for _, ok := range []string{"", "P1", "P4"} {
		if err := base(ok).Validate(); err != nil {
			t.Errorf("%q should be a valid priority gate: %v", ok, err)
		}
	}
	err := base("p1").Validate()
	if err == nil {
		t.Fatal("a lower-case band should not be accepted silently")
	}
	if !strings.Contains(err.Error(), "P1") {
		t.Errorf("the error should name the bands: %v", err)
	}
}
