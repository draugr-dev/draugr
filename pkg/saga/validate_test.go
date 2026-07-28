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
	if m.Components[0].Exposure != ExposurePublic || m.Components[0].Criticality != CriticalityCritical {
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
	if m.Components[0].Exposure != "" || m.Components[0].Criticality != "" {
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
	// A compound licence id: the package itself contains slashes, which is exactly why `*` has
	// to cross separators here.
	const lic = "license/GPL-3.0-only/github.com/somelib/thing"

	cases := []struct {
		pattern string
		ruleID  string
		want    bool
	}{
		{"license/GPL-3.0-only/*", lic, true}, // this licence, any package
		{"license/*", lic, true},              // every licence finding
		{lic, lic, true},                      // exact, no wildcard
		{"license/MIT/*", lic, false},         // different licence
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
