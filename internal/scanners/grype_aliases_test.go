package scanners

import (
	"encoding/json"
	"slices"
	"testing"
)

// Each result names the vulnerabilities Grype related to its own match: reported by CVE, the GitHub
// advisory it was matched on. An ignored match names them as a reported one does.
func TestGrypeResultsNameTheirRelatedVulnerabilities(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(grypeTestJSON(t, minimatchMatches, "")), &doc); err != nil {
		t.Fatal(err)
	}
	ms := doc["matches"].([]any)
	ignored := ms[len(ms)-1].(map[string]any)
	ignored["appliedIgnoreRules"] = []any{map[string]any{"vulnerability": "CVE-2026-26996", "reason": "not reachable"}}
	doc["matches"], doc["ignoredMatches"] = ms[:len(ms)-1], []any{ignored}

	reported := minimatchMatches[:len(minimatchMatches)-1]
	out, err := withGrypeJSON([]byte(grypeTestSARIF(t, reported, "")), []byte(mustJSON(t, doc)), nil)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := parseGrypeRepoSARIF(out, "/src", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != len(minimatchMatches) {
		t.Fatalf("results = %d, want every match, the ignored one included", len(rep.Results))
	}
	for _, r := range rep.Results {
		var want []string
		for _, m := range minimatchMatches {
			if r.VulnerabilityID() == m.vuln {
				want = []string{m.related}
			}
		}
		if !slices.Equal(r.Aliases, want) {
			t.Errorf("%s (suppressed %v): aliases = %q, want %q", r.RuleID, r.Suppressed(), r.Aliases, want)
		}
	}
}

// The related identifiers are each named once, leaving out the one the match was reported under,
// and matches that fit a result equally and relate different vulnerabilities give none.
func TestGrypeMatchAliases(t *testing.T) {
	var doc grypeDoc
	if err := json.Unmarshal([]byte(grypeTestJSON(t, minimatchMatches[:1], "")), &doc); err != nil {
		t.Fatal(err)
	}
	m := doc.Matches[0]
	m.RelatedVulnerabilities = append(slices.Clone(m.RelatedVulnerabilities),
		grypeVulnerability{ID: m.Vulnerability.ID}, grypeVulnerability{ID: "GHSA-g3hv-75wg-m249"}, grypeVulnerability{})
	if got := grypeMatchAliases(m); !slices.Equal(got, []string{"GHSA-g3hv-75wg-m249"}) {
		t.Errorf("aliases = %q", got)
	}

	other := m
	other.RelatedVulnerabilities = []grypeVulnerability{{ID: "GHSA-2222-2222-2222"}}
	msg := "A medium vulnerability in npm package: minimatch, version 10.2.3 was found at: /pnpm-lock.yaml"
	pkg, aliases, ok := newGrypeMatchIndex([]grypeMatch{m, other}).find("CVE-2026-118764-minimatch", msg, "/pnpm-lock.yaml")
	if !ok || pkg.Version != "10.2.3" || aliases != nil {
		t.Errorf("find = %+v, %q, %v, want the package and no identifiers", pkg, aliases, ok)
	}
}

// The identifiers are read back by result, and a document that does not carry them gives none.
func TestGrypeResultAliases(t *testing.T) {
	for _, c := range []struct {
		name, doc string
		want      [][]string
	}{
		{"by result", `{"runs":[{"results":[{"properties":{"draugr/aliases":["GHSA-x"]}},{}]},{"results":[{"properties":{"draugr/aliases":"GHSA-y"}}]}]}`,
			[][]string{{"GHSA-x"}, nil, nil}},
		{"none carried", `{"runs":[{"results":[{},{"properties":{"draugr/aliases":[]}}]}]}`, nil},
		{"not JSON", `{`, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := grypeResultAliases([]byte(c.doc))
			if len(got) != len(c.want) {
				t.Fatalf("aliases = %q, want %q", got, c.want)
			}
			for i := range c.want {
				if !slices.Equal(got[i], c.want[i]) {
					t.Errorf("result %d: aliases = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
