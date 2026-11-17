package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

// Two components, each in a repository of its own, import the same file from a tool Draugr has no
// table for, each with its own mapping of the tool's rating. Each component's finding is rated by its
// own import's mapping: the same file, read twice under the same digest, is two scans and not one
// answered from the other's result. The file is hand-written, naming a tool no table covers.
func TestEachImportIsRatedByItsOwnMapping(t *testing.T) {
	file := filepath.Join(t.TempDir(), "acme.sarif")
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"acme-analyzer","rules":[{"id":"ACME-1"}]}},
"results":[{"ruleId":"ACME-1","level":"warning","message":{"text":"Tainted input reaches a query."},
"properties":{"impact":"Blocker"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"db.go"}}}]}]}]}`
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	saga := writeSaga(t, `
project: shop
config:
  controls: {}
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: "`+t.TempDir()+`"
    imports:
      - control: sast
        file: "`+file+`"
        severity:
          property: impact
          values: {Blocker: critical}
  - name: web
    exposure: public
    criticality: critical
    repositories:
      - url: "`+t.TempDir()+`"
    imports:
      - control: sast
        file: "`+file+`"
        severity:
          property: impact
          values: {blocker: low}
`)
	var buf bytes.Buffer
	if err := runScan(context.Background(), saga, scanOptions{format: "sarif", noGate: true}, builtins.Registry(), &buf); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Properties struct {
					Component string `json:"component"`
					Priority  string `json:"priority"`
					Rating    struct {
						Severity string `json:"severity"`
						Detail   string `json:"detail"`
					} `json:"draugr/rating"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, run := range log.Runs {
		for _, r := range run.Results {
			p := r.Properties
			got[p.Component] = p.Rating.Severity + " " + p.Rating.Detail + " " + p.Priority
		}
	}
	// The level alone, warning, would rank both medium.
	want := map[string]string{"api": "critical impact Blocker P1", "web": "low impact Blocker P3"}
	if len(got) != len(want) || got["api"] != want["api"] || got["web"] != want["web"] {
		t.Errorf("findings = %v, want %v\n%s", got, want, buf.String())
	}
}

// A mapping naming a word that is not a severity is refused before anything runs.
func TestAnImportMappingToNoSeverityIsRefused(t *testing.T) {
	saga := writeSaga(t, `
project: shop
components:
  - name: api
    imports:
      - control: sast
        file: x.sarif
        severity:
          property: impact
          values: {Blocker: severe}
`)
	err := runScan(context.Background(), saga, scanOptions{format: "json"}, builtins.Registry(), &bytes.Buffer{})
	want := `imports[0].severity.values["Blocker"]: "severe" is not a severity: use critical, high, medium, low`
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Errorf("err = %v, want %q", err, want)
	}
}
