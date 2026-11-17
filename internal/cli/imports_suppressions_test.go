package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

// toolFile writes a SARIF file from the named tool whose results are each a rule id, a file and the
// suppressions array the case asks for, placed in repository by its versionControlProvenance where
// one is given.
func toolFile(t *testing.T, tool, repository string, results ...[3]string) string {
	t.Helper()
	var rs []string
	for _, r := range results {
		rs = append(rs, `{"ruleId":"`+r[0]+`","level":"error","message":{"text":"`+r[0]+` found"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"`+r[1]+`"}}}],"suppressions":`+r[2]+`}`)
	}
	vcp := ""
	if repository != "" {
		vcp = `"versionControlProvenance":[{"repositoryUri":"` + repository + `"}],`
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `"}},` + vcp +
		`"results":[` + strings.Join(rs, ",") + `]}]}`
	p := filepath.Join(t.TempDir(), tool+".sarif")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// One component of two repositories imports two files: bandit's, honored by default, placed in the
// second repository, and acme-analyzer's, counted. Bandit's two standing suppressions are set aside
// and named by the tool, where it recorded each and why, in the console's ACCEPTED block and in
// report.json; its rejected one counts. Every acme-analyzer finding counts, and the one it suppressed
// says so in its detail, so the two files' settings do not leak into each other.
func TestImportsHonorOrCountTheirToolsSuppressions(t *testing.T) {
	api, worker := t.TempDir(), t.TempDir()
	bandit := toolFile(t, "bandit", worker,
		[3]string{"B105", "app/config.py", `[{"kind":"inSource"}]`},
		[3]string{"B303", "app/cache.py", `[{"kind":"external","status":"accepted","justification":"cache keys, not passwords"}]`},
		[3]string{"B608", "app/db.py", `[{"kind":"external","status":"rejected"}]`},
	)
	acme := toolFile(t, "acme-analyzer", "",
		[3]string{"ACME-1", "web/handler.go", `[{"kind":"inSource","justification":"reviewed"}]`},
		[3]string{"ACME-2", "web/query.go", `[]`},
	)
	saga := writeSaga(t, `
project: shop
config:
  controls: {}
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: "`+api+`"
      - url: "`+worker+`"
    imports:
      - control: sast
        file: "`+bandit+`"
      - control: sast
        file: "`+acme+`"
        suppressions: count
`)
	opts := scanOptions{format: "json", noGate: true, minPriority: "P4"}
	var buf bytes.Buffer
	if err := runScan(context.Background(), saga, opts, builtins.Registry(), &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Tool, Scanner, RuleID string
			Suppressed            *struct{ Justification, Origin, Source string }
		} `json:"findings"`
		Suppressed *struct{ Total int } `json:"suppressed"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	type aside struct{ tool, origin, why, source string }
	got := map[string]*aside{}
	for _, f := range doc.Findings {
		if f.Scanner != "sarif-import" {
			t.Errorf("%s: scanner %q, want sarif-import", f.RuleID, f.Scanner)
		}
		got[f.RuleID] = nil
		if s := f.Suppressed; s != nil {
			got[f.RuleID] = &aside{f.Tool, s.Origin, s.Justification, s.Source}
		}
	}
	want := map[string]*aside{
		"B105":   {"bandit", "tool", "", bandit},
		"B303":   {"bandit", "scanner", "cache keys, not passwords", bandit},
		"B608":   nil,
		"ACME-1": nil,
		"ACME-2": nil,
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %+v, want %d", doc.Findings, len(want))
	}
	for rule, w := range want {
		g := got[rule]
		if (g == nil) != (w == nil) || (g != nil && *g != *w) {
			t.Errorf("%s set aside as %+v, want %+v", rule, g, w)
		}
	}
	if doc.Suppressed == nil || doc.Suppressed.Total != 2 {
		t.Errorf("suppressed = %+v, want bandit's two", doc.Suppressed)
	}

	opts.format, opts.evidence = "console", true
	var console bytes.Buffer
	if err := runScan(context.Background(), saga, opts, builtins.Registry(), &console); err != nil {
		t.Fatal(err)
	}
	out := console.String()
	for _, line := range []string{
		"imported bandit  2 findings the tool suppressed, not counted",
		"who: not recorded by the tool",
		"in a comment in the code · no reason given · 1 finding · B105",
		"in the tool's own settings · reason: cache keys, not passwords · 1 finding · B303",
		// The console keeps the end of a long detail, which is what the setting did.
		"in a comment in the code · reason: reviewed · counted, as the import says suppressions: count\n",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("console lacks %q:\n%s", line, out)
		}
	}
	if strings.Contains(out, "scanner exclusions") || strings.Contains(out, "imported acme-analyzer  ") {
		t.Errorf("an imported tool's suppressions were counted as a scanner's, or a counted file's were set aside:\n%s", out)
	}
}

// The gate judges what the setting leaves counting: a file whose only finding its tool suppressed
// passes honored and fails counted.
func TestTheGateFollowsAnImportsSuppressions(t *testing.T) {
	file := toolFile(t, "bandit", "", [3]string{"B105", "app/config.py", `[{"kind":"inSource"}]`})
	descriptor := func(setting string) string {
		return writeSaga(t, `
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
        file: "`+file+`"`+setting+`
`)
	}
	for _, c := range []struct {
		setting, verdict string
	}{
		{"", "pass"},
		{"\n        suppressions: honor", "pass"},
		{"\n        suppressions: count", "fail"},
	} {
		var buf bytes.Buffer
		_ = runScan(context.Background(), descriptor(c.setting), scanOptions{format: "json"}, builtins.Registry(), &buf)
		var doc struct{ Verdict string }
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("%q: %v\n%s", c.setting, err, buf.String())
		}
		if !strings.EqualFold(doc.Verdict, c.verdict) {
			t.Errorf("suppressions%q: verdict %q, want %q", c.setting, doc.Verdict, c.verdict)
		}
	}
}

// A value that is neither honor nor count is refused before anything runs.
func TestAnImportsSuppressionsSettingIsValidated(t *testing.T) {
	saga := writeSaga(t, `
project: shop
components:
  - name: api
    imports:
      - control: sast
        file: x.sarif
        suppressions: ignore
`)
	err := runScan(context.Background(), saga, scanOptions{format: "json"}, builtins.Registry(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `imports[0]: suppressions "ignore" is not honor or count`) {
		t.Errorf("err = %v, want the value refused", err)
	}
}
