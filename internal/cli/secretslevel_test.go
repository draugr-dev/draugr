package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// secretsLevelRun is the real secrets control over two components on two repositories. api is
// public and critical, so the control's context tier changes nothing there; web is internal and
// supporting, so the tier is what decides its band. Each repository holds a secret its scanner rated only by
// the level `warning`, and api's also holds one the scanner scored medium.
func secretsLevelRun(t *testing.T) (string, *engine.Registry) {
	t.Helper()
	cacheHome(t)
	gitleaks := &perRepoScanner{name: "gitleaks", findings: map[string][]sarif.Result{
		apiRepo: {
			{RuleID: "api-level-key", Level: sarif.LevelWarning, Message: "a credential",
				Location: sarif.Location{URI: "config.env", StartLine: 1}},
			{RuleID: "api-scored-key", Level: sarif.LevelWarning, HasScore: true, Score: 5.5, Message: "a credential",
				Location: sarif.Location{URI: "scored.env", StartLine: 2}},
		},
		webRepo: {{RuleID: "web-level-key", Level: sarif.LevelWarning, Message: "a credential",
			Location: sarif.Location{URI: "deploy.env", StartLine: 3}}},
	}}
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSecrets())
	reg.RegisterScanner(gitleaks)
	path := writeSaga(t, `
project: shop
release:
  version: "1.0"
config:
  controls:
    secrets:
      enabled: true
components:
  - name: api
    exposure: public
    criticality: critical
    repositories:
      - url: `+apiRepo+`
  - name: web
    exposure: internal
    criticality: supporting
    repositories:
      - url: `+webRepo+`
`)
	return path, reg
}

// A secret rated only by its level reads back with the scanner's severity, held at the control's
// minimum, through a real scan of two repositories with the run's own prioritizer. The level on the
// wire stays `error`, which is what code scanning and JUnit read; a scored secret is unchanged.
func TestALevelOnlySecretKeepsTheScannersSeverity(t *testing.T) {
	path, reg := secretsLevelRun(t)
	dir := t.TempDir()
	var console bytes.Buffer
	err := runScan(context.Background(), path, scanOptions{outputDir: dir, noPublish: true,
		view: "findings", minPriority: "P4", setFlags: map[string]bool{}}, reg, &console)
	if err == nil {
		t.Fatal("the default gate passed a leaked credential")
	}

	data, err := os.ReadFile(filepath.Join(dir, "results.sarif")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	read, err := sarif.FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		severity, floor sarif.Severity
		component       string
	}{
		"api-level-key":  {sarif.SeverityMedium, sarif.SeverityHigh, "api"},
		"web-level-key":  {sarif.SeverityMedium, sarif.SeverityHigh, "web"},
		"api-scored-key": {sarif.SeverityMedium, sarif.SeverityHigh, "api"},
	}
	if len(read.Results) != len(want) {
		t.Fatalf("got %d results in results.sarif, want %d", len(read.Results), len(want))
	}
	for _, res := range read.Results {
		w, ok := want[res.RuleID]
		if !ok {
			t.Errorf("unexpected finding %s", res.RuleID)
			continue
		}
		if res.Component != w.component {
			t.Errorf("%s: component %q, want %q", res.RuleID, res.Component, w.component)
		}
		if res.Level != sarif.LevelError {
			t.Errorf("%s: level %q, want error, the value code scanning reads", res.RuleID, res.Level)
		}
		if got := res.Severity(""); got != w.severity {
			t.Errorf("%s: severity %q, want the scanner's %q", res.RuleID, got, w.severity)
		}
		if res.SeverityFloor != w.floor {
			t.Errorf("%s: severityFloor %q, want %q", res.RuleID, res.SeverityFloor, w.floor)
		}
		if got := res.RankedSeverity(); got != sarif.SeverityHigh {
			t.Errorf("%s: ranked severity %q, want high", res.RuleID, got)
		}
		if res.Priority != "P1" {
			t.Errorf("%s: priority %q, want P1", res.RuleID, res.Priority)
		}
		if res.HasScore && res.Rating != nil {
			t.Errorf("%s: a scored secret gained a rating %+v", res.RuleID, res.Rating)
		}
	}

	// report.json counts each secret as an error, as before.
	raw, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Controls []struct {
			Name                    string
			Errors, Warnings, Notes int
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Controls {
		if c.Name == "secrets" && (c.Errors != len(want) || c.Warnings != 0 || c.Notes != 0) {
			t.Errorf("secrets counts = %+v, want every finding an error", c)
		}
	}

	// The mark, on the line under the row: ↑ minimum where the component's own tier stood, ↑ floor
	// where the control's tier decided the band.
	marks := map[string]string{"api-level-key": "↑ minimum", "web-level-key": "↑ floor"}
	for rule, mark := range marks {
		row, under := rowAndUnder(console.String(), rule)
		if !strings.Contains(row, "P1  high") || !strings.HasPrefix(under, mark+" ·") {
			t.Errorf("%s: row %q over %q, want P1 high marked %s, in:\n%s", rule, row, under, mark, console.String())
		}
	}
}

// rowAndUnder is the trimmed line of out that holds want, and the trimmed facts line of its block.
//
// The facts line follows the message and any instruction, and the mark, where there is one, leads it.
func rowAndUnder(out, want string) (string, string) {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.Contains(line, want) {
			continue
		}
		for _, next := range lines[i+1:] {
			next = strings.TrimSpace(next)
			if next == "" {
				break
			}
			for _, lead := range []string{"↑ ", "↓ ", "↩ ", "component ", "scanner "} {
				if strings.HasPrefix(next, lead) {
					return strings.TrimSpace(line), next
				}
			}
		}
		return strings.TrimSpace(line), ""
	}
	return "", ""
}
