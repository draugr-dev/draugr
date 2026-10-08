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
	"github.com/draugr-dev/draugr/pkg/saga"
)

// importSaga declares a component importing gosec's own SARIF output, with nothing else enabled,
// so the run needs no tool: the import scanner reads a file.
func importSaga(t *testing.T, gate string) string {
	t.Helper()
	abs, err := filepath.Abs("../scanners/testdata/sarif-import/gosec.sarif")
	if err != nil {
		t.Fatal(err)
	}
	return writeSaga(t, `
project: shop
config:
`+gate+`
  controls: {}
components:
  - name: api
    exposure: public
    criticality: critical
    imports:
      - control: sast
        file: "`+abs+`"
`)
}

// An imported file's findings are judged with everything else: they reach report.json under the
// control the descriptor named, and the file, stating no revision, is listed as unbound.
func TestAnImportedFileIsRankedAndGated(t *testing.T) {
	var buf bytes.Buffer
	err := runScan(context.Background(), importSaga(t, ""), scanOptions{format: "json"}, builtins.Registry(), &buf)
	if err == nil || !strings.Contains(err.Error(), "policy verdict: fail") {
		t.Fatalf("err = %v, want the gate to fail on gosec's findings", err)
	}
	var doc struct {
		Controls []struct {
			Name    string `json:"name"`
			Verdict string `json:"verdict"`
		} `json:"controls"`
		Actions []struct {
			Control   string `json:"control"`
			Component string `json:"component"`
			Priority  string `json:"priority"`
			Clears    int    `json:"clears"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, c := range doc.Controls {
		failed = failed || (c.Name == "sast" && c.Verdict == "fail")
	}
	if !failed {
		t.Errorf("controls = %+v, want sast failing on the imported findings", doc.Controls)
	}
	clears := 0
	for _, a := range doc.Actions {
		if a.Control != "sast" || a.Component != "api" || a.Priority != "P1" {
			t.Errorf("action %+v, want it under sast, on api, ranked P1", a)
		}
		clears += a.Clears
	}
	if clears != 3 {
		t.Errorf("actions clear %d findings, want gosec's three", clears)
	}

	var console bytes.Buffer
	_ = runScan(context.Background(), importSaga(t, ""), scanOptions{format: "console"}, builtins.Registry(), &console)
	if !strings.Contains(console.String(), "unbound") || !strings.Contains(console.String(), "tool: gosec 2.29.0") {
		t.Errorf("want the unbound caveat and the tool under measured against:\n%s", console.String())
	}
}

// failOnCaveats: [unbound-imports] makes a file that names no revision fail the run.
func TestAnUnboundImportCanFailTheRun(t *testing.T) {
	gate := "  gate:\n    failOnCaveats: [" + string(saga.CaveatUnboundImports) + "]"
	err := runScan(context.Background(), importSaga(t, gate), scanOptions{format: "json", noGate: true}, builtins.Registry(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "1 caveat fails it under config.gate.failOnCaveats") {
		t.Errorf("err = %v, want the unbound import to fail the run", err)
	}
}

// A misspelled control is refused before anything runs, naming the import.
func TestAnImportNamingNoControlIsRefused(t *testing.T) {
	path := writeSaga(t, `
project: shop
components:
  - name: api
    imports:
      - control: sats
        file: x.sarif
`)
	err := runScan(context.Background(), path, scanOptions{format: "json"}, builtins.Registry(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `components["api"].imports[0].control: "sats" is not a control`) {
		t.Errorf("err = %v, want the misspelled control named", err)
	}
	_ = os.Remove(path)
}
