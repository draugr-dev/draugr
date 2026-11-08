package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// writeResultsSARIF is results.sarif as -o writes it.
func writeResultsSARIF(t *testing.T, data report.Data) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := writeArtifacts(dir, []string{"sarif"}, data, saga.Release{}, data.Run, norn.Result{}, "", ""); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(filepath.Join(dir, "results.sarif")) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// caveatsAndAFinding is a run with one finding, one unread file and one scan error.
func caveatsAndAFinding() report.Data {
	return report.Data{Project: "shop", Version: "1.2.3", Run: engine.Result{
		Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
			Results: []sarif.Result{{RuleID: "CVE-1", Level: sarif.LevelError, Message: "m", Tool: "trivy"}},
		}}},
		Inputs: []engine.InputCoverage{{Component: "api", Control: "sca", Unread: []engine.UnreadInput{
			{Repository: ".", Path: "package.json", Reason: "no lockfile"},
		}}},
		ScanErrors: map[string][]string{"sast": {"gosec: exit status 2"}},
	}}
}

// The file -o writes carries what the file a publisher renders carries: the report's own options, and
// no second copy of them to drift. results.sarif does not go through the reporter.
func TestResultsSARIFCarriesTheRunsNotifications(t *testing.T) {
	data := caveatsAndAFinding()
	var doc struct {
		Runs []struct {
			AutomationDetails struct {
				ID string `json:"id"`
			} `json:"automationDetails"`
			Invocations []struct {
				ExecutionSuccessful        bool `json:"executionSuccessful"`
				ToolExecutionNotifications []struct {
					Descriptor struct {
						ID string `json:"id"`
					} `json:"descriptor"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Tool struct {
				Driver struct {
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(writeResultsSARIF(t, data), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	if run.AutomationDetails.ID != report.AutomationID("shop", engine.Scope{}) || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("the file lost what it already carried: %+v", run)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("want one unsuccessful invocation, got %+v", run.Invocations)
	}
	var kinds []string
	for _, n := range run.Invocations[0].ToolExecutionNotifications {
		kinds = append(kinds, n.Descriptor.ID)
	}
	if want := []string{"scan-error", "unread-files"}; !reflect.DeepEqual(kinds, want) {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
}

// A notification is no finding on either side of a comparison, and an older file with none reads the
// same, so `draugr diff` and `--base` count what they counted before.
func TestNotificationsDoNotMoveADiff(t *testing.T) {
	data := caveatsAndAFinding()
	withNotes, err := sarif.FromSARIF(writeResultsSARIF(t, data))
	if err != nil {
		t.Fatal(err)
	}
	var older report.Data
	older.Run = data.Run
	older.Run.Inputs, older.Run.ScanErrors = nil, nil
	without, err := sarif.FromSARIF(writeResultsSARIF(t, older))
	if err != nil {
		t.Fatal(err)
	}
	if len(withNotes.Results) != 1 {
		t.Fatalf("got %d findings read back, want the 1 finding and no notification", len(withNotes.Results))
	}
	for name, r := range map[string]diff.Result{
		"new against old": diff.Compare(without, withNotes),
		"old against new": diff.Compare(withNotes, without),
	} {
		if len(r.New) != 0 || len(r.Fixed) != 0 {
			t.Errorf("%s: %d new and %d fixed, want none", name, len(r.New), len(r.Fixed))
		}
	}
}

// A scanner turned off on a scan with no descriptor reports every file that called for it, past where
// FOUND stops naming them. The row's text is for a reader, and a location has to be a path.
func TestFoundPathsAreEveryFile(t *testing.T) {
	tree := inventory.Tree{Terraform: []string{"a/main.tf", "b/main.tf", "c/main.tf", "d/main.tf", "e/main.tf", "f/main.tf", "g/main.tf"}}
	rows := foundRows(tree)
	paths := foundPaths(rows, "iac")
	if !slices.Equal(paths, tree.Terraform) {
		t.Errorf("foundPaths = %v, want every file in %v", paths, tree.Terraform)
	}
	if got := foundPaths(rows, "semgrep"); got != nil {
		t.Errorf("foundPaths for a scanner no row names = %v", got)
	}
}
