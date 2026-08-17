package cli

import (
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
)

// Both guards below protect the same failure, from two sides: the self-scan running against a
// runner that lacks a scanner its descriptor enables. A control whose scanner is missing reports
// an error rather than a pass — the design working — so the branch goes red for a reason that is
// about the runner rather than about the code, and the pull request that would fix it is blocked
// by the thing it fixes.

const selfscanWorkflow = "../../.github/workflows/selfscan.yml"

// TestSelfscanAsksTheActionToProvisionScanners guards the line the whole job rests on.
//
// The workflow installs nothing itself: it hands the action `tools: true` and Draugr provisions
// its own scanners, which is what the action offers every user and therefore what this job should
// be exercising. That is one input, easily lost to a merge or an edit, and losing it produces no
// error anyone reads until every control fails at once.
//
// Deliberately a check on the input rather than on how the action honors it — that has its own
// tests. What nothing else can see is the self-scan quietly ceasing to ask.
func TestSelfscanAsksTheActionToProvisionScanners(t *testing.T) {
	t.Parallel()
	workflow := readSelfscanWorkflow(t)
	if !regexp.MustCompile(`(?m)^\s+tools:\s+true\s*$`).MatchString(workflow) {
		t.Error("selfscan.yml no longer passes `tools: true` to the action, so nothing provisions " +
			"the scanners: every control will report an error and main goes red for a reason " +
			"that is not about the code")
	}
}

// TestSelfscanInstallsEveryScannerItsDescriptorEnables catches what `tools: true` cannot cover.
//
// `draugr tools install` provisions the tools Draugr has pinned and verified, and nothing else. A
// control backed by a tool Draugr does not distribute — a proprietary one, or an environment
// prerequisite — is enabled in the descriptor, valid, registered, and simply absent from the
// runner. Nothing about it looks wrong beforehand.
//
// So: a tool the descriptor requires is either installable by Draugr, or named in the workflow.
// Asked of the real registry rather than of the descriptor's text, because what a control needs
// is a fact about the scanners serving it and not about which words the file happens to contain.
//
// Deliberately shallow on the second half: it asks whether the workflow mentions the tool at all,
// not how it installs it. A test that understood installation would need rewriting every time one
// changed, and the omission is the thing worth catching.
func TestSelfscanInstallsEveryScannerItsDescriptorEnables(t *testing.T) {
	t.Parallel()
	workflow := readSelfscanWorkflow(t)
	model, err := loadSaga("../../.draugr/self.saga.yaml")
	if err != nil {
		t.Fatalf("load descriptor: %v", err)
	}

	installable := tools.Installable()
	for _, tool := range requiredTools(builtins.Registry(), model) {
		if tool.Category == tools.CategoryUtility || slices.Contains(installable, tool.Binary) {
			continue
		}
		named := regexp.MustCompile(`\b` + regexp.QuoteMeta(tool.Binary) + `\b`)
		if !named.MatchString(workflow) {
			t.Errorf("%s is required by a control .draugr/self.saga.yaml enables and `draugr tools "+
				"install` cannot provision it, but selfscan.yml never mentions it — the scan will "+
				"report that control as an error, and main goes red for a reason that is not "+
				"about the code", tool.Binary)
		}
	}
}

func readSelfscanWorkflow(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(selfscanWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", selfscanWorkflow, err)
	}
	return string(data)
}
