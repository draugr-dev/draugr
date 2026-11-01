package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

const sagaWithAcceptedBy = `project: app
release:
  version: "1.0"
components:
  - name: c
    images:
      - image: repo/x:1
config:
  controls:
    images:
      enabled: true
  exclude:
    - rules: ["R"]
      reason: "accepted for the test"
      acceptedBy: "someone@example.com"
`

// removedAcceptedBy is what the refusal has to say: that the key is gone rather than misspelled,
// and where the record of who wrote the exclusion is now.
var removedAcceptedBy = []string{
	"config.exclude.acceptedBy was removed", "git blame", "descriptor.exclusions[].gitHistory",
}

func assertRemovedAcceptedBy(t *testing.T, got string) {
	t.Helper()
	for _, want := range removedAcceptedBy {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not say %q", got, want)
		}
	}
}

// validate refuses a descriptor that still sets acceptedBy, and the error names what replaced it.
func TestValidateRefusesAcceptedBy(t *testing.T) {
	path := writeSaga(t, sagaWithAcceptedBy)
	var out bytes.Buffer
	err := runValidate([]string{path}, &out)
	if err == nil {
		t.Fatalf("validate accepted acceptedBy:\n%s", out.String())
	}
	assertRemovedAcceptedBy(t, err.Error())
}

// A fragment validated on its own is refused the same way.
func TestValidateRefusesAFragmentsAcceptedBy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "team.saga-fragment.yaml")
	body := "config:\n  exclude:\n    - rules: [R]\n      reason: r\n      acceptedBy: team\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runValidate([]string{path}, &out)
	if err == nil {
		t.Fatalf("validate accepted acceptedBy in a fragment:\n%s", out.String())
	}
	assertRemovedAcceptedBy(t, err.Error())
}

// scan refuses the descriptor before running anything, so no report is written for it.
func TestScanRefusesAcceptedBy(t *testing.T) {
	path := writeSaga(t, sagaWithAcceptedBy)
	var out bytes.Buffer
	err := runScan(context.Background(), path, scanOptions{failOn: "error", format: "json", noPublish: true, minPriority: "P4"},
		fakeRegistry(sarif.LevelError), &out)
	if err == nil {
		t.Fatalf("scan ran a descriptor that sets acceptedBy:\n%s", out.String())
	}
	assertRemovedAcceptedBy(t, err.Error())
	if out.Len() != 0 {
		t.Errorf("a refused descriptor still produced a report:\n%s", out.String())
	}
}
