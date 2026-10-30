package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
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
  controllers:
    images:
      enabled: true
  exclude:
    - rules: ["R"]
      reason: "accepted for the test"
      acceptedBy: "someone@example.com"
`

// validate accepts a descriptor that still sets acceptedBy and warns under the line saying it is
// valid, naming the file and line of the key and the release that removes it.
func TestValidateWarnsThatAcceptedByIsDeprecated(t *testing.T) {
	path := writeSaga(t, sagaWithAcceptedBy)
	var out bytes.Buffer
	if err := runValidate([]string{path}, &out); err != nil {
		t.Fatalf("validate: %v", err)
	}
	want := "  ! " + path + ":15: acceptedBy is deprecated and " + saga.AcceptedByRemovedIn + " removes it. " +
		"Delete the line. Who wrote the exclusion: git blame -L 13,13 " + path + "\n"
	if !strings.Contains(out.String(), "is valid\n"+want) {
		t.Errorf("output\n%s\nwant the warning under the valid line:\n%s", out.String(), want)
	}
}

// A fragment validated on its own warns the same way, under its own path.
func TestValidateWarnsOnAFragmentsAcceptedBy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "team.saga-fragment.yaml")
	body := "config:\n  exclude:\n    - rules: [R]\n      reason: r\n      acceptedBy: team\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runValidate([]string{path}, &out); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.Contains(out.String(), "  ! "+filepath.ToSlash(path)+":5: acceptedBy is deprecated") {
		t.Errorf("output = %q", out.String())
	}
}

// scan warns on stderr, so a json report on stdout stays one document, and the run goes ahead.
func TestScanWarnsThatAcceptedByIsDeprecated(t *testing.T) {
	path := writeSaga(t, sagaWithAcceptedBy)
	stderr := captureStderr(t)
	var out bytes.Buffer
	if err := runScan(context.Background(), path, scanOptions{failOn: "error", format: "json", noPublish: true, minPriority: "P4"},
		fakeRegistry(sarif.LevelError), &out); err != nil {
		t.Errorf("scan: %v", err)
	}
	if strings.Contains(out.String(), "acceptedBy is deprecated") {
		t.Error("the warning reached the report on stdout")
	}
	// The report keeps the value only under the name that marks it unverified.
	if strings.Contains(out.String(), `"acceptedBy"`) || !strings.Contains(out.String(), `"unverifiedAcceptedBy": "someone@example.com"`) {
		t.Errorf("report.json should carry the value only as unverifiedAcceptedBy:\n%s", out.String())
	}
	if got := stderr(); !strings.Contains(got, "warning: "+path+":15: acceptedBy is deprecated") {
		t.Errorf("stderr = %q", got)
	}
}
