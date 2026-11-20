package sealed

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The copy that goes to code scanning is still SARIF 2.1.0: a result left with no location, a
// location moved to the properties and a notification with none all keep the document valid.
func TestTheCodeScanningCopyIsValidSARIF(t *testing.T) {
	rep := sarif.Report{Tool: "draugr", Results: []sarif.Result{
		{Tool: "trivy", RuleID: "CVE-2023-0464", Level: sarif.LevelError, Message: "openssl", Control: "images",
			Location: sarif.Location{URI: "python:3.8-slim"}, Image: "python:3.8-slim"},
		{Tool: "testssl", RuleID: "TLS1", Level: sarif.LevelWarning, Message: "TLS 1.0", Control: "tls",
			Location: sarif.Location{URI: "https://example.com/"}},
		{Tool: "gosec", RuleID: "G304", Level: sarif.LevelWarning, Message: "file inclusion", Control: "sast",
			Location: sarif.Location{URI: "main.go", StartLine: 7}},
		{Tool: "gitleaks", RuleID: "aws", Level: sarif.LevelError, Message: "key", Control: "secrets",
			Location: sarif.Location{URI: "/work/.env", StartLine: 1}},
	}}
	doc, err := rep.MarshalSARIFWith(sarif.MarshalOptions{Notifications: []sarif.Notification{{
		Kind: "scan-error", Level: sarif.LevelError, Message: "images: pull failed",
		Locations: []sarif.NotificationLocation{{URI: "python:3.8-slim"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := sarif.ForCodeScanning(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSARIF(out); err != nil {
		t.Errorf("the code-scanning copy is not valid SARIF 2.1.0: %v\n%s", err, out)
	}
}
