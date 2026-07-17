package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A minimal Draugr SARIF report with one result.
func sarifDoc(ruleID, level, uri, priority string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr","rules":[]}},"results":[
{"ruleId":"` + ruleID + `","level":"` + level + `","message":{"text":"` + ruleID + ` msg"},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + uri + `"}}}],
"properties":{"tool":"trivy","priority":"` + priority + `"}}]}]}`
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunDiffReportsDelta(t *testing.T) {
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	var out bytes.Buffer
	if err := runDiff(base, head, diffOptions{format: "console"}, &out); err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "1 new") || !strings.Contains(s, "CVE-2") || !strings.Contains(s, "CVE-1") {
		t.Errorf("diff output missing expected content:\n%s", s)
	}
}

func TestRunDiffGateTrips(t *testing.T) {
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	var out bytes.Buffer
	err := runDiff(base, head, diffOptions{format: "console", failOnNewPriority: "P2"}, &out)
	if err == nil {
		t.Error("expected the differential gate to trip on a new P1")
	}
}

func TestRunDiffGatePasses(t *testing.T) {
	// Head only fixes a finding — no new ones, so no gate can trip.
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "error", "img", "P1"))
	head := writeFile(t, "head.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[]}]}`)
	var out bytes.Buffer
	if err := runDiff(base, head, diffOptions{failOnNew: "error", failOnNewPriority: "P1"}, &out); err != nil {
		t.Errorf("gate should pass when there are no new findings: %v", err)
	}
	if !strings.Contains(out.String(), "1 fixed") {
		t.Errorf("expected a fixed finding, got:\n%s", out.String())
	}
}

func TestRunDiffMissingFile(t *testing.T) {
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	err := runDiff(filepath.Join(t.TempDir(), "nope.sarif"), head, diffOptions{}, &bytes.Buffer{})
	if err == nil {
		t.Error("expected an error for a missing base report")
	}
}

func TestRunDiffBadFormat(t *testing.T) {
	base := writeFile(t, "base.sarif", sarifDoc("CVE-1", "warning", "img", "P3"))
	head := writeFile(t, "head.sarif", sarifDoc("CVE-2", "error", "img", "P1"))
	if err := runDiff(base, head, diffOptions{format: "bogus"}, &bytes.Buffer{}); err == nil {
		t.Error("expected an error for an unknown format")
	}
}
