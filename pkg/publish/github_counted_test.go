package publish

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// decodeUpload undoes the gzip and base64 the code-scanning upload API asks for.
func decodeUpload(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("upload is not base64: %v", err)
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Errorf("upload is not gzip: %v", err)
		return nil
	}
	doc, err := io.ReadAll(zr)
	if err != nil {
		t.Errorf("upload does not decompress: %v", err)
	}
	return doc
}

// startFake serves fake for the length of the test and returns its address.
func startFake(t *testing.T, fake *fakeCodeScanning) string {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return srv.URL
}

// uploadedResult is what these tests read of a result in a SARIF document.
type uploadedResult struct {
	RuleID     string `json:"ruleId"`
	Properties struct {
		Correlation struct {
			AlsoFoundBy []struct {
				Tool   string `json:"tool"`
				RuleID string `json:"ruleId"`
			} `json:"alsoFoundBy"`
			CountedUnder string `json:"countedUnder"`
		} `json:"correlation"`
	} `json:"properties"`
}

func resultsOf(t *testing.T, doc []byte) []uploadedResult {
	t.Helper()
	var d struct {
		Runs []struct {
			Results []uploadedResult `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		t.Fatalf("not a SARIF document: %v\n%s", err, doc)
	}
	var out []uploadedResult
	for _, r := range d.Runs {
		out = append(out, r.Results...)
	}
	return out
}

// correlatedPair is one flaw reported by two scanners, marked as the engine marks it: Trivy's finding
// is counted and names Grype's, and Grype's is counted under Trivy's. Grype's account is either a
// scanner Draugr ran or a SARIF file it imported, which correlation treats alike.
func correlatedPair(rule, copyRule, path string, line int, imported bool, s *sarif.Suppression) []sarif.Result {
	at := sarif.Location{URI: path, StartLine: line}
	counted := sarif.Result{RuleID: rule, Level: sarif.LevelError, Priority: "P1", Tool: "trivy", Scanner: "trivy-fs", Location: at}
	cp := sarif.Result{RuleID: copyRule, Level: sarif.LevelError, Priority: "P1", Tool: "grype", Scanner: "grype", Location: at}
	if imported {
		cp.Scanner, cp.ImportFormat = sarif.ImportScanner, "sarif"
	}
	if s != nil {
		a, b := *s, *s
		counted.Suppression, cp.Suppression = &a, &b
	}
	counted.Correlation = &sarif.Correlation{AlsoFoundBy: []sarif.Observation{{Tool: cp.Reporter(), RuleID: copyRule, Severity: "high"}}}
	cp.Correlation = &sarif.Correlation{CountedUnder: counted.Reporter()}
	return []sarif.Result{counted, cp}
}

func correlatedData(results ...sarif.Result) report.Data {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy-fs", Results: results}},
	}}
	return report.Data{Release: saga.Release{Version: "1.0"}, Run: run, Verdict: norn.Result{Verdict: norn.Fail}}
}

var pairKinds = []struct {
	name     string
	imported bool
}{{"native", false}, {"imported", true}}

// A flaw two scanners reported is uploaded to code scanning once, as the result that is counted, and
// that result still names the other scanner. The results.sarif written beside it from the same render
// keeps both, because it is the evidence of what each scanner said.
func TestGithubPublisherUploadsOneResultPerCountedFinding(t *testing.T) {
	for _, kind := range pairKinds {
		t.Run(kind.name, func(t *testing.T) {
			fake := &fakeCodeScanning{t: t}
			ghEnv(t, startFake(t, fake))
			dir := t.TempDir()
			pair := correlatedPair("CVE-2024-56201", "GHSA-q2x7-8rv6-6q7h", "go.mod", 12, kind.imported, nil)
			err := Run(context.Background(), []saga.PublisherConfig{
				{Kind: "file", Dir: dir, Reports: []saga.ReportConfig{{Format: "sarif"}}},
				{Kind: "github"},
			}, correlatedData(pair...))
			if err != nil {
				t.Fatal(err)
			}

			up := resultsOf(t, fake.uploaded)
			if len(up) != 1 || up[0].RuleID != "CVE-2024-56201" {
				t.Fatalf("uploaded %+v, want the counted CVE-2024-56201 alone", up)
			}
			also := up[0].Properties.Correlation.AlsoFoundBy
			if len(also) != 1 || also[0].Tool != pair[1].Reporter() || also[0].RuleID != "GHSA-q2x7-8rv6-6q7h" {
				t.Errorf("the uploaded result names %+v, want %s's GHSA-q2x7-8rv6-6q7h", also, pair[1].Reporter())
			}

			onDisk, err := os.ReadFile(filepath.Join(dir, "results.sarif")) // #nosec G304 -- a fixed name under t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			kept := resultsOf(t, onDisk)
			if len(kept) != 2 || kept[1].Properties.Correlation.CountedUnder != pair[0].Reporter() {
				t.Errorf("results.sarif holds %+v, want both copies, the second counted under %s", kept, pair[0].Reporter())
			}
		})
	}
}

// The dismissal pass reads what was uploaded. A suppressed finding's alert is dismissed; a counted
// finding that is not suppressed keeps its alert open; and a copy, which is no longer uploaded, has
// its alerts left alone, whether open or dismissed by Draugr, rather than dismissed or reopened.
func TestGithubPublisherDismissesNoCorrelatedAlert(t *testing.T) {
	accepted := &sarif.Suppression{Kind: "external", Justification: "fixed in the base image", Source: "draugr.saga.yaml", Line: 9}
	for _, kind := range pairKinds {
		t.Run(kind.name, func(t *testing.T) {
			results := []sarif.Result{{RuleID: "G304", Level: sarif.LevelWarning, Priority: "P2", Tool: "gosec",
				Location: sarif.Location{URI: "cmd/main.go", StartLine: 7}, Suppression: accepted}}
			results = append(results, correlatedPair("CVE-2024-56201", "GHSA-q2x7-8rv6-6q7h", "go.mod", 12, kind.imported, nil)...)
			results = append(results, correlatedPair("CVE-2023-4911", "GHSA-m77w-6vjw-wh2f", "go.sum", 30, kind.imported, accepted)...)
			fake := &fakeCodeScanning{t: t,
				open: []codeScanningAlert{
					alert(1, "open", "G304", "cmd/main.go", 7, ""),
					alert(2, "open", "CVE-2024-56201", "go.mod", 12, ""),
					alert(3, "open", "GHSA-q2x7-8rv6-6q7h", "go.mod", 12, ""),
					alert(4, "open", "CVE-2023-4911", "go.sum", 30, ""),
					alert(5, "open", "GHSA-m77w-6vjw-wh2f", "go.sum", 30, ""),
				},
				dismissed: []codeScanningAlert{
					alert(6, "dismissed", "GHSA-q2x7-8rv6-6q7h", "go.mod", 12, "Accepted in Draugr: expired since"),
				},
			}
			if err := publishTo(t, fake, correlatedData(results...)); err != nil {
				t.Fatal(err)
			}
			if len(fake.patches) != 2 || fake.patches[1]["state"] != "dismissed" || fake.patches[4]["state"] != "dismissed" {
				t.Fatalf("patched %v, want alerts 1 and 4 dismissed and nothing else", fake.patches)
			}
			if got := fake.patches[4]["dismissed_comment"]; got != "Accepted in Draugr: fixed in the base image (draugr.saga.yaml:9)" {
				t.Errorf("alert 4 comment = %q", got)
			}
		})
	}
}

// A document with no copy in it is uploaded as rendered, and one that cannot be read is refused
// rather than uploaded with its copies.
func TestCountedOnly(t *testing.T) {
	plain := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr"}},"results":[{"ruleId":"R"}]},{"tool":{"driver":{"name":"Draugr"}}}]}`)
	got, err := countedOnly(plain)
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("a document with no copy came back as %s, %v", got, err)
	}

	withCopy := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr","rules":[{"id":"R"},{"id":"S"}]}},"results":[
{"ruleId":"R","ruleIndex":0,"partialFingerprints":{"draugr/v1":"abc"},"properties":{"correlation":{"alsoFoundBy":[{"tool":"grype","ruleId":"S"}]}}},
{"ruleId":"S","ruleIndex":1,"properties":{"correlation":{"countedUnder":"trivy"}}}]}]}`)
	got, err = countedOnly(withCopy)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				RuleIndex           int               `json:"ruleIndex"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("the document around the results changed: %s", got)
	}
	if r := doc.Runs[0].Results; len(r) != 1 || r[0].RuleID != "R" || r[0].RuleIndex != 0 || r[0].PartialFingerprints["draugr/v1"] != "abc" {
		t.Errorf("results = %+v, want R alone and as written", r)
	}

	for name, bad := range map[string]string{
		"not json":         `not json`,
		"no runs":          `{"version":"2.1.0"}`,
		"results not list": `{"runs":[{"results":{}}]}`,
		"correlation odd":  `{"runs":[{"results":[{"properties":{"correlation":"trivy"}}]}]}`,
	} {
		if _, err := countedOnly([]byte(bad)); err == nil || !strings.Contains(err.Error(), "github code scanning") {
			t.Errorf("%s: err = %v, want the document refused", name, err)
		}
	}
}
