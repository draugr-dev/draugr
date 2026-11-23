package scanners

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The reports in testdata/kics read testdata/kics/dockerfile/Dockerfile, which opens with two lines
// of comments and sets neither USER nor HEALTHCHECK:
//
//   - dockerfile.json is the report KICS 2.2.1 (checkmarx/kics:v2.2.1) wrote over draugr-demo's
//     app/Dockerfile, the file the directory copies, with the source mounted at /src.
//   - dockerfile-trivy.json is Trivy 0.76.1's `trivy fs --scanners misconfig --format json
//     --show-suppressed --offline-scan` over it, and dockerfile-trivy.sarif what `trivy convert
//     --format sarif` wrote from that report, the two commands trivy-config runs.
//
// Trivy reports both checks about the file as a whole, with no lines in its JSON and at line 1 in
// its SARIF; KICS reports both at the FROM on line 3.

// trivyRecorded answers trivy-config's scan with the recorded JSON report and its conversion with
// the recorded SARIF.
func trivyRecorded(t *testing.T) func(context.Context, string, []string) ([]byte, []byte, error) {
	t.Helper()
	report := readFixture(t, "dockerfile-trivy.json")
	converted := readFixture(t, "dockerfile-trivy.sarif")
	return func(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
		switch argv[1] {
		case "fs":
			return report, nil, nil
		case "convert":
			handed, err := os.ReadFile(argv[len(argv)-1])
			if err != nil || !bytes.Equal(handed, report) {
				t.Errorf("convert was handed %.40q (%v), want the scan's report", handed, err)
			}
			return converted, nil, nil
		}
		t.Errorf("unexpected command %v", argv)
		return nil, nil, nil
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "kics", name)) // #nosec G304 -- a fixture this file names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// KICS and Trivy each fail a Dockerfile that opens with comments for having no HEALTHCHECK and no
// USER, Trivy about the file as a whole and KICS at the FROM below the comments. Each setting is
// counted once in each of two repositories, with KICS's copy naming Trivy's. Not parallel: it swaps
// kicsDetect and the Trivy version.
func TestKICSAndTrivyCountAWholeDockerfileCheckOnce(t *testing.T) {
	prior := kicsDetect
	t.Cleanup(func() { kicsDetect = prior })
	kicsDetect = func(context.Context) tools.Status { return tools.Status{Found: true} }
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.76.1;db@2026-11-22T00:00:00Z"

	dir, err := filepath.Abs(filepath.Join("testdata", "kics", "dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	checkout := func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dir}, func() {}, nil
	}
	kics := NewKICS().(repoScanner)
	kics.cacheVersion = nil
	kics.checkout = checkout
	var reportDir string
	kics.run = kicsRun(fakeKICS(string(readFixture(t, "dockerfile.json")), exitCode(t, 50), &reportDir))
	trivy := NewTrivyConfig().(repoScanner)
	trivy.cacheVersion, trivy.prewarm, trivy.dataState = nil, nil, nil
	trivy.checkout = checkout
	trivy.runLogged = trivyConfigRun(trivyRecorded(t))

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewIAC())
	reg.RegisterScanner(trivy)
	reg.RegisterScanner(kics)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"iac": {"enabled": true, "kics": map[string]any{"enabled": true}},
		}},
		Components: []saga.Component{{Name: "api",
			Repositories: []saga.Repository{{URL: "app-a"}, {URL: "app-b"}}}},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	// Each setting by both of its rule ids, whichever copy is counted.
	settings := map[string]string{
		"fd54f200-402c-4333-a5a4-36ef6709af2f": "user", "DS-0002": "user",
		"b03a748a-542d-44f4-bb86-9199ab4fd2d5": "healthcheck", "DS-0026": "healthcheck",
		"f2f903fb-b977-461e-98d7-b3e2185c6118": "pip cache", // which no Trivy check tests
	}
	results := res.Controls["iac"].Report.Results
	if len(results) != 10 {
		t.Fatalf("%d results, want 10: both tools' findings in two repositories", len(results))
	}
	counted := map[string]int{}
	for _, r := range results {
		if r.Correlated() {
			continue
		}
		setting := settings[r.RuleID]
		counted[r.Repository+" "+setting]++
		if setting == "pip cache" {
			continue
		}
		if c := r.Correlation; c == nil || len(c.AlsoFoundBy) != 1 || settings[c.AlsoFoundBy[0].RuleID] != setting ||
			c.AlsoFoundBy[0].RuleID == r.RuleID {
			t.Errorf("%s %s in %s = %+v, want the other tool's copy named", r.Tool, r.RuleID, r.Repository, c)
		}
	}
	want := map[string]int{}
	for _, repo := range []string{"app-a", "app-b"} {
		for _, setting := range []string{"user", "healthcheck", "pip cache"} {
			want[repo+" "+setting] = 1
		}
	}
	if fmt.Sprint(counted) != fmt.Sprint(want) {
		t.Errorf("counted %v\nwant %v", counted, want)
	}
}

// A check Trivy reports about a Dockerfile as a whole gets the whole file as its region; one it
// reports at an instruction on line 1, or a check the file also failed at line 1, keeps line 1, and
// so does a whole-file check of a file that cannot be read.
func TestAWholeDockerfileCheckCoversTheFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("# base\nFROM alpine:latest\nCMD [\"true\"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := `{"Results": [
	  {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
	   "Misconfigurations": [
	     {"ID": "DS-0026", "Status": "FAIL", "CauseMetadata": {"Provider": "Dockerfile"}},
	     {"ID": "DS-0001", "Status": "FAIL", "CauseMetadata": {"StartLine": 1, "EndLine": 1}},
	     {"ID": "DS-0005", "Status": "FAIL", "CauseMetadata": {}},
	     {"ID": "DS-0005", "Status": "FAIL", "CauseMetadata": {"StartLine": 1, "EndLine": 1}},
	     {"ID": "DS-0013", "Status": "FAIL", "CauseMetadata": {"StartLine": 3, "EndLine": 3}},
	     {"ID": "DS-0017", "Status": "PASS"}],
	   "ExperimentalModifiedFindings": [
	     {"Type": "misconfiguration", "Status": "ignored", "Source": ".trivyignore",
	      "Finding": {"ID": "DS-0002", "Severity": "HIGH", "Status": "FAIL", "CauseMetadata": {}}}]},
	  {"Target": "missing/Dockerfile", "Class": "config", "Type": "dockerfile",
	   "Misconfigurations": [{"ID": "DS-0026", "Status": "FAIL"}]},
	  {"Target": "k8s/web.yaml", "Class": "config", "Type": "kubernetes",
	   "Misconfigurations": [{"ID": "KSV-0110", "Status": "FAIL"}]}
	]}`
	_, doc, _, err := trivyConfigReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	at := func(uri, rule string, start, end int) string {
		return fmt.Sprintf(`{"ruleId": %q, "locations": [{"physicalLocation": {"artifactLocation": {"uri": %q},
		  "region": {"startLine": %d, "endLine": %d}}}]}`, rule, uri, start, end)
	}
	sarifOut := `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": [` + strings.Join([]string{
		at("Dockerfile", "DS-0026", 1, 1), at("Dockerfile", "DS-0001", 1, 1), at("Dockerfile", "DS-0005", 1, 1),
		at("Dockerfile", "DS-0013", 3, 3), at("missing/Dockerfile", "DS-0026", 1, 1), at("k8s/web.yaml", "KSV-0110", 1, 1),
	}, ",") + `]}]}`
	// In the order trivyConfigRun applies them, so an excluded check is measured too.
	out, err := withTrivyMisconfigExclusions([]byte(sarifOut), doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err = withWholeFileRegions(out, doc, dir)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.RuleID+"@"+r.Location.URI] = fmt.Sprintf("%d-%d", r.Location.StartLine, r.Location.EndLine)
	}
	want := map[string]string{
		"DS-0026@Dockerfile": "1-3", "DS-0002@Dockerfile": "1-3",
		"DS-0001@Dockerfile": "1-0", "DS-0005@Dockerfile": "1-0", "DS-0013@Dockerfile": "3-0",
		"DS-0026@missing/Dockerfile": "1-0", "KSV-0110@k8s/web.yaml": "1-0",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("regions %v\nwant %v", got, want)
	}
}

// SARIF is returned unchanged where nothing is a whole-file check or there is no checkout to read,
// and SARIF that cannot be read is an error.
func TestWholeFileRegionsLeaveOtherSARIFAlone(t *testing.T) {
	t.Parallel()
	whole := trivyMisconfigDoc{wholeFile: map[trivyFileCheck]bool{{"Dockerfile", "DS-0026"}: true}}
	ambiguous := trivyMisconfigDoc{wholeFile: map[trivyFileCheck]bool{{"Dockerfile", "DS-0026"}: false}}
	const doc = `{"runs": [{"results": [{"ruleId": "DS-0026", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}, "region": {"startLine": 1}}}]}, {"ruleId": "DS-0026"}]}]}`
	for name, c := range map[string]struct {
		doc trivyMisconfigDoc
		dir string
	}{
		"none whole":  {ambiguous, t.TempDir()},
		"no checkout": {whole, filepath.Join(t.TempDir(), "gone")},
		"no file":     {whole, t.TempDir()},
	} {
		if out, err := withWholeFileRegions([]byte(doc), c.doc, c.dir); err != nil || string(out) != doc {
			t.Errorf("%s: %s, %v", name, out, err)
		}
	}
	if _, err := withWholeFileRegions([]byte("not json"), whole, t.TempDir()); err == nil {
		t.Error("unreadable SARIF was not an error")
	}
	if _, _, _, err := trivyConfigReport([]byte(`{"Results": [{"Target": "Dockerfile", "Type": "dockerfile", "Misconfigurations": "x"}]}`)); err == nil {
		t.Error("an unreadable list of misconfigurations was not an error")
	}
}
