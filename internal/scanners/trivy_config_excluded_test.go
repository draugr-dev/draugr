package scanners

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// trivyMisconfigJSON is `trivy fs --scanners misconfig --format json --show-suppressed` over a
// Dockerfile that runs as root, excluded by `.trivyignore`, and a Terraform file whose rule is
// excluded by an ignore file with a statement, in the fields Trivy 0.74.0 writes. Trivy lists the
// exclusion against a Dockerfile that passes the check as well, with the finding's status PASS.
const trivyMisconfigJSON = `{"Results": [
  {"Target": "app/Dockerfile", "Class": "config", "Type": "dockerfile",
   "Misconfigurations": [{"ID": "DS-0026", "Status": "FAIL"}],
   "ExperimentalModifiedFindings": [
     {"Type": "misconfiguration", "Status": "ignored", "Statement": "", "Source": ".trivyignore",
      "Finding": {"Type": "Dockerfile Security Check", "ID": "DS-0002", "Title": "Image user should not be 'root'",
        "Description": "Running containers with 'root' user can lead to a container escape situation.",
        "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
        "Severity": "HIGH", "PrimaryURL": "https://avd.aquasec.com/misconfig/ds-0002", "Status": "FAIL",
        "CauseMetadata": {"Provider": "Dockerfile", "Service": "general"}}}
   ]},
  {"Target": "ok/Dockerfile", "Class": "config", "Type": "dockerfile",
   "ExperimentalModifiedFindings": [
     {"Type": "misconfiguration", "Status": "ignored", "Source": ".trivyignore",
      "Finding": {"ID": "DS-0002", "Severity": "HIGH", "Status": "PASS"}}
   ]},
  {"Target": "infra/main.tf", "Class": "config", "Type": "terraform",
   "ExperimentalModifiedFindings": [
     {"Type": "misconfiguration", "Status": "ignored", "Statement": "descriptions are generated", "Source": ".trivyignore.yaml",
      "Finding": {"Type": "Terraform Security Check", "ID": "AWS-0124", "Title": "Missing description for security group rule.",
        "Message": "Security group rule does not have a description.", "Severity": "LOW",
        "PrimaryURL": "https://avd.aquasec.com/misconfig/aws-0124", "Status": "FAIL",
        "CauseMetadata": {"StartLine": 11, "EndLine": 18}}},
     {"Type": "misconfiguration", "Status": "ignored", "Statement": "descriptions are generated", "Source": ".trivyignore.yaml",
      "Finding": {"ID": "AWS-0124", "Severity": "LOW", "Status": "FAIL", "CauseMetadata": {"StartLine": 11, "EndLine": 18}}}
   ]}
]}`

// trivyMisconfigSARIF is what `trivy convert` writes from that document: the finding Trivy
// reported, and nothing of the ones it excluded.
const trivyMisconfigSARIF = `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy", "rules": [
  {"id": "DS-0026", "name": "Misconfiguration", "shortDescription": {"text": "No HEALTHCHECK defined"},
   "properties": {"security-severity": "2.0"}}]}},
 "results": [{"ruleId": "DS-0026", "ruleIndex": 0, "level": "note", "message": {"text": "Add HEALTHCHECK instruction in your Dockerfile"},
  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/Dockerfile", "uriBaseId": "ROOTPATH"},
   "region": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1}}}]}]}]}`

// fakeTrivyMisconfig answers the scan with the JSON report and convert with the SARIF, checking
// that convert was handed the report the scan wrote.
func fakeTrivyMisconfig(t *testing.T, calls *[]string) func(context.Context, string, []string) ([]byte, error) {
	return func(_ context.Context, _ string, argv []string) ([]byte, error) {
		*calls = append(*calls, argv[1])
		switch argv[1] {
		case "fs":
			return []byte(trivyMisconfigJSON), nil
		case "convert":
			got, err := os.ReadFile(argv[len(argv)-1])
			if err != nil || !bytes.Equal(got, []byte(trivyMisconfigJSON)) {
				t.Errorf("convert was handed %q (%v), want the scan's report", got, err)
			}
			return []byte(trivyMisconfigSARIF), nil
		}
		t.Errorf("unexpected command %v", argv)
		return nil, nil
	}
}

// A misconfiguration `.trivyignore` excluded reaches the report as a suppression by the scanner,
// with the file and statement, over two repositories. The finding Trivy reported arrives as it did.
func TestAnExcludedMisconfigurationArrivesSuppressed(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"

	for _, repo := range []string{"infra-a", "infra-b"} {
		var calls []string
		dir := t.TempDir()
		s := NewTrivyConfig().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		s.run = trivyConfigRun(fakeTrivyMisconfig(t, &calls))
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(calls, ",") != "fs,convert" {
			t.Errorf("%s: commands %v, want one scan and one conversion", repo, calls)
		}
		got := map[string]sarif.Result{}
		for _, r := range rep.Results {
			got[r.RuleID+"@"+r.Location.URI] = r
		}
		if len(got) != 3 || len(rep.Results) != 3 {
			t.Fatalf("%s: results %v, want the reported check and the two failed checks excluded once each", repo, got)
		}
		if got["DS-0026@app/Dockerfile"].Suppression != nil {
			t.Errorf("%s: the check Trivy reported arrived suppressed", repo)
		}
		for key, want := range map[string]struct {
			source, why string
			level       sarif.Level
			start       int
		}{
			"DS-0002@app/Dockerfile": {".trivyignore", "", sarif.LevelError, 1},
			"AWS-0124@infra/main.tf": {".trivyignore.yaml", "descriptions are generated", sarif.LevelNote, 11},
		} {
			r, ok := got[key]
			sup := r.Suppression
			switch {
			case !ok || sup == nil:
				t.Errorf("%s: %s has no suppression, so the exclusion leaves no record", repo, key)
			case sup.Origin != sarif.OriginScanner || sup.Kind != "external":
				t.Errorf("%s: %s origin %q kind %q, want the scanner's own configuration", repo, key, sup.Origin, sup.Kind)
			case sup.Source != want.source || sup.Justification != want.why:
				t.Errorf("%s: %s source %q justification %q", repo, key, sup.Source, sup.Justification)
			case r.Level != want.level || r.Location.StartLine != want.start:
				t.Errorf("%s: %s level %q line %d", repo, key, r.Level, r.Location.StartLine)
			}
		}
		if r := rep.Rules["DS-0002"]; r.ShortDescription != "Image user should not be 'root'" || r.HelpURI == "" {
			t.Errorf("%s: rule %+v, want the check's own documentation", repo, r)
		}
	}
}

// An older Trivy has no --show-suppressed, so the scan stays `trivy config` writing SARIF, and the
// run hands its output through untouched.
func TestAnOlderTrivyConfigScanIsUnchanged(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })

	sharedTrivyVersion.val = "trivy@0.52.0;db@2026-07-15T00:56:58Z"
	argv := trivyConfigArgs("/tree", nil)
	if argv[1] != "config" || !hasArg(argv, "sarif") || hasArg(argv, trivyConfigExclusionsArg) {
		t.Errorf("older Trivy: %v", argv)
	}
	var calls []string
	out, err := trivyConfigRun(func(_ context.Context, _ string, a []string) ([]byte, error) {
		calls = append(calls, a[1])
		return []byte(trivyMisconfigSARIF), nil
	})(context.Background(), "/tree", argv)
	if err != nil || string(out) != trivyMisconfigSARIF || len(calls) != 1 {
		t.Errorf("out changed or convert ran: calls %v err %v", calls, err)
	}

	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"
	argv = trivyConfigArgs("/tree", plugin.Config{"namespaces": []any{"user"}})
	if strings.Join(argv[:8], " ") != "trivy fs --quiet --scanners misconfig --format json --show-suppressed" ||
		!hasArg(argv, "--check-namespaces") || argv[len(argv)-1] != "/tree" {
		t.Errorf("current Trivy: %v", argv)
	}
}

// A failed scan or conversion is the error, and an unreadable report is not read as nothing
// excluded.
func TestATrivyConfigScanThatCannotBeReadFails(t *testing.T) {
	argv := []string{"trivy", "fs", trivyConfigExclusionsArg, "/tree"}
	boom := errors.New("boom")
	for name, run := range map[string]func(context.Context, string, []string) ([]byte, error){
		"scan": func(context.Context, string, []string) ([]byte, error) { return nil, boom },
		"convert": func(_ context.Context, _ string, a []string) ([]byte, error) {
			if a[1] == "convert" {
				return nil, boom
			}
			return []byte(trivyMisconfigJSON), nil
		},
	} {
		if _, err := trivyConfigRun(run)(context.Background(), "/tree", argv); !errors.Is(err, boom) {
			t.Errorf("%s: err = %v, want Trivy's own", name, err)
		}
	}
	if _, err := withTrivyMisconfigExclusions([]byte(trivyMisconfigSARIF), []byte("not json")); err == nil {
		t.Error("an unreadable report was read as nothing excluded")
	}
	if _, err := withTrivyMisconfigExclusions(nil, []byte(trivyMisconfigJSON)); err == nil {
		t.Error("an empty conversion was accepted")
	}
	if out, err := withTrivyMisconfigExclusions([]byte(trivyMisconfigSARIF), []byte(`{"Results": []}`)); err != nil || string(out) != trivyMisconfigSARIF {
		t.Errorf("out %s err %v, want the SARIF untouched", out, err)
	}
}

// Anything in that section other than an exclusion of a misconfiguration is left out, for the
// reason TestOnlyAnExclusionOfAVulnerabilityIsReadAsOne gives.
func TestOnlyAnExclusionOfAMisconfigurationIsReadAsOne(t *testing.T) {
	for _, entry := range []string{
		`{"Type": "misconfiguration", "Status": "modified", "Finding": {"ID": "DS-0002", "Status": "FAIL"}}`,
		`{"Type": "vulnerability", "Status": "ignored", "Finding": {"ID": "DS-0002", "Status": "FAIL"}}`,
		`{"Type": "misconfiguration", "Status": "ignored", "Finding": {"Status": "FAIL"}}`,
	} {
		doc := `{"Results": [{"Target": "Dockerfile", "ExperimentalModifiedFindings": [` + entry + `]}]}`
		out, err := withTrivyMisconfigExclusions([]byte(trivyMisconfigSARIF), []byte(doc))
		if err != nil || string(out) != trivyMisconfigSARIF {
			t.Errorf("%s: read as an exclusion (%v)", entry, err)
		}
	}
}

func TestTrivyMisconfigLevelAndScore(t *testing.T) {
	for severity, want := range map[string][2]string{
		"CRITICAL": {"error", "9.5"}, "HIGH": {"error", "8.0"}, "MEDIUM": {"warning", "5.5"},
		"LOW": {"note", "2.0"}, "UNKNOWN": {"note", "0.0"}, "": {"none", "0.0"},
	} {
		if got := [2]string{trivyMisconfigLevel(severity), trivyMisconfigScore(severity)}; got != want {
			t.Errorf("%q = %v, want %v", severity, got, want)
		}
	}
}
