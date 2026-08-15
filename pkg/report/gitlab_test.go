package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gitlabData is a run with one finding in every control a GitLab report might carry, so a test can
// assert what each report takes and, just as importantly, what it leaves behind.
func gitlabData() Data {
	res := func(tool, rule string, level sarif.Level, priority, uri string, line int) sarif.Result {
		return sarif.Result{
			Tool: tool, RuleID: rule, Level: level, Priority: priority,
			Message:  rule + " was found",
			Location: sarif.Location{URI: uri, StartLine: line},
		}
	}
	run := engine.Result{
		Controls: map[string]plugin.ControlResult{
			"sast": {Control: "sast", Report: sarif.Report{Tool: "semgrep", Results: []sarif.Result{
				res("semgrep", "go.lang.security.audit", sarif.LevelError, "P1", "cmd/main.go", 42),
			}}},
			"iac": {Control: "iac", Report: sarif.Report{Tool: "trivy-config", Results: []sarif.Result{
				res("trivy-config", "AVD-AWS-0086", sarif.LevelWarning, "P3", "infra/s3.tf", 7),
			}}},
			"secrets": {Control: "secrets", Report: sarif.Report{Tool: "gitleaks", Results: []sarif.Result{
				res("gitleaks", "aws-access-key", sarif.LevelError, "P2", "config/app.env", 3),
			}}},
			"sca": {Control: "sca", Report: sarif.Report{Tool: "trivy-fs", Results: []sarif.Result{
				withPackage(res("trivy-fs", "CVE-2024-56201", sarif.LevelError, "P1", "go.mod", 12),
					&sarif.Package{Name: "jinja2", Version: "2.10", FixedVersion: "3.1.5",
						PURL: "pkg:pypi/jinja2@2.10", Ecosystem: "pip"}),
			}}},
			"licenses": {Control: "licenses", Report: sarif.Report{Tool: "trivy-license", Results: []sarif.Result{
				res("trivy-license", "AGPL-3.0", sarif.LevelWarning, "P4", "go.mod", 1),
			}}},
			// Two images, because one cannot show a per-image value collapsing into a shared one.
			// The third finding has no operating system — a distribution Trivy could not identify
			// — and is the case container scanning has to decline rather than fill in.
			"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
				withImage(withPackage(
					res("trivy", "CVE-2011-3374", sarif.LevelNote, "P4", "registry.example.com/api:1.4", 0),
					&sarif.Package{Name: "apt", Version: "2.2.4", PURL: "pkg:deb/debian/apt@2.2.4"}),
					"registry.example.com/api:1.4", "debian 11.11"),
				withImage(withPackage(
					res("trivy", "CVE-2023-4911", sarif.LevelError, "P1", "registry.example.com/worker:2.0", 0),
					&sarif.Package{Name: "glibc", Version: "2.31", FixedVersion: "2.35",
						PURL: "pkg:deb/ubuntu/glibc@2.31"}),
					"registry.example.com/worker:2.0", "ubuntu 20.04"),
				withImage(withPackage(
					res("trivy", "CVE-2024-0001", sarif.LevelWarning, "P2", "registry.example.com/scratch:1", 0),
					&sarif.Package{Name: "app", Version: "1.0"}),
					"registry.example.com/scratch:1", ""),
			}}},
		},
		Stats: engine.Stats{Duration: 90 * time.Second},
	}
	return Data{
		Release:      saga.Release{Name: "app", Version: "1.0"},
		Run:          run,
		Verdict:      norn.Result{Verdict: norn.Fail},
		Version:      "0.86.0",
		Generated:    time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		Repositories: []RepositoryProvenance{{URL: "https://gitlab.com/acme/app", Revision: "0f1e2d3c4b5a"}},
	}
}

// withPackage attaches a dependency identity, which is what a dependency finding has and a SAST
// finding does not.
func withPackage(r sarif.Result, p *sarif.Package) sarif.Result {
	r.Package = p
	return r
}

func renderGitLab(t *testing.T, format string, d Data) []byte {
	t.Helper()
	r, err := For(format)
	if err != nil {
		t.Fatalf("For(%q): %v", format, err)
	}
	var b bytes.Buffer
	if err := r.Render(&b, d); err != nil {
		t.Fatalf("Render(%q): %v", format, err)
	}
	return b.Bytes()
}

// The schema is what stands behind these formats.
//
// Seeing a document render in the Vulnerability Report needs an Ultimate instance, and GitLab
// refuses a report that does not match its schema rather than showing a partial one — so a field
// Draugr gets wrong costs a user the whole report and tells them nothing about which field.
func TestGitLabReportsMatchTheirSchema(t *testing.T) {
	cases := []struct{ format, schema string }{
		{"gitlab-sast", "sast-report-format.json"},
		{"gitlab-secret-detection", "secret-detection-report-format.json"},
		{"gitlab-dependency-scanning", "dependency-scanning-report-format.json"},
		{"gitlab-container-scanning", "container-scanning-report-format.json"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "gitlab", tc.schema))
			if err != nil {
				t.Fatal(err)
			}
			var schema jsonschema.Schema
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatalf("the vendored schema does not parse: %v", err)
			}
			resolved, err := schema.Resolve(nil)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			var doc any
			if err := json.Unmarshal(renderGitLab(t, tc.format, gitlabData()), &doc); err != nil {
				t.Fatalf("the rendered report is not valid JSON: %v", err)
			}
			if err := resolved.Validate(doc); err != nil {
				t.Errorf("GitLab would refuse this report: %v", err)
			}
		})
	}
}

// The declared version has to be the one the vendored schemas describe, or the test above proves
// something about a document GitLab never sees.
func TestGitLabSchemaVersionMatchesTheVendoredSchemas(t *testing.T) {
	for _, name := range []string{
		"sast-report-format.json",
		"secret-detection-report-format.json",
		"dependency-scanning-report-format.json",
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", "gitlab", name)) // #nosec G304 -- fixture name from the literal list above
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Self struct {
				Version string `json:"version"`
			} `json:"self"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		if s.Self.Version != gitlabSchemaVersion {
			t.Errorf("%s is version %q, gitlabSchemaVersion is %q — refresh both together",
				name, s.Self.Version, gitlabSchemaVersion)
		}
	}
}

func decodeSecurity(t *testing.T, b []byte) glReport {
	t.Helper()
	var doc glReport
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestGitLabSASTCarriesOnlyTheControlsItNames(t *testing.T) {
	// A typed report is a drawer GitLab's deduplication, widget and approval policies look in. A
	// dependency CVE filed as SAST is present and in the wrong one, which is worse than a policy
	// that finds nothing: it finds the wrong thing and reports success.
	doc := decodeSecurity(t, renderGitLab(t, "gitlab-sast", gitlabData()))

	got := map[string]bool{}
	for _, v := range doc.Vulnerabilities {
		got[v.Name] = true
	}
	for _, want := range []string{"go.lang.security.audit", "AVD-AWS-0086"} {
		if !got[want] {
			t.Errorf("gitlab-sast is missing %q — sast and iac both belong in it", want)
		}
	}
	for _, unwanted := range []string{"CVE-2024-56201", "aws-access-key", "AGPL-3.0"} {
		if got[unwanted] {
			t.Errorf("gitlab-sast carries %q, which is not a SAST finding", unwanted)
		}
	}
	if doc.Scan.Type != "sast" {
		t.Errorf("scan.type = %q, want sast", doc.Scan.Type)
	}
	if doc.Version != gitlabSchemaVersion {
		t.Errorf("version = %q, want %q", doc.Version, gitlabSchemaVersion)
	}
}

func TestGitLabSecretDetectionRecordsTheCommit(t *testing.T) {
	doc := decodeSecurity(t, renderGitLab(t, "gitlab-secret-detection", gitlabData()))
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("want the one secret, got %d", len(doc.Vulnerabilities))
	}
	v := doc.Vulnerabilities[0]
	if v.Location.Commit == nil || v.Location.Commit.SHA != "0f1e2d3c4b5a" {
		t.Errorf("location.commit = %+v, want the scanned revision", v.Location.Commit)
	}
}

func TestGitLabSecretDetectionSaysSoWhenItCannotNameTheCommit(t *testing.T) {
	// The schema requires the commit. Writing a placeholder would put a guess in an artifact
	// somebody treats as a record, and omitting the finding would report a clean secret scan.
	d := gitlabData()
	d.Repositories = nil

	r, err := For("gitlab-secret-detection")
	if err != nil {
		t.Fatal(err)
	}
	err = r.Render(&bytes.Buffer{}, d)
	if err == nil {
		t.Fatal("a report that cannot carry a required field rendered anyway")
	}
	if !strings.Contains(err.Error(), "commit") || !strings.Contains(err.Error(), "gitlab-codequality") {
		t.Errorf("the error should name what is missing and what to use instead: %v", err)
	}
}

func TestGitLabSecretDetectionNamesEachRepositorysOwnCommit(t *testing.T) {
	// One repository proves the lookup runs; two prove it does not collapse. A component may hold
	// several, and a fragment may contribute one from another project — attributing every secret to
	// whichever revision was recorded first would point a reviewer at a commit that does not
	// contain it.
	d := gitlabData()
	d.Repositories = []RepositoryProvenance{
		{URL: "https://gitlab.com/acme/app", Revision: "aaaaaaaaaaaa"},
		{URL: "https://gitlab.com/acme/platform", Revision: "bbbbbbbbbbbb"},
	}
	rep := d.Run.Controls["secrets"].Report
	rep.Results[0].Repository = "https://gitlab.com/acme/platform"
	rep.Results = append(rep.Results, sarif.Result{
		Tool: "gitleaks", RuleID: "private-key", Level: sarif.LevelError, Priority: "P1",
		Message: "key", Location: sarif.Location{URI: "deploy/id_rsa", StartLine: 1},
		Repository: "https://gitlab.com/acme/app",
	})
	d.Run.Controls["secrets"] = plugin.ControlResult{Control: "secrets", Report: rep}

	doc := decodeSecurity(t, renderGitLab(t, "gitlab-secret-detection", d))
	got := map[string]string{}
	for _, v := range doc.Vulnerabilities {
		if v.Location.Commit == nil {
			t.Fatalf("%s has no commit", v.Name)
		}
		got[v.Name] = v.Location.Commit.SHA
	}
	if got["aws-access-key"] != "bbbbbbbbbbbb" {
		t.Errorf("aws-access-key points at %q, want the platform repository's revision", got["aws-access-key"])
	}
	if got["private-key"] != "aaaaaaaaaaaa" {
		t.Errorf("private-key points at %q, want the app repository's revision", got["private-key"])
	}
}

func TestGitLabCodeQualityDescriptionIsOneLine(t *testing.T) {
	// Several scanners relay a paragraph, and the widget renders it into a table cell.
	cases := []struct {
		name string
		res  sarif.Result
		want string
	}{
		{
			"a paragraph is trimmed to its first line",
			sarif.Result{RuleID: "CVE-1", Level: sarif.LevelError,
				Message: "Vulnerability CVE-1\nSeverity: HIGH\nPackage: libssl"},
			"HIGH: Vulnerability CVE-1",
		},
		{
			"no message falls back to the rule",
			sarif.Result{RuleID: "AVD-AWS-0086", Level: sarif.LevelWarning},
			"MEDIUM: AVD-AWS-0086",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitlabCodeQualityDescription(tc.res); got != tc.want {
				t.Errorf("description = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGitLabCodeQualityCarriesEveryControl(t *testing.T) {
	// The only GitLab surface that works on a Free project, and the reason no finding is invisible
	// there: the typed security reports are subsets, and this one is the whole run.
	var out []glCodeQuality
	if err := json.Unmarshal(renderGitLab(t, "gitlab-codequality", gitlabData()), &out); err != nil {
		t.Fatal(err)
	}
	// Derived from the fixture rather than written down: this report's contract is that it
	// carries everything, so the number it should equal is however many findings the run had.
	if want := activeFindings(gitlabData()); len(out) != want {
		t.Fatalf("want every finding in the run (%d), got %d", want, len(out))
	}
	got := map[string]bool{}
	for _, e := range out {
		got[e.CheckName] = true
		if e.Fingerprint == "" {
			t.Errorf("%s has no fingerprint, so GitLab cannot tell it apart across runs", e.CheckName)
		}
		if e.Location.Lines.Begin < 1 {
			t.Errorf("%s reports line %d; the widget needs a line to anchor to",
				e.CheckName, e.Location.Lines.Begin)
		}
	}
	// licenses and threats have no honest GitLab security type, so this report is where they land.
	if !got["AGPL-3.0"] {
		t.Error("a licence finding reaches no typed report, so it has to reach this one")
	}
}

func TestGitLabCodeQualityRanksByPriority(t *testing.T) {
	// Priority, not severity — the opposite of the security reports, because this widget has no
	// policy engine behind it and is read as an ordered list of what to look at.
	cases := []struct{ priority, want string }{
		{"P1", "blocker"}, {"P2", "critical"}, {"P3", "major"}, {"P4", "minor"}, {"", "info"},
	}
	for _, tc := range cases {
		if got := gitlabCodeQualitySeverity(tc.priority); got != tc.want {
			t.Errorf("priority %q -> %q, want %q", tc.priority, got, tc.want)
		}
	}
}

func TestGitLabSecurityReportCarriesTheFlawsSeverity(t *testing.T) {
	// GitLab's merge-request approval policies gate on this field. A priority has already folded
	// in the component's exposure and criticality, so putting one here would have those policies
	// apply that context a second time.
	doc := decodeSecurity(t, renderGitLab(t, "gitlab-sast", gitlabData()))
	byName := map[string]string{}
	for _, v := range doc.Vulnerabilities {
		byName[v.Name] = v.Severity
	}
	// A P1 whose flaw is error-level with no CVSS score is a "high", not a "critical". The band
	// travelling here is the flaw's; the P1 came from what the component is exposed to, and putting
	// it in this field would hand GitLab's policies that context to apply again.
	if byName["go.lang.security.audit"] != "High" {
		t.Errorf("an error-level P1 rendered as %q, want the flaw's own band",
			byName["go.lang.security.audit"])
	}
	for _, tc := range []struct {
		in   sarif.Severity
		want string
	}{
		{sarif.SeverityCritical, "Critical"}, {sarif.SeverityHigh, "High"},
		{sarif.SeverityMedium, "Medium"}, {sarif.SeverityLow, "Low"}, {"", "Unknown"},
	} {
		if got := gitlabSeverity(tc.in); got != tc.want {
			t.Errorf("gitlabSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGitLabReportsOmitSuppressedFindings(t *testing.T) {
	// GitLab has no notion of a finding somebody already accepted: it would show one as open and
	// wait to be dismissed, asking again for a decision the Saga records with its reason and its
	// author. The finding stays in Draugr's own report, marked.
	d := gitlabData()
	rep := d.Run.Controls["sast"].Report
	rep.Results[0].Suppression = &sarif.Suppression{
		Kind: "external", Justification: "reviewed 2026-08-01", AcceptedBy: "security",
	}
	d.Run.Controls["sast"] = plugin.ControlResult{Control: "sast", Report: rep}

	doc := decodeSecurity(t, renderGitLab(t, "gitlab-sast", d))
	for _, v := range doc.Vulnerabilities {
		if v.Name == "go.lang.security.audit" {
			t.Error("a suppressed finding was filed as an open GitLab vulnerability")
		}
	}
	var cq []glCodeQuality
	if err := json.Unmarshal(renderGitLab(t, "gitlab-codequality", d), &cq); err != nil {
		t.Fatal(err)
	}
	if want := activeFindings(d); len(cq) != want {
		t.Errorf("code quality carried %d findings, want the %d that are not suppressed",
			len(cq), want)
	}
}

func TestGitLabScanStatusSaysWhenAControlCouldNotRun(t *testing.T) {
	// A control whose scanner never ran found nothing because it looked at nothing. A report that
	// called that success would be a clean bill of health for a scan that did not happen.
	d := gitlabData()
	if got := gitlabScanStatus(d); got != "success" {
		t.Errorf("a complete run reported %q", got)
	}
	d.Run.ScanErrors = map[string][]string{"sast": {"semgrep: executable file not found in $PATH"}}
	if got := gitlabScanStatus(d); got != "failure" {
		t.Errorf("a run with a scanner that could not start reported %q, want failure", got)
	}
	doc := decodeSecurity(t, renderGitLab(t, "gitlab-sast", d))
	if doc.Scan.Status != "failure" {
		t.Errorf("scan.status = %q", doc.Scan.Status)
	}
}

func TestGitLabIdentifierNamesACVEAsOne(t *testing.T) {
	// GitLab correlates its own findings and everyone else's through the identifier. A CVE
	// reported under a private type is a second copy of a vulnerability the project already has.
	cases := []struct {
		rule, tool, wantType string
	}{
		{"CVE-2024-56201", "trivy-fs", "cve"},
		{"GHSA-xxxx-yyyy-zzzz", "trivy-fs", "ghsa"},
		{"go.lang.security.audit", "semgrep", "semgrep"},
		{"some-rule", "", "draugr"},
		// Not a CVE, however much it looks like one.
		{"CVE-24-1", "gitleaks", "gitleaks"},
	}
	for _, tc := range cases {
		got := gitlabIdentifier(sarif.Result{RuleID: tc.rule, Tool: tc.tool}, "")
		if got.Type != tc.wantType {
			t.Errorf("identifier type for %q (%s) = %q, want %q", tc.rule, tc.tool, got.Type, tc.wantType)
		}
		if got.Value != tc.rule || got.Name != tc.rule {
			t.Errorf("identifier for %q = %+v", tc.rule, got)
		}
	}
}

func TestGitLabReportsAreDocumentsNotStreams(t *testing.T) {
	// A runner reads these from a path. Printing several thousand lines of JSON because somebody
	// typed a plausible-looking flag is not the answer, and the error says where the format did go.
	for _, f := range []string{"gitlab-sast", "gitlab-secret-detection", "gitlab-codequality"} {
		err := StreamFormat(f)
		if err == nil {
			t.Errorf("--format %s was accepted for stdout", f)
			continue
		}
		if !strings.Contains(err.Error(), "--report") {
			t.Errorf("the error for %s should name --report: %v", f, err)
		}
	}
}

func TestGitLabFilenamesFollowGitLabsConvention(t *testing.T) {
	// A .gitlab-ci.yml written from GitLab's own documentation names these files. A file written
	// under a different name is one the `artifacts: reports:` glob does not find, and a runner
	// that finds no artifact warns and carries on.
	want := map[string]string{
		"gitlab-sast":             "gl-sast-report.json",
		"gitlab-secret-detection": "gl-secret-detection-report.json",
		"gitlab-codequality":      "gl-code-quality-report.json",
	}
	for format, filename := range want {
		if got := Filename(format); got != filename {
			t.Errorf("Filename(%q) = %q, want %q", format, got, filename)
		}
	}
}

func TestGitLabScanTimesBracketTheRun(t *testing.T) {
	doc := decodeSecurity(t, renderGitLab(t, "gitlab-sast", gitlabData()))
	if doc.Scan.EndTime != "2026-08-13T12:00:00" {
		t.Errorf("end_time = %q", doc.Scan.EndTime)
	}
	// The run took 90 seconds, and a report claiming an instantaneous scan is one nobody can
	// reconcile with the pipeline's own timings.
	if doc.Scan.StartTime != "2026-08-13T11:58:30" {
		t.Errorf("start_time = %q, want the end minus the run's duration", doc.Scan.StartTime)
	}
}

// dependency_scanning requires a package on every finding, so a finding without one cannot be in
// it — and quietly including it would have GitLab reject the whole document rather than the row.
func TestGitLabDependencyScanningNeedsAPackage(t *testing.T) {
	d := gitlabData()
	rep := d.Run.Controls["sca"].Report
	// A second sca finding with no package: the shape a scanner produces when it reports something
	// about a manifest rather than about a dependency in it.
	rep.Results = append(rep.Results, sarif.Result{
		Tool: "trivy-fs", RuleID: "NO-PACKAGE", Level: sarif.LevelWarning, Priority: "P3",
		Message: "about the file, not a package", Location: sarif.Location{URI: "go.mod"},
	})
	d.Run.Controls["sca"] = plugin.ControlResult{Control: "sca", Report: rep}

	doc := decodeSecurity(t, renderGitLab(t, "gitlab-dependency-scanning", d))
	for _, v := range doc.Vulnerabilities {
		if v.Name == "NO-PACKAGE" {
			t.Error("a finding with no package reached a report whose schema requires one")
		}
		if v.Location.Dependency == nil || v.Location.Dependency.Package.Name == "" {
			t.Errorf("%s has no dependency, which the schema requires", v.Name)
		}
		// A line number in a manifest points at wherever the scanner happened to look, not at the
		// package — GitLab renders it as a position, so it is left out.
		if v.Location.StartLine != 0 {
			t.Errorf("%s carries start_line %d", v.Name, v.Location.StartLine)
		}
	}
}

func TestGitLabDependencyScanningCarriesTheVersion(t *testing.T) {
	doc := decodeSecurity(t, renderGitLab(t, "gitlab-dependency-scanning", gitlabData()))
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("want the one sca finding, got %d", len(doc.Vulnerabilities))
	}
	dep := doc.Vulnerabilities[0].Location.Dependency
	if dep.Package.Name != "jinja2" || dep.Version != "2.10" {
		t.Errorf("dependency = %+v, want jinja2 2.10", dep)
	}
	if doc.Vulnerabilities[0].Location.File != "go.mod" {
		t.Errorf("file = %q, want the manifest", doc.Vulnerabilities[0].Location.File)
	}
}

// withImage attaches the container identity a container-scanning finding has to carry.
func withImage(r sarif.Result, image, operatingSystem string) sarif.Result {
	r.Image, r.OperatingSystem = image, operatingSystem
	return r
}

// TestGitLabContainerScanningCarriesEachImage is the assertion the schema test cannot make: a
// document with no findings satisfies the schema perfectly.
//
// Two images, because that is where a per-image value collapsing into a shared one becomes
// visible — with one image, a correct implementation and one that resolves the image afterwards
// produce the same document.
func TestGitLabContainerScanningCarriesEachImage(t *testing.T) {
	var doc struct {
		Vulnerabilities []struct {
			Name     string `json:"name"`
			Location struct {
				Image           string `json:"image"`
				OperatingSystem string `json:"operating_system"`
				Dependency      struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
					Version string `json:"version"`
				} `json:"dependency"`
			} `json:"location"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(renderGitLab(t, "gitlab-container-scanning", gitlabData()), &doc); err != nil {
		t.Fatal(err)
	}

	byImage := map[string]string{}
	for _, v := range doc.Vulnerabilities {
		byImage[v.Location.Image] = v.Location.OperatingSystem
		if v.Location.Dependency.Package.Name == "" {
			t.Errorf("%s: the schema requires a package and this row has none", v.Name)
		}
	}
	if len(byImage) != 2 {
		t.Fatalf("want findings from two distinct images, got %d: %v", len(byImage), byImage)
	}
	if got := byImage["registry.example.com/api:1.4"]; got != "debian 11.11" {
		t.Errorf("api image reported operating system %q", got)
	}
	if got := byImage["registry.example.com/worker:2.0"]; got != "ubuntu 20.04" {
		t.Errorf("worker image reported operating system %q", got)
	}
}

// TestGitLabContainerScanningOmitsWhatItCannotFill covers the finding with no identifiable
// distribution.
//
// `operating_system` is required with a minimum length, so the only alternatives are to leave the
// finding out or to invent a value. An invented one is a claim GitLab renders, attributes to
// Draugr and applies a policy to; the finding still reaches a reviewer through
// `gitlab-codequality`, which carries every control.
func TestGitLabContainerScanningOmitsWhatItCannotFill(t *testing.T) {
	out := string(renderGitLab(t, "gitlab-container-scanning", gitlabData()))
	if strings.Contains(out, "CVE-2024-0001") {
		t.Error("a finding with no operating system was included, so the value was invented")
	}
	if strings.Contains(out, "scratch") {
		t.Error("the image with no identifiable distribution reached the report")
	}
	// It is not lost — the complete stream still has it.
	quality := string(renderGitLab(t, "gitlab-codequality", gitlabData()))
	if !strings.Contains(quality, "CVE-2024-0001") {
		t.Error("the omitted finding should still reach the reviewer through Code Quality")
	}
}

// activeFindings counts what a report carrying everything should carry: every finding of every
// control, less the suppressed ones, which are reported but never filed as open.
func activeFindings(d Data) int {
	n := 0
	for _, c := range d.Run.Controls {
		for _, r := range c.Report.Results {
			if r.Suppression == nil {
				n++
			}
		}
	}
	return n
}
