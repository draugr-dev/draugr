package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// downloadedModuleTree is a configuration calling one registry module three ways: twice directly and
// once through a local module. Trivy reports the module's finding at the module's own path for each.
func downloadedModuleTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		"main.tf": `module "wrap" {
  source = "./modules/wrap"
}

module "direct_one" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"
}

module "direct_two" {
  source = "terraform-aws-modules/s3-bucket/aws"
}
`,
		"modules/wrap/main.tf": `module "inner" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"
}
`,
		"modules/local/main.tf": "resource \"aws_s3_bucket\" \"b\" {}\n",
	})
}

// trivyJSONMisconfig is one failed check of Trivy's JSON report, behind the module calls given as
// "file:start-end" innermost first.
func trivyJSONMisconfig(id string, line int, calls ...string) string {
	var occ []string
	for _, c := range calls {
		file, lines, _ := strings.Cut(c, ":")
		var start, end int
		_, _ = fmt.Sscanf(lines, "%d-%d", &start, &end)
		occ = append(occ, fmt.Sprintf(`{"Resource":"module.x","Filename":%q,"Location":{"StartLine":%d,"EndLine":%d}}`, file, start, end))
	}
	return fmt.Sprintf(`{"ID":%q,"Status":"FAIL","CauseMetadata":{"StartLine":%d,"EndLine":%d,"Occurrences":[%s]}}`,
		id, line, line+9, strings.Join(occ, ","))
}

// trivySARIFAt is one result of the SARIF trivy convert writes, at uri and line.
func trivySARIFAt(id, uri string, line int) string {
	return fmt.Sprintf(`{"ruleId":%q,"message":{"text":"Artifact: %s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q,"uriBaseId":"ROOTPATH"},"region":{"startLine":%d,"startColumn":1,"endLine":%d,"endColumn":1}},"message":{"text":%q}}]}`,
		id, uri, uri, line, line+9, uri)
}

// A finding at a path the checkout does not hold moves to the first module call in its chain that
// the checkout does hold, with the module's source, version, file and line, and each call keeps its
// own finding. A finding in a module the checkout holds, and one with no call behind it, stay.
func TestDownloadedModuleFindingsMoveToTheCallingBlock(t *testing.T) {
	dir := downloadedModuleTree(t)
	const mod = "terraform-aws-modules/s3-bucket/aws/main.tf"
	report := `{"Results":[
	  {"Target":"` + mod + `","Misconfigurations":[` +
		trivyJSONMisconfig("AWS-0089", 25, "main.tf:5-8") + "," +
		trivyJSONMisconfig("AWS-0089", 80, "main.tf:5-8") + "," +
		trivyJSONMisconfig("AWS-0089", 25, "main.tf:10-12") + "," +
		trivyJSONMisconfig("AWS-0089", 25, mod+":40-44", "modules/wrap/main.tf:1-4", "main.tf:1-3") + "," +
		trivyJSONMisconfig("AWS-0090", 60) + "," +
		`{"ID":"AWS-0091","Status":"PASS","CauseMetadata":{"StartLine":70,"Occurrences":[{"Filename":"main.tf","Location":{"StartLine":5,"EndLine":8}}]}}` + `]},
	  {"Target":"modules/local/main.tf","Misconfigurations":[` + trivyJSONMisconfig("AWS-0086", 1, "main.tf:1-3") + `]}
	]}`
	calls, err := trivyDownloadedModuleCalls([]byte(report), dir)
	if err != nil {
		t.Fatal(err)
	}
	sarifIn := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[` + strings.Join([]string{
		trivySARIFAt("AWS-0089", mod, 25), trivySARIFAt("AWS-0089", mod, 80), trivySARIFAt("AWS-0089", mod, 25), trivySARIFAt("AWS-0089", mod, 25),
		trivySARIFAt("AWS-0090", mod, 60), trivySARIFAt("AWS-0086", "modules/local/main.tf", 1),
	}, ",") + `]}]}`
	out, err := relocateDownloadedModuleFindings([]byte(sarifIn), calls)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rep.Results {
		line := fmt.Sprintf("%s %s:%d", r.RuleID, r.Location.URI, r.Location.StartLine)
		if m := r.Module; m != nil {
			line += fmt.Sprintf(" in %s %s %s:%d", m.Source, m.Version, m.File, m.Line)
		}
		got = append(got, line)
	}
	want := []string{
		"AWS-0089 main.tf:5 in terraform-aws-modules/s3-bucket/aws 4.1.2 main.tf:25",
		// A second setting in the same module, through the same call: the same line in the
		// checkout, and a finding of its own.
		"AWS-0089 main.tf:5 in terraform-aws-modules/s3-bucket/aws 4.1.2 main.tf:80",
		"AWS-0089 main.tf:10 in terraform-aws-modules/s3-bucket/aws  main.tf:25",
		// The innermost call the checkout holds, the block that names the module, not the root's.
		"AWS-0089 modules/wrap/main.tf:1 in terraform-aws-modules/s3-bucket/aws 4.1.2 main.tf:25",
		// No call behind it: nothing to move it to, so it stays where Trivy put it.
		"AWS-0090 " + mod + ":60",
		// A module the checkout holds is the reader's own file.
		"AWS-0086 modules/local/main.tf:1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("results\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	fps := map[string]bool{}
	for _, r := range rep.Results {
		fps[r.Fingerprint()] = true
	}
	if len(fps) != len(rep.Results) {
		t.Errorf("%d results share %d fingerprints, so some would be merged", len(rep.Results), len(fps))
	}
}

func TestRelocateDownloadedModuleFindingsLeavesWhatItCannotPlace(t *testing.T) {
	in := []byte(`{"runs":[{"results":[{"ruleId":"X"}]}]}`)
	if out, err := relocateDownloadedModuleFindings(in, nil); err != nil || string(out) != string(in) {
		t.Errorf("nothing to move changed the SARIF: %s, %v", out, err)
	}
	out, err := relocateDownloadedModuleFindings(in, map[string][]trivyModuleCall{"k": {{file: "main.tf"}}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil || strings.Contains(string(out), "module") {
		t.Errorf("a result with no location was given a module: %s, %v", out, err)
	}
	if _, err := relocateDownloadedModuleFindings([]byte("{"), map[string][]trivyModuleCall{"k": nil}); err == nil {
		t.Error("unreadable SARIF was accepted")
	}
	if _, err := trivyDownloadedModuleCalls([]byte("{"), t.TempDir()); err == nil {
		t.Error("an unreadable report was accepted")
	}
	if m := moduleBlockSource("/nonexistent/main.tf", 1, 3); m != (sarif.Module{}) {
		t.Errorf("an unreadable file gave %+v", m)
	}
}
