package scanners

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importSemgrep reads file as semgrep-json into control, in the component of repos.
func importSemgrep(t *testing.T, file, control string, repos ...plugin.RepositoryTarget) sarif.Report {
	t.Helper()
	rep, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: file,
		Format: saga.ImportFormatSemgrepJSON, Control: control, Repositories: repos}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// semgrepFindingOf is the finding of rule at uri among results, failing the test where there is not
// exactly one.
func semgrepFindingOf(t *testing.T, results []sarif.Result, rule, uri string) sarif.Result {
	t.Helper()
	var found []sarif.Result
	for _, r := range results {
		if r.RuleID == rule && r.Location.URI == uri {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s at %s: %d findings in %+v", rule, uri, len(found), results)
	}
	return found[0]
}

// The file Semgrep 1.182.1 wrote of a project with two code rules and a Supply Chain rule, imported
// into sast, holds the two code findings, each at its file and line under its rule, with its CWE,
// rated from its rule's impact and likelihood as Draugr's own Semgrep run rates it, and under the
// name Semgrep's SARIF gives the tool, so a finding Draugr's run also reports merges with it.
func TestSemgrepsCodeResultsReadIntoSAST(t *testing.T) {
	rep := importSemgrep(t, veracodeFixture("semgrep-scan.json"), "sast")
	if len(rep.Results) != 2 {
		t.Fatalf("%d findings, want 2: %+v", len(rep.Results), rep.Results)
	}
	shell := semgrepFindingOf(t, rep.Results, "shell-true-subprocess", "api/app.py")
	if shell.Tool != "Semgrep OSS" || shell.Location.StartLine != 5 || !slices.Equal(shell.CWE, []string{"CWE-78"}) ||
		shell.Severity("") != sarif.SeverityHigh || shell.Level != sarif.LevelError || shell.Package != nil {
		t.Errorf("shell = %+v", shell)
	}
	if !strings.HasPrefix(shell.Message, "subprocess runs its command through a shell") {
		t.Errorf("message = %q", shell.Message)
	}
	// Impact medium and likelihood low, from a rule of low confidence in the audit subcategory,
	// lowered once.
	eval := semgrepFindingOf(t, rep.Results, "eval-call", "web/app.js")
	if eval.Location.StartLine != 9 || !slices.Equal(eval.CWE, []string{"CWE-95"}) || eval.Severity("") != sarif.SeverityLow ||
		!strings.Contains(eval.Rating.Detail, "subcategory audit") {
		t.Errorf("eval = %+v, rating %+v", eval, eval.Rating)
	}
	if got := provenanceField(rep, "severity"); got != "Semgrep's impact and likelihood" {
		t.Errorf("severity source = %q", got)
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v", rep.Inputs)
	}
}

// The same file imported into sca holds its three Supply Chain findings, one in each lockfile: the
// advisory under its CVE, so KEV and EPSS reach it, in the package at the version installed, with the
// package URL of its ecosystem and the fixed version the rule names for that package, rated by the
// advisory's severity. The rule checks the version alone, so the detail says nothing about where the
// code uses it.
func TestSemgrepsSupplyChainResultsReadIntoSCA(t *testing.T) {
	rep := importSemgrep(t, veracodeFixture("semgrep-scan.json"), "sca")
	if len(rep.Results) != 3 {
		t.Fatalf("%d findings, want 3: %+v", len(rep.Results), rep.Results)
	}
	for _, c := range []struct {
		lockfile, name, version, ecosystem, purl string
		line                                     int
		detail                                   string
	}{
		{"api/requirements.txt", "grpcio", "1.47.0", "pypi", "pkg:pypi/grpcio@1.47.0", 1, ""},
		{"worker/Gemfile.lock", "grpc", "1.47.0", "gem", "pkg:gem/grpc@1.47.0", 7, ""},
		{"jvm/gradle.lockfile", "io.grpc:grpc-protobuf", "1.51.0", "maven", "pkg:maven/io.grpc/grpc-protobuf@1.51.0", 4, ""},
	} {
		r := semgrepFindingOf(t, rep.Results, "CVE-2023-1428", c.lockfile)
		p := r.Package
		if p == nil || p.Name != c.name || p.Version != c.version || p.Ecosystem != c.ecosystem || p.PURL != c.purl ||
			p.FixedVersion != "1.53.0" {
			t.Errorf("%s: package %+v", c.lockfile, p)
			continue
		}
		if r.Tool != "Semgrep OSS" || r.Location.StartLine != c.line || r.Severity("") != sarif.SeverityHigh ||
			!slices.Equal(r.CWE, []string{"CWE-617"}) || len(r.Aliases) != 0 {
			t.Errorf("%s: finding %+v", c.lockfile, r)
		}
		if r.Message != c.name+" "+c.version+" → 1.53.0" {
			t.Errorf("%s: message %q", c.lockfile, r.Message)
		}
		if !strings.HasPrefix(r.Detail, "grpc versions before 1.53.0, before 3.2.0, grpcio versions") ||
			strings.Contains(r.Detail, "Semgrep found") || strings.Contains(r.Detail, "Semgrep looked") ||
			strings.Contains(r.Detail, "transitive") {
			t.Errorf("%s: detail %q", c.lockfile, r.Detail)
		}
	}
	if got := provenanceField(rep, "severity"); got != "Semgrep's Supply Chain severity" {
		t.Errorf("severity source = %q", got)
	}
	if rule := rep.Rules["CVE-2023-1428"]; !strings.HasPrefix(rule.HelpURI, "https://semgrep.dev/orgs/-/supply-chain/advisories") {
		t.Errorf("rule = %+v", rule)
	}
}

// semgrepFileOf is a hand-written file with results, run by engine.
func semgrepFileOf(engine string, results ...string) string {
	return fmt.Sprintf(`{"version":"1.182.1","results":[%s],"errors":[],"paths":{"scanned":[]},"engine_requested":%q}`,
		strings.Join(results, ","), engine)
}

// semgrepCodeOf is a hand-written code result of rule at path:line, of severity, with metadata.
func semgrepCodeOf(rule, path string, line int, severity, metadata string) string {
	return fmt.Sprintf(`{"check_id":%q,"path":%q,"start":{"line":%d,"col":1},"end":{"line":%d,"col":9},`+
		`"extra":{"message":"m","severity":%q,"metadata":%s}}`, rule, path, line, line+1, severity, metadata)
}

// semgrepSCAOf is a hand-written Supply Chain result of rule at path:line, about pkg at version in
// lockfile, with metadata and the reachability fields.
func semgrepSCAOf(rule, path string, line int, eco, pkg, version, transitivity, lockfile, metadata string, reachabilityRule, reachable bool) string {
	return fmt.Sprintf(`{"check_id":%q,"path":%q,"start":{"line":%d},"end":{"line":%d},`+
		`"extra":{"message":"An advisory.","severity":"ERROR","metadata":%s,"sca_info":{"reachability_rule":%t,`+
		`"sca_finding_schema":20220913,"reachable":%t,"dependency_match":{"dependency_pattern":{"ecosystem":%q,`+
		`"package":%q,"semver_range":"< 9"},"found_dependency":{"package":%q,"version":%q,"ecosystem":%q,`+
		`"allowed_hashes":{},"transitivity":%q,"lockfile_path":%q,"line_number":3},"lockfile":%q}}}}`,
		rule, path, line, line, metadata, reachabilityRule, reachable, eco, pkg, pkg, version, eco, transitivity,
		lockfile, lockfile)
}

// Shapes the recorded file lacks, each hand-written: a rule that looks for the vulnerable code
// reports a match at each place it finds it, which is one finding naming each place; such a rule that
// found none says so; a dependency both direct and transitive is one finding; the CVE in the rule's
// cve key names the finding, and its GHSA id is an alias; fixes for another package or an older release
// line are left out, and a fix only for an older line stays in the detail; a rule with no advisory
// severity is rated by its own; and a Go module takes Go's package URL.
func TestSemgrepSupplyChainShapesTheRecordedFileLacks(t *testing.T) {
	const lodash = `{"cve":"CVE-2021-23337","ghsa":"GHSA-35jh-r3h4-6jhm","sca-severity":"MODERATE",` +
		`"sca-fix-versions":[{"lodash":"4.17.21"},{"lodash":"3.10.2"},{"lodash.template":"4.5.0"}],"cwe":"CWE-94: Code Injection"}`
	file := semgrepFileOf("PRO",
		semgrepSCAOf("ssc-1", "web/app.js", 4, "npm", "lodash", "4.17.4", "direct", "web/package-lock.json", lodash, true, true),
		semgrepSCAOf("ssc-1", "web/app.js", 9, "npm", "lodash", "4.17.4", "transitive", "web/package-lock.json", lodash, true, true),
		semgrepSCAOf("ssc-1", "web/app.js", 9, "npm", "lodash", "4.17.4", "direct", "web/package-lock.json", lodash, true, true),
		semgrepSCAOf("ssc-1", "api/package-lock.json", 3, "npm", "lodash", "4.17.4", "unknown", "api/package-lock.json", lodash, true, false),
		semgrepSCAOf("ssc-1", "old/package-lock.json", 3, "npm", "lodash", "4.17.21", "direct", "old/package-lock.json", lodash, false, false),
		semgrepSCAOf("ssc-2", "go.mod", 6, "gomod", "github.com/gin-gonic/gin", "1.6.3", "transitive", "go.mod",
			`{"sca-vuln-database-identifier":"GHSA-2c4m-59x9-fr2g","sca-fix-versions":[{"github.com/gin-gonic/gin":"1.9.1"}]}`, false, false),
		semgrepSCAOf("ssc-3", "Cargo.lock", 2, "cargo", "smallvec", "1.0.0", "direct", "Cargo.lock",
			`{"sca-vuln-database-identifier":"RUSTSEC-2021-0003"}`, false, false),
		semgrepCodeOf("eval-call", "web/app.js", 9, "WARNING", `{}`),
	)
	rep := importSemgrep(t, writeFile(t, file), "sca")
	if len(rep.Results) != 5 {
		t.Fatalf("%d findings, want 5: %+v", len(rep.Results), rep.Results)
	}
	web := semgrepFindingOf(t, rep.Results, "CVE-2021-23337", "web/package-lock.json")
	if web.Tool != "Semgrep PRO" || !slices.Equal(web.Aliases, []string{"GHSA-35jh-r3h4-6jhm"}) ||
		web.Package.FixedVersion != "4.17.21" || web.Package.PURL != "pkg:npm/lodash@4.17.4" || web.Location.StartLine != 3 ||
		web.Severity("") != sarif.SeverityMedium || !slices.Equal(web.CWE, []string{"CWE-94"}) {
		t.Errorf("web = %+v, package %+v", web, web.Package)
	}
	if !strings.HasSuffix(web.Detail, "An advisory. Semgrep found the vulnerable code used at web/app.js:4, web/app.js:9. "+
		"A direct dependency, and a transitive one.") {
		t.Errorf("web detail = %q", web.Detail)
	}
	if api := semgrepFindingOf(t, rep.Results, "CVE-2021-23337", "api/package-lock.json"); api.Detail !=
		"An advisory. Semgrep looked for the vulnerable code and found no use of it." {
		t.Errorf("api detail = %q", api.Detail)
	}
	old := semgrepFindingOf(t, rep.Results, "CVE-2021-23337", "old/package-lock.json")
	if old.Package.FixedVersion != "" || old.Message != "lodash 4.17.21, no fix available" ||
		old.Detail != "An advisory. Semgrep names 4.17.21, 3.10.2 as fixed, none above the installed version." {
		t.Errorf("old = %+v", old)
	}
	gin := semgrepFindingOf(t, rep.Results, "GHSA-2c4m-59x9-fr2g", "go.mod")
	if gin.Package.PURL != "pkg:golang/github.com/gin-gonic/gin@v1.6.3" || gin.Package.FixedVersion != "1.9.1" ||
		gin.Severity("") != sarif.SeverityHigh || !strings.HasSuffix(gin.Detail, "A transitive dependency.") {
		t.Errorf("gin = %+v, package %+v", gin, gin.Package)
	}
	// An id that is neither a CVE nor a GHSA id leaves the finding under Semgrep's rule.
	if rust := semgrepFindingOf(t, rep.Results, "ssc-3", "Cargo.lock"); rust.Package.PURL != "pkg:cargo/smallvec@1.0.0" ||
		rust.Package.FixedVersion != "" {
		t.Errorf("rust = %+v", rust.Package)
	}
}

// A code rule that states no impact and likelihood is rated by its severity, in Semgrep's newer words
// or its older ones; Secrets results are read into neither control; and a file a rule timed out on is
// a file no rule read in full, as for Draugr's own Semgrep run.
func TestSemgrepCodeShapesTheRecordedFileLacks(t *testing.T) {
	file := `{"version":"1.182.1","results":[` + strings.Join([]string{
		semgrepCodeOf("crit", "a.py", 1, "CRITICAL", `{"cwe":["CWE-89: SQL Injection","CWE-89: again","not a cwe"]}`),
		semgrepCodeOf("info", "b.py", 2, "INFO", `{"cwe":"CWE-20: Improper Input Validation"}`),
		semgrepCodeOf("warn", "c.py", 3, "WARNING", `"not an object"`),
		semgrepCodeOf("aws-key", "d.py", 4, "ERROR", `{"product":"secrets"}`),
	}, ",") + `],"errors":[{"type":"Timeout","rule_id":"slow-rule","path":"big.py"}],"paths":{"scanned":[]}}`
	rep := importSemgrep(t, writeFile(t, file), "sast")
	if len(rep.Results) != 3 {
		t.Fatalf("%d findings, want 3: %+v", len(rep.Results), rep.Results)
	}
	for _, c := range []struct {
		rule, uri string
		severity  sarif.Severity
		cwe       []string
	}{
		{"crit", "a.py", sarif.SeverityCritical, []string{"CWE-89"}},
		{"info", "b.py", sarif.SeverityLow, []string{"CWE-20"}},
		{"warn", "c.py", sarif.SeverityMedium, nil},
	} {
		r := semgrepFindingOf(t, rep.Results, c.rule, c.uri)
		if r.Severity("") != c.severity || !slices.Equal(r.CWE, c.cwe) || r.Location.EndLine != r.Location.StartLine+1 {
			t.Errorf("%s = %+v", c.rule, r)
		}
	}
	if got := provenanceField(rep, "severity"); got != "Semgrep's severity" {
		t.Errorf("severity source = %q", got)
	}
	if len(rep.Inputs) != 1 || rep.Inputs[0].Path != "big.py" || rep.Inputs[0].Scanner != plugin.ImportScanner ||
		!strings.Contains(rep.Inputs[0].Unread, `"slow-rule"`) {
		t.Errorf("inputs = %+v", rep.Inputs)
	}
	if sca := importSemgrep(t, writeFile(t, file), "sca"); len(sca.Results) != 0 || len(sca.Inputs) != 0 {
		t.Errorf("sca = %+v", sca)
	}
}

// One file is read twice, once into each control, so its cache entry and its doctor row carry the
// control.
func TestASemgrepFileIsCachedPerControl(t *testing.T) {
	sast := plugin.FileTarget{Path: "semgrep.json", Digest: "d", Format: saga.ImportFormatSemgrepJSON, Control: "sast"}
	sca := sast
	sca.Control = "sca"
	if sast.CacheDetail() == sca.CacheDetail() || !strings.Contains(sca.CacheDetail(), " control=sca") {
		t.Errorf("sast %q, sca %q", sast.CacheDetail(), sca.CacheDetail())
	}
	got, err := DescribeFile([]byte(semgrepFileOf("OSS", semgrepCodeOf("r", "a.py", 1, "ERROR", `{}`))), sast)
	if err != nil || got != "Semgrep JSON, 1 finding" {
		t.Errorf("describe: %q, %v", got, err)
	}
}

// A file that is not the JSON Semgrep writes, or whose result lacks what places and names it, or that
// rates one outside Semgrep's severities, is refused with an error naming what, rather than read as a
// scan that found less.
func TestASemgrepFileOfTheWrongShapeIsRefused(t *testing.T) {
	sca := func(metadata string) string {
		return semgrepFileOf("OSS", semgrepSCAOf("ssc", "go.mod", 1, "gomod", "x", "1.0.0", "direct", "go.mod", metadata, false, false))
	}
	for name, c := range map[string]struct{ body, control, want string }{
		"a list":           {`[]`, "sast", "not Semgrep's JSON. Write it with semgrep ci --json-output=<file>"},
		"not JSON":         {`{`, "sast", "not Semgrep's JSON"},
		"no paths":         {`{"results":[],"errors":[]}`, "sast", "not Semgrep's JSON"},
		"SARIF":            {`{"version":"2.1.0","runs":[]}`, "sast", "not Semgrep's JSON"},
		"results a string": {`{"results":"x","errors":[],"paths":{}}`, "sast", "not Semgrep's JSON"},
		"results of the wrong type": {`{"results":[{"check_id":1}],"errors":[],"paths":{}}`, "sast",
			"not Semgrep's JSON"},
		"no rule": {semgrepFileOf("OSS", semgrepCodeOf("", "a.py", 1, "ERROR", `{}`)), "sast",
			"result 1 has no check_id, the rule it matched, which Semgrep writes for every one"},
		"no path": {semgrepFileOf("OSS", semgrepCodeOf("r", "", 1, "ERROR", `{}`)), "sast", "result 1 (r) has no path"},
		"an unknown severity": {semgrepFileOf("OSS", semgrepCodeOf("r", "a.py", 1, "SEVERE", `{}`)), "sast",
			`result 1 (r): severity "SEVERE"; a Semgrep rule's severity is CRITICAL`},
		"no package": {strings.Replace(sca(`{}`), `"package":"x","version"`, `"package":"","version"`, 1),
			"sca", "result 1 (ssc) has no sca_info.dependency_match.found_dependency.package"},
		"an unknown advisory severity": {sca(`{"sca-severity":"URGENT"}`), "sca",
			`result 1 (ssc): sca-severity "URGENT"; Semgrep rates an advisory CRITICAL, HIGH, MODERATE or LOW`},
		"an unknown rule severity": {strings.Replace(sca(`{}`), `"severity":"ERROR"`, `"severity":"SEVERE"`, 1), "sca",
			`result 1 (ssc): severity "SEVERE"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewSARIFImport().Scan(context.Background(), plugin.FileTarget{Path: writeFile(t, c.body),
				Format: saga.ImportFormatSemgrepJSON, Control: c.control}, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
	// Validation holds the format to sast and sca; the reader refuses another control too.
	if _, err := readSemgrepImport([]byte(semgrepFileOf("OSS")), plugin.FileTarget{Control: "iac"}); err == nil ||
		!strings.Contains(err.Error(), `control "iac"; import this file into sast or sca`) {
		t.Errorf("iac: %v", err)
	}
}

// Semgrep's JSON imported into sast, beside Draugr's run of Semgrep over the same code: each finding
// is counted once in each of two components, naming the other copy, since the import names its tool
// as Semgrep's SARIF does, and both copies are rated from the rule's impact and likelihood.
func TestAnImportedSemgrepJSONBesideSemgrepCountsEachFindingOnce(t *testing.T) {
	semgrep, config := replayingSemgrep(t)
	comps := twoComponents("semgrep-code.json")
	for name, c := range comps {
		c.format = saga.ImportFormatSemgrepJSON
		comps[name] = c
	}
	res, _ := runBesideImport(t, controllers.NewSAST(), semgrep,
		saga.ControllerSettings{"enabled": true, "semgrep": map[string]any{"config": config}}, comps)
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	if n := len(res.Controls["sast"].Report.Results); n != 8 {
		t.Fatalf("%d results, want 2 rules × 2 copies × 2 components", n)
	}
	got := countedFlaws(t, res, "sast")
	for _, comp := range []string{"api", "web"} {
		flaws := got[comp]
		if len(flaws) != 2 {
			t.Fatalf("%s: counted %+v, want each of the two findings once", comp, flaws)
		}
		for _, f := range flaws {
			if len(f.also) != 1 || (f.also[0] != "Semgrep OSS" && f.also[0] != "imported Semgrep OSS (semgrep-json)") {
				t.Errorf("%s %s: also found by %v, want the other Semgrep copy", comp, f.rule, f.also)
			}
		}
	}
	for _, r := range res.Controls["sast"].Report.Results {
		for _, o := range r.Correlation.AlsoFoundBy {
			if o.Severity != r.Severity("") {
				t.Errorf("%s %s: %s under %s, %s under %s", r.Component, r.RuleID, r.Severity(""), r.Reporter(), o.Severity, o.Tool)
			}
		}
	}
}
