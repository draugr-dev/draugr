package sealed

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const sampleSARIF = `{"runs":[{"results":[
 {"ruleId":"CVE-1","locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.mod"},"region":{"startLine":5}}}],
  "properties":{"tool":"trivy","control":"sca","package":{"name":"golang.org/x/text","version":"v0.3.6","ecosystem":"gomod"},"reachability":{"state":"reachable"}}},
 {"ruleId":"draugr-fixture-eval","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/index.js"},"region":{"startLine":4}}}],
  "properties":{"tool":"Semgrep OSS","control":"sast"}},
 {"ruleId":"CVE-2","locations":[{"physicalLocation":{"artifactLocation":{"uri":"static/lib.js"}}}],
  "properties":{"tool":"retirejs","control":"sca","package":{"name":"jquery","version":"1.8.3","ecosystem":"npm"}}},
 {"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"deploy/aws.env"},"region":{"startLine":1}}}],
  "properties":{"tool":"gitleaks","control":"secrets"}},
 {"ruleId":"no-location","properties":{"tool":"x","control":"sast"}}
]}]}`

func TestObserve(t *testing.T) {
	got, err := Observe([]byte(sampleSARIF))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d findings", len(got))
	}
	for i, want := range []string{
		"sca trivy CVE-1 at go.mod:5 (gomod golang.org/x/text v0.3.6) reachable",
		"sast Semgrep OSS draugr-fixture-eval at src/index.js:4",
		"sca retirejs CVE-2 at static/lib.js (npm jquery 1.8.3)",
		"secrets gitleaks aws-access-token at deploy/aws.env:1",
		"sast x no-location at ",
	} {
		if got[i].String() != want {
			t.Errorf("finding %d = %q, want %q", i, got[i], want)
		}
	}
	if _, err := Observe([]byte("{")); err == nil {
		t.Error("unreadable SARIF was accepted")
	}
}

func TestCheck(t *testing.T) {
	got, err := Observe([]byte(sampleSARIF))
	if err != nil {
		t.Fatal(err)
	}
	got = got[:4]
	exp := Expected{
		Secrets: []SecretExpectation{{File: "deploy/aws.env", Rules: []string{"aws-access-token"}}},
		Findings: []FindingExpectation{
			{Control: "sca", Tool: "trivy", Rule: "CVE-1", Location: "go.mod:5", Package: "gomod golang.org/x/text v0.3.6", Reachability: "reachable"},
			{Control: "sca", Tool: "retirejs", Rule: "CVE-2", Location: "static/lib.js"},
		},
	}
	anns := []Annotation{{File: "src/index.js", Line: 4, Rule: "draugr-fixture-eval", Want: true}}
	problems, err := Check(exp, anns, got)
	if err != nil || len(problems) != 0 {
		t.Fatalf("a matching scan reported %v (%v)", problems, err)
	}

	// The wrong verdict, a result nothing expects, and a result on a line marked ok.
	exp.Findings[0].Reachability = "unreachable"
	anns = append(anns, Annotation{File: "src/index.js", Line: 4, Rule: "draugr-fixture-eval", Want: false})
	problems, err = Check(exp, anns, got)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		"missing (expected.yaml): sca trivy CVE-1 at go.mod:5 (gomod golang.org/x/text v0.3.6) unreachable",
		"unexpected: sca trivy CVE-1 at go.mod:5 (gomod golang.org/x/text v0.3.6) reachable",
		"reported on a line marked ok: sast Semgrep OSS draugr-fixture-eval at src/index.js:4",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems lack %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "unexpected: sast") {
		t.Errorf("a result on an ok line was reported twice:\n%s", joined)
	}

	exp.Findings[0].Location = "go.mod:x"
	if _, err := Check(exp, nil, got); err == nil {
		t.Error("a bad location was accepted")
	}
}

func TestCheckTellsComponentsApart(t *testing.T) {
	// Two components scanning one repository report the same file twice, and only the component
	// says which verdict belongs to which. An expectation naming the component holds each to its
	// own; swapping the verdicts between them must fail.
	const twoComponents = `{"runs":[{"results":[
 {"ruleId":"CVE-1","locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.mod"},"region":{"startLine":5}}}],
  "properties":{"tool":"trivy","control":"sca","component":"api","reachability":{"state":"reachable"}}},
 {"ruleId":"CVE-1","locations":[{"physicalLocation":{"artifactLocation":{"uri":"go.mod"},"region":{"startLine":5}}}],
  "properties":{"tool":"trivy","control":"sca","component":"worker","reachability":{"state":"unreachable"}}}
]}]}`
	got, err := Observe([]byte(twoComponents))
	if err != nil {
		t.Fatal(err)
	}
	if s := got[0].String(); s != "sca trivy CVE-1 at go.mod:5 in api reachable" {
		t.Errorf("finding = %q, want the component named", s)
	}
	exp := Expected{Findings: []FindingExpectation{
		{Rule: "CVE-1", Location: "go.mod:5", Component: "api", Reachability: "reachable"},
		{Rule: "CVE-1", Location: "go.mod:5", Component: "worker", Reachability: "unreachable"},
	}}
	if problems, err := Check(exp, nil, got); err != nil || len(problems) != 0 {
		t.Fatalf("a matching scan reported %v (%v)", problems, err)
	}
	exp.Findings[0].Component, exp.Findings[1].Component = "worker", "api"
	problems, err := Check(exp, nil, got)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 4 {
		t.Errorf("swapped verdicts reported %d problems, want 2 missing and 2 unexpected:\n%s",
			len(problems), strings.Join(problems, "\n"))
	}
}

func TestCheckHoldsASecretToTheComponentsThatOwnIt(t *testing.T) {
	// A root secret two components both name is reported once under each; a secret under one
	// component's paths is reported under that one alone. Filing either under the wrong component
	// must fail, and so must a second report nothing expects.
	const reported = `{"runs":[{"results":[
 {"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"deploy.env"},"region":{"startLine":1}}}],
  "properties":{"tool":"gitleaks","control":"secrets","component":"api"}},
 {"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"deploy.env"},"region":{"startLine":1}}}],
  "properties":{"tool":"gitleaks","control":"secrets","component":"web"}},
 {"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"services/api/aws.env"},"region":{"startLine":1}}}],
  "properties":{"tool":"gitleaks","control":"secrets","component":"api"}}
]}]}`
	got, err := Observe([]byte(reported))
	if err != nil {
		t.Fatal(err)
	}
	exp := Expected{Secrets: []SecretExpectation{
		{File: "deploy.env", Rules: []string{"aws-access-token"}, Components: []string{"api", "web"}},
		{File: "services/api/aws.env", Rules: []string{"aws-access-token"}, Components: []string{"api"}},
	}}
	if problems, err := Check(exp, nil, got); err != nil || len(problems) != 0 {
		t.Fatalf("a matching scan reported %v (%v)", problems, err)
	}

	exp.Secrets[1].Components = []string{"web"}
	problems, err := Check(exp, nil, got)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		"missing (expected.yaml secrets): secrets aws-access-token at services/api/aws.env:1 in web",
		"unexpected: secrets gitleaks aws-access-token at services/api/aws.env:1 in api",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems lack %q:\n%s", want, joined)
		}
	}

	// Without components, one report from any component satisfies it, and a second is unexpected.
	exp.Secrets = []SecretExpectation{
		{File: "deploy.env", Rules: []string{"aws-access-token"}},
		{File: "services/api/aws.env", Rules: []string{"aws-access-token"}},
	}
	problems, err = Check(exp, nil, got)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "unexpected: secrets gitleaks aws-access-token at deploy.env:1") {
		t.Errorf("problems = %v, want the second report of deploy.env unexpected", problems)
	}

	// With no rules, the secret is one nothing may report: every report of it is unexpected.
	exp.Secrets = []SecretExpectation{
		{File: "deploy.env"},
		{File: "services/api/aws.env", Rules: []string{"aws-access-token"}, Components: []string{"api"}},
	}
	problems, err = Check(exp, nil, got)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 || !strings.Contains(strings.Join(problems, "\n"), "unexpected: secrets gitleaks aws-access-token at deploy.env:1 in web") {
		t.Errorf("problems = %v, want both reports of deploy.env unexpected", problems)
	}
}

func TestCheckHoldsTheHistoryMark(t *testing.T) {
	// A removed secret is reported from history and must carry the mark; a secret still in the
	// tree is reported once, unmarked. A second, historical report of the tree secret is the
	// duplicate the mark exists to catch, and an expectation matching either would pass it.
	const reported = `{"runs":[{"results":[
 {"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"old/aws.env"},"region":{"startLine":1}}}],
  "properties":{"tool":"gitleaks","control":"secrets","component":"api","historical":true}},
 {"ruleId":"generic-api-key","locations":[{"physicalLocation":{"artifactLocation":{"uri":"settings.py"},"region":{"startLine":3}}}],
  "properties":{"tool":"gitleaks","control":"secrets","component":"web"}}
]}]}`
	got, err := Observe([]byte(reported))
	if err != nil {
		t.Fatal(err)
	}
	if want := "secrets gitleaks aws-access-token at old/aws.env:1 in api (historical)"; got[0].String() != want {
		t.Errorf("finding = %q, want %q", got[0], want)
	}
	exp := Expected{
		Secrets: []SecretExpectation{{File: "old/aws.env", Rules: []string{"aws-access-token"}, Removed: true}},
		Findings: []FindingExpectation{
			{Control: "secrets", Tool: "gitleaks", Rule: "generic-api-key", Location: "settings.py:3"},
		},
	}
	if problems, err := Check(exp, nil, got); err != nil || len(problems) != 0 {
		t.Fatalf("a matching scan reported %v (%v)", problems, err)
	}

	// The same secret again from history, beside its tree finding.
	dup := append(slices.Clone(got), Finding{Control: "secrets", Tool: "gitleaks", Rule: "generic-api-key",
		File: "settings.py", Line: 3, Component: "web", Historical: true})
	problems, err := Check(exp, nil, dup)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "unexpected: secrets gitleaks generic-api-key at settings.py:3 in web (historical)") {
		t.Errorf("problems = %v, want the history copy unexpected", problems)
	}

	// A history finding reported without the mark does not satisfy a removed secret.
	got[0].Historical = false
	problems, err = Check(exp, nil, got)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 {
		t.Errorf("problems = %v, want the marked report missing and the unmarked one unexpected", problems)
	}
}

func TestSplitLocation(t *testing.T) {
	for loc, want := range map[string]struct {
		file string
		line int
		bad  bool
	}{
		"a/b.go:12":                        {file: "a/b.go", line: 12},
		"a/b.js":                           {file: "a/b.js"},
		"a:0":                              {bad: true},
		"a:":                               {bad: true},
		"":                                 {bad: true},
		"127.0.0.1:18080/app:1.0":          {file: "127.0.0.1:18080/app:1.0"},
		"http://127.0.0.1:18080/items?q=1": {file: "http://127.0.0.1:18080/items?q=1"},
		"a/b.go:x":                         {bad: true},
	} {
		file, line, err := splitLocation(loc)
		if (err != nil) != want.bad || file != want.file || line != want.line {
			t.Errorf("splitLocation(%q) = %q %d %v", loc, file, line, err)
		}
	}
}

func TestReadAnnotations(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "app.py"), "import os\n\n# ruleid: rule-a\n\nos.popen(x)\n# ok: rule-a\nsafe()\n")
	writeFixture(t, filepath.Join(dir, "main.go"), "package main\n// ruleid: G204, G702\nexec()\n/* ok: G101 */\nx := 1\n// ruleid: dangling\n")
	writeFixture(t, filepath.Join(dir, "package.json"+FixtureSuffix), "// ruleid: in-a-fixture\n{}\n")
	writeFixture(t, filepath.Join(dir, "vendor", "x.go"), "// ruleid: vendored\nx()\n")
	writeFixture(t, filepath.Join(dir, "node_modules", "y.js"), "// ruleid: installed\ny()\n")

	got, err := ReadAnnotations(dir)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, a := range got {
		kind := "ok"
		if a.Want {
			kind = "ruleid"
		}
		lines = append(lines, a.File+":"+strconv.Itoa(a.Line)+" "+kind+" "+a.Rule)
	}
	want := []string{
		"app.py:5 ruleid rule-a", "app.py:7 ok rule-a",
		"main.go:3 ruleid G204", "main.go:3 ruleid G702", "main.go:5 ok G101",
		"package.json:2 ruleid in-a-fixture",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("annotations:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if _, err := ReadAnnotations(filepath.Join(dir, "absent")); err == nil {
		t.Error("an absent directory read cleanly")
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "draugr.saga.yaml")
	writeFixture(t, path, "project: demo\nrelease:\n  version: \"1.0\"\nconfig:\n  controllers:\n    sca:\n      enabled: true\n    sast:\n      enabled: true\n    iac:\n      enabled: false\ncomponents:\n  - name: demo\n    repositories:\n      - url: .\n")
	got, err := ObserveInit(path)
	if err != nil {
		t.Fatal(err)
	}
	exp := InitExpectation{Controls: []string{"sca", "sast"}, Components: []ComponentExpectation{{Name: "demo", Repositories: []string{"."}}}}
	if p := CheckInit(exp, got); len(p) != 0 {
		t.Errorf("a matching descriptor reported %v", p)
	}
	exp.Controls = append(exp.Controls, "secrets")
	exp.Components[0].Name = "other"
	if p := CheckInit(exp, got); len(p) != 2 {
		t.Errorf("problems = %v, want the controls and the components named", p)
	}

	// Scanners inside a control, the reachability analyzers and each repository's scope are part
	// of what init wrote, and a difference in any of them is reported.
	writeFixture(t, path, "project: demo\nrelease:\n  version: \"1.0\"\nconfig:\n  reachability:\n    analyzers: [govulncheck]\n"+
		"  controls:\n    sast:\n      enabled: true\n      gosec:\n        enabled: true\n      semgrep:\n        enabled: false\n"+
		"components:\n  - name: demo\n    repositories:\n      - url: .\n        ignore: [web/]\n"+
		"  - name: web\n    repositories:\n      - url: .\n        paths: [web]\n")
	got, err = ObserveInit(path)
	if err != nil {
		t.Fatal(err)
	}
	exp = InitExpectation{
		Controls: []string{"sast"}, Scanners: []string{"sast.gosec"}, Reachability: []string{"govulncheck"},
		Components: []ComponentExpectation{
			{Name: "demo", Repositories: []string{"."}, Ignore: []string{"web/"}},
			{Name: "web", Repositories: []string{"."}, Paths: []string{"web"}},
		},
	}
	if p := CheckInit(exp, got); len(p) != 0 {
		t.Errorf("a matching descriptor reported %v", p)
	}
	exp.Scanners, exp.Reachability, exp.Components[1].Paths = nil, nil, nil
	if p := CheckInit(exp, got); len(p) != 3 {
		t.Errorf("problems = %v, want the scanners, the analyzers and the components named", p)
	}

	// An API document init found is proposed in a hosts block written commented out, as init
	// writes it.
	writeFixture(t, path, "project: demo\nconfig:\n  controls:\n    sca:\n      enabled: true\ncomponents:\n  - name: demo\n"+
		"    repositories:\n      - url: .\n    # hosts:\n    #   - name: api\n    #     url: https://api.example.com\n"+
		"    #     type: api\n    #     spec:\n    #       path: ./openapi.yaml\n")
	got, err = ObserveInit(path)
	if err != nil {
		t.Fatal(err)
	}
	exp = InitExpectation{Controls: []string{"sca"}, Specs: []string{"./openapi.yaml"}, Components: []ComponentExpectation{{Name: "demo", Repositories: []string{"."}}}}
	if p := CheckInit(exp, got); len(p) != 0 {
		t.Errorf("a matching descriptor reported %v", p)
	}
	exp.Specs = nil
	if p := CheckInit(exp, got); len(p) != 1 || !strings.Contains(p[0], "proposes host specs") {
		t.Errorf("problems = %v, want the spec named", p)
	}

	writeFixture(t, path, "project: [\n")
	if _, err := ObserveInit(path); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Errorf("err = %v", err)
	}
	_ = os.Remove(path)
}

func TestCheckHoldsTheSuppression(t *testing.T) {
	// A finding a scanner set aside under its own configuration arrives suppressed, with the origin
	// naming whose rule it was. An expectation for it has to name the origin, and one written for an
	// active finding must not accept it.
	const reported = `{"runs":[{"results":[
 {"ruleId":"license/ISC/inherits","locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json"},"region":{"startLine":9}}}],
  "suppressions":[{"kind":"external","properties":{"origin":"scanner","source":".trivyignore"}}],
  "properties":{"tool":"trivy-license","control":"licenses","component":"web"}},
 {"ruleId":"aws-access-token","locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":3}}}],
  "suppressions":[{"kind":"inSource"}],
  "properties":{"tool":"gitleaks","control":"secrets","component":"api"}}
]}]}`
	got, err := Observe([]byte(reported))
	if err != nil {
		t.Fatal(err)
	}
	if want := "licenses trivy-license license/ISC/inherits at package-lock.json:9 in web (suppressed: scanner)"; got[0].String() != want {
		t.Errorf("finding = %q, want %q", got[0], want)
	}
	if got[1].Suppressed != "inSource" {
		t.Errorf("a suppression with no origin read as %q, want its kind", got[1].Suppressed)
	}
	exp := Expected{Findings: []FindingExpectation{
		{Control: "licenses", Rule: "license/ISC/inherits", Location: "package-lock.json:9", Suppressed: "scanner"},
		{Control: "secrets", Rule: "aws-access-token", Location: "app.py:3", Suppressed: "inSource"},
	}}
	if problems, err := Check(exp, nil, got); err != nil || len(problems) != 0 {
		t.Fatalf("a matching scan reported %v (%v)", problems, err)
	}

	exp.Findings[0].Suppressed = ""
	problems, err := Check(exp, nil, got)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 {
		t.Errorf("problems = %v, want the active finding missing and the suppressed one unexpected", problems)
	}
}
