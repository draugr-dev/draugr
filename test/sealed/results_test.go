package sealed

import (
	"os"
	"path/filepath"
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

func TestSplitLocation(t *testing.T) {
	for loc, want := range map[string]struct {
		file string
		line int
		bad  bool
	}{
		"a/b.go:12": {file: "a/b.go", line: 12},
		"a/b.js":    {file: "a/b.js"},
		"a:0":       {bad: true},
		"":          {bad: true},
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

	writeFixture(t, path, "project: [\n")
	if _, err := ObserveInit(path); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Errorf("err = %v", err)
	}
	_ = os.Remove(path)
}
