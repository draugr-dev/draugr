package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/converter"
	"github.com/draugr-dev/draugr/pkg/saga"
)

var update = flag.Bool("update", false, "rewrite testdata/npm-audit.draugr.json from the recorded audit")

// fixedClock is the time every test's file says it was written.
func fixedClock() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }

const commit = "0123456789abcdef0123456789abcdef01234567"

// TestConvertsARecordedAudit runs the converter on what npm 11.16.0's `npm audit --json` wrote for a
// package-lock.json pinning lodash 4.17.20 and minimist 1.2.5, and holds the file it writes to the
// one checked in, which the contract accepts with the properties manifest.yaml declares.
func TestConvertsARecordedAudit(t *testing.T) {
	golden, err := filepath.Abs(filepath.Join("testdata", "npm-audit.draugr.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The lockfile is checked in as package-lock.json.fixture, so that a tool reading the repository
	// for its dependencies does not take these deliberately vulnerable pins for the project's own. The
	// test puts it back under its real name, beside the audit, at the root of a checkout of its own.
	audit, err := os.ReadFile(filepath.Join("testdata", "npm-audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(filepath.Join("testdata", "package-lock.json.fixture"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.WriteFile("npm-audit.json", audit, 0o600); err != nil { // #nosec G703 -- a fixed name in the test's own temporary directory
		t.Fatal(err)
	}
	if err := os.WriteFile("package-lock.json", lock, 0o600); err != nil { // #nosec G703 -- a fixed name in the test's own temporary directory
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-audit", "npm-audit.json", "-lock", "package-lock.json", "-commit", commit},
		&stdout, &stderr, fixedClock)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if *update {
		if err := os.WriteFile(golden, stdout.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) // #nosec G304 -- a file in testdata
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Errorf("the converted file differs from %s; run go test -update if the change is meant\n%s", golden, stdout.String())
	}

	doc, err := converter.Read(stdout.Bytes(), sets)
	if err != nil {
		t.Fatalf("the contract refuses the file: %v", err)
	}
	if len(doc.Results) != 5 {
		t.Fatalf("%d results, want one per advisory: four on lodash and one on minimist", len(doc.Results))
	}
	first := doc.Results[0]
	if first.RuleID != "GHSA-35jh-r3h4-6jhm" || first.Severity != "high" || first.Score == nil || *first.Score != 7.2 {
		t.Errorf("first result %+v, want lodash's command injection advisory, high, 7.2", first)
	}
	if !slices.Equal(first.CWE, []string{"CWE-77", "CWE-94"}) {
		t.Errorf("cwe %v, want the advisory's CWE-77 and CWE-94", first.CWE)
	}
	p := first.Package
	if p == nil || p.Version != "4.17.20" || p.FixedVersion != "4.18.1" || p.PURL != "pkg:npm/lodash@4.17.20" || p.Ecosystem != "npm" {
		t.Errorf("package %+v, want lodash 4.17.20 from the lockfile, fixed in 4.18.1", p)
	}
	if first.Location == nil || first.Location.Path != "package-lock.json" {
		t.Errorf("location %+v, want the lockfile", first.Location)
	}
	last := doc.Results[4]
	if last.RuleID != "GHSA-xvch-5gv4-984h" || last.Severity != "critical" || last.Package.Name != "minimist" {
		t.Errorf("last result %+v, want minimist's critical prototype pollution", last)
	}
	if doc.Source.Tool != "npm audit" || len(doc.Source.SHA256) != 64 || doc.Written != "2026-11-17T12:00:00Z" || doc.Commit != commit {
		t.Errorf("head %+v, want the tool, the audit's digest, the clock and the commit", doc)
	}
}

// TestTheManifestDeclaresWhatTheConverterSets loads manifest.yaml as the import entry a descriptor
// holds and checks it names this converter, the contract it writes, and every property it sets, so a
// user who copies it has an import that reads the converter's files.
func TestTheManifestDeclaresWhatTheConverterSets(t *testing.T) {
	raw, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var imp saga.Import
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&imp); err != nil {
		t.Fatalf("manifest.yaml is not an import entry: %v", err)
	}
	if imp.Format != saga.ImportFormatConverter || imp.Converter == nil {
		t.Fatalf("format %q and converter %v, want %s with a converter", imp.Format, imp.Converter, saga.ImportFormatConverter)
	}
	if imp.Converter.Name != name || imp.Converter.Contract != converter.Version {
		t.Errorf("converter %+v, want %s writing contract %d", imp.Converter, name, converter.Version)
	}
	for _, p := range sets {
		if !slices.Contains(imp.Converter.Sets, string(p)) {
			t.Errorf("converter.sets %v leaves out %s, which the converter sets", imp.Converter.Sets, p)
		}
	}
	descriptor := "project: shop\ncomponents:\n  - name: web\n    repositories:\n      - url: .\n    imports:\n      - " +
		strings.ReplaceAll(strings.TrimSpace(stripComments(string(raw))), "\n", "\n        ") + "\n"
	if _, err := saga.Load([]byte(descriptor)); err != nil {
		t.Errorf("a descriptor importing with manifest.yaml does not load: %v\n%s", err, descriptor)
	}
}

// stripComments drops the comment lines at the top of a YAML file.
func stripComments(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

// TestATransitiveFlawIsReportedOnItsOwnPackage checks that a package npm lists only because a
// dependency of it is vulnerable, a via entry that is a package name, gets no finding of its own, and
// that a scoped package's URL escapes its @.
func TestATransitiveFlawIsReportedOnItsOwnPackage(t *testing.T) {
	audit := `{"auditReportVersion": 2, "vulnerabilities": {
	  "parent": {"name": "parent", "via": ["@acme/inner"], "nodes": ["node_modules/parent"], "fixAvailable": true},
	  "@acme/inner": {"name": "@acme/inner", "via": [
	    {"source": 7, "name": "@acme/inner", "dependency": "@acme/inner", "title": "Bad thing", "url": "https://example.com/7",
	     "severity": "moderate", "cwe": ["CWE-20", "not-a-cwe"], "cvss": {"score": 0}}],
	    "nodes": ["node_modules/parent/node_modules/@acme/inner"], "fixAvailable": {"name": "parent", "version": "2.0.0"}}}}`
	lock := `{"packages": {"node_modules/parent/node_modules/@acme/inner": {"version": "1.0.0"}}}`
	doc, err := convert([]byte(audit), []byte(lock), options{lockPath: "package-lock.json", commit: commit})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Results) != 1 {
		t.Fatalf("%d results, want only @acme/inner's own advisory", len(doc.Results))
	}
	r := doc.Results[0]
	if r.RuleID != "npm-advisory-7" || r.Severity != "medium" || r.Score != nil {
		t.Errorf("result %+v, want npm's own id, moderate read as medium, and no score", r)
	}
	if !slices.Equal(r.CWE, []string{"CWE-20"}) {
		t.Errorf("cwe %v, want only the well-formed CWE-20", r.CWE)
	}
	if r.Package.PURL != "pkg:npm/%40acme/inner@1.0.0" || r.Package.FixedVersion != "" {
		t.Errorf("package %+v, want the scope escaped and no fixed version, since the fix upgrades parent", r.Package)
	}
}

// TestRefusesWhatItCannotConvert covers the usage and input errors, each of which writes no file.
func TestRefusesWhatItCannotConvert(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sarifFile := write("x.sarif", `{"version": "2.1.0", "runs": []}`)
	v1 := write("v1.json", `{"auditReportVersion": 1, "vulnerabilities": {}}`)
	badLock := write("lock.json", `[`)
	clean := write("clean.json", `{"auditReportVersion": 2, "vulnerabilities": {}}`)
	for _, c := range []struct {
		name string
		args []string
		code int
		says string
	}{
		{"no audit", []string{"-commit", commit}, 2, "required"},
		{"unknown flag", []string{"-nope"}, 2, "not defined"},
		{"missing audit", []string{"-audit", filepath.Join(dir, "absent.json"), "-commit", commit}, 1, "no such file"},
		{"not npm audit", []string{"-audit", sarifFile, "-commit", commit}, 1, "not npm audit JSON"},
		{"old report", []string{"-audit", v1, "-commit", commit}, 1, "auditReportVersion 1"},
		{"bad lockfile", []string{"-audit", clean, "-lock", badLock, "-commit", commit}, 1, "not a package-lock.json"},
		{"bad commit", []string{"-audit", clean, "-lock", badLock + ".absent", "-commit", "main"}, 1, "breaks the contract"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(c.args, &stdout, &stderr, fixedClock); code != c.code || !strings.Contains(stderr.String(), c.says) {
				t.Errorf("exit %d, stderr %q, want %d saying %q", code, stderr.String(), c.code, c.says)
			}
			if stdout.Len() > 0 {
				t.Errorf("wrote %q on a refusal", stdout.String())
			}
		})
	}
}

// TestWritesTheNamedFile checks -o writes the file, and that a clean audit is an empty list of
// results rather than no file, which the import reads as a clean scan.
func TestWritesTheNamedFile(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.json")
	if err := os.WriteFile(auditPath, []byte(`{"auditReportVersion": 2, "vulnerabilities": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")
	var stdout, stderr bytes.Buffer
	args := []string{"-audit", auditPath, "-lock", filepath.Join(dir, "none.json"), "-commit", commit, "-repository", "https://example.com/shop.git", "-o", out}
	if code := run(args, &stdout, &stderr, fixedClock); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	raw, err := os.ReadFile(out) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if results, ok := doc["results"].([]any); !ok || len(results) != 0 || doc["repository"] != "https://example.com/shop.git" {
		t.Errorf("file %s, want an empty results list and the repository", raw)
	}
}
