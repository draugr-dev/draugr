package sealed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCheckPresent(t *testing.T) {
	got := []Finding{
		// A real database names the same package finding by another advisory and reaches a
		// different verdict on it.
		{Control: "sca", Tool: "trivy", Rule: "CVE-9", File: "go.mod", Line: 5, Package: "gomod golang.org/x/text v0.3.6", Reachability: "unreachable"},
		{Control: "sast", Tool: "Semgrep OSS", Rule: "draugr-fixture-eval", File: "src/index.js", Line: 4},
		{Control: "secrets", Tool: "gitleaks", Rule: "aws-access-token", File: "deploy/aws.env", Line: 1},
		{Control: "sca", Tool: "trivy", Rule: "CVE-10", File: "package-lock.json", Line: 3, Package: "npm extra 1.0.0"},
	}
	exp := Expected{
		Secrets: []SecretExpectation{{File: "deploy/aws.env", Rules: []string{"aws-access-token"}}},
		Findings: []FindingExpectation{
			{Control: "sca", Tool: "trivy", Rule: "CVE-1", Location: "go.mod:5", Package: "gomod golang.org/x/text v0.3.6", Reachability: "reachable"},
		},
	}
	anns := []Annotation{{File: "src/index.js", Line: 4, Rule: "draugr-fixture-eval", Want: true}}
	if problems, err := CheckPresent(exp, anns, got); err != nil || len(problems) != 0 {
		t.Errorf("CheckPresent = %q, %v; want every expectation met", problems, err)
	}

	// What real data cannot move still has to be there: the package, the rule of a result with no
	// package, and a verdict where one was expected.
	exp.Findings = append(exp.Findings,
		FindingExpectation{Control: "sca", Tool: "trivy", Rule: "CVE-2", Location: "go.mod:5", Package: "gomod golang.org/x/text v0.3.7"},
		FindingExpectation{Control: "sca", Tool: "retirejs", Rule: "CVE-3", Location: "static/jquery.js", Package: "npm jquery 1.8.3", Reachability: "reachable"},
	)
	anns = append(anns, Annotation{File: "src/index.js", Line: 4, Rule: "draugr-fixture-other", Want: true})
	got = append(got, Finding{Control: "sca", Tool: "retirejs", Rule: "CVE-3", File: "static/jquery.js", Package: "npm jquery 1.8.3"})
	problems, err := CheckPresent(exp, anns, got)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"missing (expected.yaml): sca retirejs CVE-3 at static/jquery.js (npm jquery 1.8.3) reachable",
		"missing (expected.yaml): sca trivy CVE-2 at go.mod:5 (gomod golang.org/x/text v0.3.7)",
		"missing (ruleid annotation): sast draugr-fixture-other at src/index.js:4",
	}
	if !reflect.DeepEqual(problems, want) {
		t.Errorf("CheckPresent =\n%s\nwant\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}

	exp.Findings = []FindingExpectation{{Control: "sca", Location: "go.mod:x"}}
	if _, err := CheckPresent(exp, nil, got); err == nil {
		t.Error("an unreadable location was accepted")
	}
}

func writeManifest(t *testing.T, home string, v any) string {
	t.Helper()
	dir := filepath.Join(home, ".draugr", "feeds")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".draugr-feeds.json")
	if err := writeJSON(path, v); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTakeAway(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	src, home := t.TempDir(), filepath.Join(t.TempDir(), "home")
	for _, f := range []string{".cache/trivy/db/trivy.db", ".cache/trivy/java-db/trivy-java.db"} {
		p := filepath.Join(src, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("db"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	original := writeManifest(t, src, map[string]any{
		"govulndb": map[string]any{"url": "https://vuln.go.dev/vulndb.zip", "fetchedAt": now, "bytes": 7},
		"kev":      map[string]any{"fetchedAt": now},
	})
	before, err := os.ReadFile(original) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkTree(src, home); err != nil {
		t.Fatal(err)
	}

	// Nothing asked for leaves everything in place.
	if err := (RunOptions{WithoutTool: "trivy"}).TakeAway(home, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".cache", "trivy", "db", "trivy.db")); err != nil {
		t.Errorf("an empty option removed the database: %v", err)
	}

	if err := (RunOptions{WithoutTrivyDB: true, GoVulnDBAge: "72h"}).TakeAway(home, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".cache", "trivy", "db")); !os.IsNotExist(err) {
		t.Errorf("the vulnerability database is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".cache", "trivy", "java-db", "trivy-java.db")); err != nil {
		t.Errorf("the Java database went with it: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".draugr", "feeds", ".draugr-feeds.json")) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if at := got["govulndb"]["fetchedAt"]; at != "2026-09-21T12:00:00Z" {
		t.Errorf("govulndb fetchedAt = %v, want three days before now", at)
	}
	if got["govulndb"]["url"] != "https://vuln.go.dev/vulndb.zip" || got["kev"] == nil {
		t.Errorf("the rest of the manifest was not kept: %s", raw)
	}
	after, err := os.ReadFile(original) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("aging the linked copy wrote through to the original")
	}
	if _, err := os.Stat(filepath.Join(src, ".cache", "trivy", "db", "trivy.db")); err != nil {
		t.Errorf("removing the linked database removed the original: %v", err)
	}
}

func TestTakeAwayRefuses(t *testing.T) {
	home := t.TempDir()
	if err := (RunOptions{GoVulnDBAge: "three days"}).TakeAway(home, time.Now()); err == nil {
		t.Error("an unreadable age was accepted")
	}
	if err := (RunOptions{GoVulnDBAge: "1h"}).TakeAway(home, time.Now()); err == nil {
		t.Error("a home with no manifest was aged")
	}
	path := writeManifest(t, home, map[string]any{"kev": map[string]any{}})
	if err := (RunOptions{GoVulnDBAge: "1h"}).TakeAway(home, time.Now()); err == nil || !strings.Contains(err.Error(), "no govulndb") {
		t.Errorf("a manifest with no govulndb = %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (RunOptions{GoVulnDBAge: "1h"}).TakeAway(home, time.Now()); err == nil {
		t.Error("an unreadable manifest was accepted")
	}
}

func TestLinkTree(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a", "b"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a", "b", "f"), []byte("data"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b/f", filepath.Join(src, "a", "link")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy")
	if err := LinkTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "a", "b", "f")); err != nil || string(b) != "data" { // #nosec G304 -- the test's own file
		t.Errorf("linked file = %q, %v", b, err)
	}
	if target, err := os.Readlink(filepath.Join(dst, "a", "link")); err != nil || target != "b/f" {
		t.Errorf("symlink = %q, %v; want it recreated as it was", target, err)
	}
	// A second tree over the same destination refuses rather than silently merging.
	if err := LinkTree(src, dst); err == nil {
		t.Error("linking over an existing tree succeeded")
	}
	if err := LinkTree(filepath.Join(src, "absent"), dst); err == nil {
		t.Error("an absent source was linked")
	}
}

func TestCopyRegular(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	if err := os.WriteFile(from, []byte("data"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(from, to); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(to)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("mode = %v, want the source's", info.Mode().Perm())
	}
	if err := copyRegular(from, to); err == nil {
		t.Error("copying over an existing file succeeded")
	}
	if err := copyRegular(filepath.Join(dir, "absent"), filepath.Join(dir, "x")); err == nil {
		t.Error("an absent file was copied")
	}
}

func TestTrivyRanOffline(t *testing.T) {
	log := strings.Join([]string{
		`23:36:20 DEBUG  ran external tool tool=trivy argv="trivy version --format json" duration=33ms`,
		`23:36:20 DEBUG  ran external tool tool=trivy argv="trivy fs --quiet --scanners vuln --skip-db-update --skip-java-db-update --offline-scan /tmp/r" duration=43ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy argv="trivy config --skip-check-update /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy argv="trivy fs --scanners license /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy argv="trivy fs --quiet --scanners misconfig --skip-check-update /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy argv="trivy fs --scanners=secret /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy argv="trivy fs --scanners=vuln,secret /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy argv="trivy fs /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=gitleaks argv="gitleaks dir /tmp/r" duration=40ms`,
		`23:36:21 DEBUG  ran external tool tool=trivy duration=40ms`,
		`23:36:21 TRACE  tool stdout tool=trivy stdout="trivy fs /tmp/r"`,
		`23:36:22 DEBUG  ran external tool tool=trivy argv="trivy`,
	}, "\n")
	missing, ran := TrivyRanOffline([]byte(log))
	if ran != 4 {
		t.Errorf("read %d scans that read dependencies, want 4", ran)
	}
	want := []string{"trivy fs --scanners license /tmp/r", "trivy fs --scanners=vuln,secret /tmp/r", "trivy fs /tmp/r"}
	if !reflect.DeepEqual(missing, want) {
		t.Errorf("missing = %q, want %q", missing, want)
	}
	if missing, ran := TrivyRanOffline(nil); missing != nil || ran != 0 {
		t.Errorf("an empty log = %q, %d", missing, ran)
	}
}
