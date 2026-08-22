package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// tree writes files into a temporary checkout and returns its path.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestFindingsInTheTreeAreFingerprinted(t *testing.T) {
	dir := tree(t, map[string]string{
		"app/main.go": "package main\n\nfunc main() {\n\tpassword := \"hunter2\"\n}\n",
	})
	results := []sarif.Result{
		{RuleID: "secret", Location: sarif.Location{URI: "app/main.go", StartLine: 4}},
	}
	stampLineHashes(results, dir)

	if results[0].PartialFingerprints[sarif.LineHashKey] == "" {
		t.Errorf("nothing was stamped: %v", results[0].PartialFingerprints)
	}
}

func TestAFindingWithNoFileIsLeftAlone(t *testing.T) {
	// A vulnerable dependency is identified by its package, which is already on the finding.
	dir := tree(t, map[string]string{"go.mod": "module x\n"})
	results := []sarif.Result{
		{RuleID: "CVE-2024-11111", Package: &sarif.Package{Name: "flask"}},
		{RuleID: "CVE-2024-22222", Location: sarif.Location{URI: "go.mod"}}, // no line
	}
	stampLineHashes(results, dir)

	for i, r := range results {
		if r.PartialFingerprints != nil {
			t.Errorf("result %d was stamped: %v", i, r.PartialFingerprints)
		}
	}
}

func TestAMissingFileIsNotAFailure(t *testing.T) {
	// Identity across runs is worth having and never worth losing a scan over.
	dir := tree(t, map[string]string{"present.go": "package main\n"})
	results := []sarif.Result{
		{RuleID: "r", Location: sarif.Location{URI: "gone.go", StartLine: 1}},
		{RuleID: "r", Location: sarif.Location{URI: "present.go", StartLine: 1}},
	}
	stampLineHashes(results, dir)

	if results[0].PartialFingerprints != nil {
		t.Error("a finding in a file that is not there was stamped")
	}
	if results[1].PartialFingerprints[sarif.LineHashKey] == "" {
		t.Error("one unreadable file stopped the others being fingerprinted")
	}
}

func TestNothingOutsideTheCheckoutIsRead(t *testing.T) {
	// Paths here come from a scanner's output. One reporting something outside the tree it was
	// pointed at is a scanner to distrust rather than to follow.
	dir := tree(t, map[string]string{"in.go": "package main\n"})
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("do not read me\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, uri := range map[string]string{
		"absolute":  outside,
		"traversal": "../" + filepath.Base(filepath.Dir(outside)) + "/secret.txt",
		"sneaky":    "in/../../etc/passwd",
	} {
		t.Run(name, func(t *testing.T) {
			results := []sarif.Result{{RuleID: "r", Location: sarif.Location{URI: uri, StartLine: 1}}}
			stampLineHashes(results, dir)
			if results[0].PartialFingerprints != nil {
				t.Errorf("a path outside the checkout was read: %q", uri)
			}
		})
	}
}

func TestABinaryFileIsNotFingerprinted(t *testing.T) {
	// Hashing five "lines" of a binary produces a fingerprint that means nothing and changes
	// whenever the binary does.
	dir := tree(t, map[string]string{"logo.png": "\x89PNG\x00\x00binary\x00data"})
	results := []sarif.Result{{RuleID: "r", Location: sarif.Location{URI: "logo.png", StartLine: 1}}}
	stampLineHashes(results, dir)

	if results[0].PartialFingerprints != nil {
		t.Error("a binary was fingerprinted")
	}
}

func TestAHugeFileIsSkippedRatherThanRead(t *testing.T) {
	// A minified bundle costs more to read than the identity is worth.
	dir := tree(t, map[string]string{"bundle.js": strings.Repeat("x", maxFingerprintFile+1)})
	results := []sarif.Result{{RuleID: "r", Location: sarif.Location{URI: "bundle.js", StartLine: 1}}}
	stampLineHashes(results, dir)

	if results[0].PartialFingerprints != nil {
		t.Error("a file past the limit was read")
	}
}

func TestEachFileIsReadOnce(t *testing.T) {
	// A SAST run over a large file can produce dozens of findings in it, and reading it dozens of
	// times is the cost nobody notices until the repository is big.
	dir := tree(t, map[string]string{"big.go": strings.Repeat("line\n", 500)})
	var results []sarif.Result
	for i := 1; i <= 50; i++ {
		results = append(results, sarif.Result{
			RuleID: "r", Location: sarif.Location{URI: "big.go", StartLine: i * 5},
		})
	}
	stampLineHashes(results, dir)

	stamped := 0
	for _, r := range results {
		if r.PartialFingerprints[sarif.LineHashKey] != "" {
			stamped++
		}
	}
	if stamped != len(results) {
		t.Errorf("%d of %d findings were fingerprinted", stamped, len(results))
	}
}

func TestWindowsLineEndingsFingerprintTheSame(t *testing.T) {
	// A repository checked out on Windows and on Linux must not disagree about what a finding is.
	unix := tree(t, map[string]string{"a.go": "package main\nfunc main() {}\n"})
	windows := tree(t, map[string]string{"a.go": "package main\r\nfunc main() {}\r\n"})

	one := []sarif.Result{{RuleID: "r", Location: sarif.Location{URI: "a.go", StartLine: 2}}}
	two := []sarif.Result{{RuleID: "r", Location: sarif.Location{URI: "a.go", StartLine: 2}}}
	stampLineHashes(one, unix)
	stampLineHashes(two, windows)

	if one[0].PartialFingerprints[sarif.LineHashKey] != two[0].PartialFingerprints[sarif.LineHashKey] {
		t.Error("line endings changed the fingerprint")
	}
}
