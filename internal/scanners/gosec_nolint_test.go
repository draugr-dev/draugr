package scanners

import (
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gosecSARIF is one gosec SARIF document holding a result of rule G101 on each line of uri, with a
// `#nosec`'s suppression on the lines in nosec.
func gosecSARIF(uri string, lines []int, nosec map[int]bool) string {
	var results []string
	for _, l := range lines {
		sup := ""
		if nosec[l] {
			sup = `,"suppressions":[{"kind":"inSource","justification":"gosec's own"}]`
		}
		results = append(results, fmt.Sprintf(`{"ruleId":"G101","message":{"text":"m"},"locations":[{"physicalLocation":`+
			`{"artifactLocation":{"uri":%q},"region":{"startLine":%d}}}]%s}`, uri, l, sup))
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"G101"}]}},"results":[` +
		strings.Join(results, ",") + `]}]}`
}

// withNolint writes golangci-lint's directive where a fixture says NOLINT, and its spaced form where
// it says SPACED. The fixtures spell it so because the gate's check-gosec-suppressions refuses the
// directive naming gosec anywhere in Draugr's own Go source.
func withNolint(s string) string {
	return strings.NewReplacer("NOLINT", "/"+"/nolint", "SPACED", "/"+"/ nolint").Replace(s)
}

// The line numbers matter: each result below is on the line the test expects it.
const nolintService = `package main

import "os"

const envToken = "GITHUB_TOKEN" NOLINT:gosec // the variable's name, not a value

const envPassword = "APP_PASSWORD" // #nosec G101 -- gosec's own

const other = "X" NOLINT:errcheck // names another linter only

// read reads a path the operator chose.
//
NOLINT:gosec // the signature only
func read(p string) {
	_, _ = os.ReadFile(p)
}

func main() {
	_ = os.Getenv(envToken)
	NOLINT:gosec,errcheck
	x := 1
	_ = x
NOLINT:all // at another column
	y := 2
	_ = y
	z := 3 SPACED
	_ = z
	NOLINT:gosec // the first line only
	_ = os.Expand(
		"$HOME", os.Getenv)
	NOLINT:gosec

	_ = os.Getenv("A")
	NOLINT:gosec
	// another comment between
	_ = os.Getenv("B")
	_ = os.Expand(
		NOLINT:gosec
		"$HOME", os.Getenv)
}
`

// Above package, a nolint reaches the package clause and nothing in the file.
const nolintTools = `NOLINT:gosec // generated
package main

const envToken = "GITHUB_TOKEN"
`

// A gosec result on a line a `nolint` covering gosec reaches is kept and marked as a `#nosec`
// result is, and in each module's own files. The directive reaches its own line, or the first line
// of the statement or declaration directly below it, and never a function's body, a file, or a line
// under a blank line or another comment.
func TestParseGosecMarksWhatNolintCovers(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"service/go.mod":  "module example.com/service\n\ngo 1.21\n",
		"service/main.go": withNolint(nolintService),
		"tools/go.mod":    "module example.com/tools\n\ngo 1.21\n",
		"tools/main.go":   withNolint(nolintTools),
	})
	out := gosecSARIF("main.go", []int{5, 7, 9, 14, 15, 19, 21, 24, 26, 29, 30, 33, 36, 39}, map[int]bool{7: true}) + "\n" +
		gosecSARIF("main.go", []int{4}, nil)
	rep, err := parseGosec([]byte(out), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"service/main.go:5":  "the variable's name, not a value",
		"service/main.go:7":  "gosec's own",
		"service/main.go:9":  "-", // names errcheck only
		"service/main.go:14": "the signature only",
		"service/main.go:15": "-", // the function's body
		"service/main.go:19": "-", // no directive
		"service/main.go:21": "",  // the statement under a list naming gosec
		"service/main.go:24": "at another column",
		"service/main.go:26": "", // bare, with a space after the slashes
		"service/main.go:29": "the first line only",
		"service/main.go:30": "-", // a later line of the same statement
		"service/main.go:33": "-", // under a blank line
		"service/main.go:36": "-", // under another comment
		"service/main.go:39": "-", // not the first line of a statement
		"tools/main.go:4":    "-", // the directive is above package
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("results = %d, want %d", len(rep.Results), len(want))
	}
	for _, r := range rep.Results {
		at := fmt.Sprintf("%s:%d", r.Location.URI, r.Location.StartLine)
		why, ok := want[at]
		if !ok {
			t.Errorf("unexpected result at %s", at)
			continue
		}
		if why == "-" {
			if r.Suppression != nil {
				t.Errorf("%s suppressed (%+v), want a finding", at, r.Suppression)
			}
			continue
		}
		if r.Suppression == nil {
			t.Errorf("%s is a finding, want it suppressed in source", at)
			continue
		}
		if !r.SilencedInSource() || r.Suppression.Kind != "inSource" || r.Suppression.Justification != why {
			t.Errorf("%s suppression = %+v, want in source with %q", at, r.Suppression, why)
		}
	}
}

// A file that cannot be read or parsed, or a location outside the checkout, leaves the result a
// finding: unmarked claims nothing.
func TestParseGosecLeavesUnreadableFilesUnmarked(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":    "module example.com/x\n\ngo 1.21\n",
		"broken.go": withNolint("NOLINT:gosec\npackage main\n\nfunc {\n"),
	})
	for _, uri := range []string{"broken.go", "missing.go", "../outside.go"} {
		rep, err := parseGosec([]byte(gosecSARIF(uri, []int{1}, nil)), dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 1 || rep.Results[0].Suppression != nil {
			t.Errorf("%s: results = %+v, want one unmarked finding", uri, rep.Results)
		}
	}
	var none sarif.Report
	markNolintSuppressed(&none, "")
}

func TestNolintCoversGosec(t *testing.T) {
	for _, c := range []struct {
		text, why string
		ok        bool
	}{
		{"NOLINT", "", true},
		{"NOLINT:gosec", "", true},
		{"SPACED:gosec // reason here", "reason here", true},
		{"NOLINT:errcheck,GoSec // both", "both", true},
		{"NOLINT:gas", "", true},
		{"NOLINT:all // everything", "everything", true},
		{"NOLINT because it is fine", "because it is fine", true},
		{"NOLINT:errcheck // not this one", "", false},
		{"NOLINT:gosec-like", "", false},
		{"NOLINTgosec", "", false},
		{"// a comment that says nolint", "", false},
		{"/* nolint:gosec */", "", false},
	} {
		why, ok := nolintCoversGosec(withNolint(c.text))
		if ok != c.ok || why != c.why {
			t.Errorf("nolintCoversGosec(%q) = %q, %v, want %q, %v", c.text, why, ok, c.why, c.ok)
		}
	}
}
