package scanners

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The comparison over whole documents: each report decoded, its paths made relative, encoded again,
// and compared whole, with each exclusion's results appended in turn. Comparing a result at a time
// has to give what this gives, so it is kept here to check that against.

func wholeDocumentRelative(data []byte, dir string) ([]byte, error) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	runs, _ := doc["runs"].([]any)
	for _, run := range runs {
		r, _ := run.(map[string]any)
		results, _ := r["results"].([]any)
		for _, res := range results {
			gitleaksRelative(res, dir)
		}
	}
	return json.Marshal(doc)
}

func wholeDocumentSetAside(report, with, all []byte, kind string) ([]byte, error) {
	var every struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(all, &every); err != nil {
		return nil, err
	}
	var have struct {
		Runs []struct {
			Results []gitleaksResult `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(with, &have); err != nil {
		return nil, err
	}
	seen := map[string]int{}
	for _, run := range have.Runs {
		for _, r := range run.Results {
			seen[r.key()]++
		}
	}
	var added []any
	for _, run := range every.Runs {
		for _, raw := range run.Results {
			var r gitleaksResult
			if err := json.Unmarshal(raw, &r); err != nil {
				return nil, err
			}
			if k := r.key(); seen[k] > 0 {
				seen[k]--
				continue
			}
			result, err := decodeJSON(raw)
			if err != nil {
				return nil, err
			}
			result.(map[string]any)["suppressions"] = []any{map[string]any{"kind": kind}}
			added = append(added, result)
		}
	}
	if len(added) == 0 {
		return report, nil
	}
	return appendSARIFResults(report, "gitleaks", added, nil)
}

// wholeDocumentMerge is the report the reported run's is replaced with, given the run with the
// .gitleaksignore file out of reach (nil where there is none) and the run with allow comments
// ignored.
func wholeDocumentMerge(reported, noignore, all []byte, dir string) ([]byte, error) {
	rep, err := wholeDocumentRelative(reported, dir)
	if err != nil {
		return nil, err
	}
	merged, before := rep, rep
	if noignore != nil {
		if before, err = wholeDocumentRelative(noignore, dir); err != nil {
			return nil, err
		}
		if merged, err = wholeDocumentSetAside(merged, rep, before, "external"); err != nil {
			return nil, err
		}
	}
	a, err := wholeDocumentRelative(all, dir)
	if err != nil {
		return nil, err
	}
	return wholeDocumentSetAside(merged, before, a, "inSource")
}

// gitleaksMerged runs the passes of one tree over the reports given, with a .gitleaksignore in the
// checkout where noignore is set, and returns the report the reported run's path holds after.
func gitleaksMerged(t *testing.T, dir, reported, noignore, all string) ([]byte, error) {
	t.Helper()
	reports := map[string]string{"dir": reported, "dir+all": all}
	if noignore != "" {
		if err := os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		reports = map[string]string{"dir": reported, "dir+noignore": noignore, "dir+noignore+all": all}
	}
	path := filepath.Join(t.TempDir(), "report.sarif")
	argv := []string{"gitleaks", "dir", ".", "--report-path", path}
	passes := &gitleaksPasses{reports: reports}
	if _, err := gitleaksRun(passes.run, gitleaksVersion("8.30.1"))(context.Background(), dir, argv); err != nil {
		return nil, err
	}
	return os.ReadFile(path) // #nosec G304 -- a path under the test's own temporary directory
}

// The merged report is the one comparing whole reports gave: the same results matched and counted,
// paths compared relative to the checkout, and what each exclusion set aside added after the
// reported results in one append rather than two.
func TestTheMergedGitleaksReportIsTheOneTheWholeDocumentGives(t *testing.T) {
	result := func(line int, uri, message string) string {
		return fmt.Sprintf(`{"ruleId":"aws-access-token","message":{"text":%q},"locations":[{"physicalLocation":`+
			`{"artifactLocation":{"uri":%q},"region":{"startLine":%d,"startColumn":1,"endLine":%d,"endColumn":21,`+
			`"snippet":{"text":"AAAA"}}}}],"partialFingerprints":{"commitSha":"abc","author":"x"},"properties":{"z":1.50,"a":1e3}}`,
			message, uri, line, line)
	}
	active := result(4, "DIR/app.py", "aws <detected> & \u2028 é")
	ignored := result(2, "file://DIR/app.py", "ignored")
	allowed := result(3, "lib/app.py", "allowed")
	elsewhere := result(9, "/elsewhere/app.py", "outside")
	runOf := func(results ...string) string { return `{"runs":[{"results":[` + strings.Join(results, ",") + `]}]}` }
	for _, c := range []struct {
		name, reported, noignore, all string
	}{
		{
			name: "members out of order, with an ignored and an allowed secret",
			reported: `{"version":"2.1.0","<b>":1,"runs":[{"results":[` + active + `,` + elsewhere + `],"tool":{"driver":` +
				`{"rules":[{"id":"aws"}],"name":"gitleaks","informationUri":"https://x/?a=1&b=<2>"}},"Zeta":true,` +
				`"invocations":[{"executionSuccessful":true}],"properties":{"z":1.50,"a":1e3}}],"$schema":"https://sarif"}`,
			noignore: runOf(ignored, active, elsewhere),
			all:      runOf(ignored, active, active, allowed, elsewhere),
		},
		{name: "no runs, and an allowed secret", reported: `{"version":"2.1.0"}`, all: runOf(allowed)},
		{
			name:     "a first run whose results are null, and a second",
			reported: `{"runs":[{"results":null,"tool":{"driver":{"name":"gitleaks"}}},{"results":[` + active + `]}]}`,
			all:      runOf(active, allowed),
		},
		{name: "nothing set aside, and something after the report", reported: runOf(active) + ` trailing`, all: runOf(active) + `]`},
	} {
		dir := t.TempDir()
		in := func(s string) string { return strings.ReplaceAll(s, "DIR", dir) }
		var noignore []byte
		if c.noignore != "" {
			noignore = []byte(in(c.noignore))
		}
		want, err := wholeDocumentMerge([]byte(in(c.reported)), noignore, []byte(in(c.all)), dir)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := gitleaksMerged(t, dir, in(c.reported), in(c.noignore), in(c.all))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !sameJSON(t, got, want) {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, want)
		}
	}
}

// sameJSON reports whether two documents hold the same values, numbers as written, with a member
// whose value is null counted as absent. Neither the order of members nor how a character is
// escaped changes what a SARIF reader takes from a report, and the streamed merge writes each
// member as Gitleaks did rather than re-encoding the whole document.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	va, err := decodeJSON(a)
	if err != nil {
		t.Fatalf("decode %s: %v", a, err)
	}
	vb, err := decodeJSON(b)
	if err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return reflect.DeepEqual(withoutNulls(va), withoutNulls(vb))
}

// withoutNulls is v with every object member whose value is null removed.
func withoutNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if e != nil {
				out[k] = withoutNulls(e)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = withoutNulls(e)
		}
		return out
	}
	return v
}

// What a report has to be shaped as to be compared is what decoding it into its runs and their
// results needs, and a report the results cannot be added to is an error rather than a report
// without them.
func TestAGitleaksReportNotShapedAsSARIFIsAnError(t *testing.T) {
	allowed := gitleaksReport(leak{"a", "x", 1, "s"})
	for name, reported := range map[string]string{
		"a list":                     `[]`,
		"runs that are an object":    `{"runs":{}}`,
		"a run that is a list":       `{"runs":[[]]}`,
		"results that are a string":  `{"runs":[{"results":"x"}]}`,
		"runs named twice":           `{"runs":[],"runs":[]}`,
		"results named twice":        `{"runs":[{"results":[],"results":[]}]}`,
		"cut short":                  `{"runs":[{"results":[`,
		"a member cut short":         `{"version":`,
		"a run cut short":            `{"runs":[{"tool":`,
		"a result of the wrong type": `{"runs":[{"results":[{"ruleId":5}]}]}`,
		"null, with a secret to add": `null`,
		"a null run to add to":       `{"runs":[null]}`,
	} {
		if _, err := gitleaksMerged(t, t.TempDir(), reported, "", allowed); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A result set aside that is no object cannot be marked suppressed.
	if _, err := gitleaksMerged(t, t.TempDir(), `{"runs":[]}`, "", `{"runs":[{"results":[null]}]}`); err == nil {
		t.Error("a null result set aside: no error")
	}
}

// bigGitleaksReport writes a report of n results the size a history pass's are, about 2 KB each
// with the commit's details in its fingerprints, followed by extra, and returns its size.
func bigGitleaksReport(t *testing.T, path string, n int, extra ...string) int64 {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- a path under the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	message := strings.Repeat("m", 1500)
	_, _ = w.WriteString(`{"$schema":"https://sarif","version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[`)
	for i := range n {
		if i > 0 {
			_, _ = w.WriteString(",")
		}
		_, _ = fmt.Fprintf(w, `{"ruleId":"generic-api-key","message":{"text":"generic-api-key has detected secret for file src/f%d.py at commit %040d."},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/f%d.py"},"region":{"startLine":%d,"startColumn":1,"endLine":%d,"endColumn":40,`+
			`"snippet":{"text":"aaaaaaaaaaaaaaaa"}}}}],"partialFingerprints":{"commitSha":"%040d","author":"a","email":"a@example.com",`+
			`"date":"2026-01-01T00:00:00Z","commitMessage":"%s"}}`, i, i, i, i%500+1, i%500+1, i, message)
	}
	for _, e := range extra {
		_, _ = w.WriteString("," + e)
	}
	_, _ = w.WriteString(`]}]}`)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// While the further runs of a pass go, what the comparison holds is a key per result, not the
// report the first run wrote. Over a report of many results, the live heap a later run sees grows by
// a small part of the report's size: holding that report would cost its size at least, as bytes,
// and several times over decoded.
func TestGitleaksPassesAreComparedWithoutHoldingAReport(t *testing.T) {
	const n = 10000
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ignored := gitleaksReport(leak{"aws-access-token", "ignored.py", 2, "AAAA"})
	allowed := gitleaksReport(leak{"aws-access-token", "allowed.py", 3, "BBBB"})
	resultOf := func(report string) string {
		return strings.TrimSuffix(strings.TrimPrefix(report, `{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[`), `]}]}`)
	}
	fixtures := t.TempDir()
	size := bigGitleaksReport(t, filepath.Join(fixtures, "dir"), n)
	bigGitleaksReport(t, filepath.Join(fixtures, "dir+noignore"), n, resultOf(ignored))
	bigGitleaksReport(t, filepath.Join(fixtures, "dir+noignore+all"), n, resultOf(ignored), resultOf(allowed))

	heap := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	// Each pass copies its report from disk, so nothing the fake holds is counted, and a later one
	// reads the heap as it starts, when Gitleaks would be building a report of the same size.
	var peak uint64
	var calls []string
	run := func(_ context.Context, _ string, argv []string) ([]byte, error) {
		mode := argv[1]
		if slices.Contains(argv, gitleaksIgnorePathArg) {
			mode += "+noignore"
		}
		if slices.Contains(argv, gitleaksIgnoreAllowArg) {
			mode += "+all"
		}
		calls = append(calls, mode)
		if mode != "dir" {
			peak = max(peak, heap())
		}
		src, err := os.Open(filepath.Join(fixtures, mode)) // #nosec G304 -- a path under the test's own temporary directory
		if err != nil {
			return nil, err
		}
		defer func() { _ = src.Close() }()
		dst, err := os.Create(argv[slices.Index(argv, "--report-path")+1])
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(dst, src)
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		return nil, err
	}

	path := filepath.Join(t.TempDir(), "report.sarif")
	argv := []string{"gitleaks", "dir", ".", "--report-path", path}
	base := heap()
	if _, err := gitleaksRun(run, gitleaksVersion("8.30.1"))(context.Background(), dir, argv); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "dir,dir+noignore,dir+noignore+all" {
		t.Fatalf("passes %s, want the tree, with the file out of reach, then with allow comments ignored too", got)
	}
	var grew uint64
	if peak > base {
		grew = peak - base
	}
	if bound := uint64(size) / 4; grew > bound { // #nosec G115 -- the size of a file this test wrote
		t.Errorf("the heap grew by %d bytes while a later run went, over a report of %d bytes; want under %d", grew, size, bound)
	}

	out, err := os.ReadFile(path) // #nosec G304 -- a path under the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range rep.Results {
		if r.Suppression != nil {
			kinds[r.Suppression.Kind]++
		}
	}
	if len(rep.Results) != n+2 || kinds["external"] != 1 || kinds["inSource"] != 1 {
		t.Errorf("%d results, suppressed %v; want %d, the ignored one external and the allowed one in source", len(rep.Results), kinds, n+2)
	}
}
