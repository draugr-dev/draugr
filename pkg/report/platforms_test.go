package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding in code only another platform builds names that build beside its location, in the
// console, the compact view and report.json, and a finding in code every build holds names none.
func TestAFindingInAnotherPlatformsCodeNamesItsBuild(t *testing.T) {
	at := func(uri string, platforms ...string) sarif.Result {
		return sarif.Result{Tool: "gosec", RuleID: "G204", Level: sarif.LevelWarning, Message: "Subprocess launched with a variable",
			Control: "sast", Priority: "P2", Location: sarif.Location{URI: uri, StartLine: 21}, Platforms: platforms}
	}
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"sast": {Report: sarif.Report{Results: []sarif.Result{
		at("internal/checks/audit_process_windows.go", "windows/amd64"),
		at("internal/fsutil/open_other.go", "windows/amd64", "darwin/arm64"),
		at("main.go"),
	}}}}}}
	// One rule, so each finding takes a row of its own only under --top 0.
	d.TopN = -1
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	for _, want := range []string{
		"      internal/checks/audit_process_windows.go:21 · windows/amd64 build\n",
		"      internal/fsutil/open_other.go:21 · windows/amd64 and darwin/arm64 builds\n",
		"      main.go:21\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the console does not hold %q", want)
		}
	}

	buf.Reset()
	compact := d
	compact.View = ViewCompact
	if err := (consoleReporter{}).Render(&buf, compact); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "audit_process_windows.go:21 · windows/amd64 build") {
		t.Errorf("the compact view does not name the build:\n%s", buf.String())
	}

	var doc struct {
		Findings []struct {
			Location  string   `json:"location"`
			Platforms []string `json:"platforms"`
		} `json:"findings"`
	}
	buf.Reset()
	listed := d
	listed.MinPriority = "P4"
	if err := (jsonReporter{}).Render(&buf, listed); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range doc.Findings {
		got[f.Location] = strings.Join(f.Platforms, ",")
	}
	if got["internal/checks/audit_process_windows.go:21"] != "windows/amd64" || got["main.go:21"] != "" {
		t.Errorf("report.json platforms by location = %v", got)
	}
}

// A call path from code only another platform builds names that build on the reachable line.
func TestAReachablePathFromAnotherPlatformNamesItsBuild(t *testing.T) {
	got := reachabilityPath(&sarif.Reachability{
		State: sarif.ReachabilityReachable, Analyzer: "govulncheck", Platforms: []string{"windows/amd64"},
		Paths: []sarif.CallPath{{Frames: []sarif.CallFrame{{Function: "winapi.init"}, {Function: "windows.GetCurrentProcessId"}}}},
	})
	if !strings.HasPrefix(got, "reachable in the windows/amd64 build: winapi.init → windows.GetCurrentProcessId") {
		t.Errorf("reachabilityPath = %q", got)
	}
}

// Platforms survive a report written to SARIF and read back, on a finding and on its verdict.
func TestPlatformsSurviveTheSARIFFile(t *testing.T) {
	in := sarif.Report{Tool: "gosec", Results: []sarif.Result{{
		Tool: "gosec", RuleID: "G204", Level: sarif.LevelWarning, Message: "m", Location: sarif.Location{URI: "a_windows.go", StartLine: 3},
		Platforms:    []string{"windows/amd64"},
		Reachability: &sarif.Reachability{State: sarif.ReachabilityReachable, Analyzer: "govulncheck", Platforms: []string{"darwin/arm64"}},
	}}}
	raw, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sarif.FromSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := out.Results[0]
	if strings.Join(r.Platforms, ",") != "windows/amd64" || r.Reachability == nil || strings.Join(r.Reachability.Platforms, ",") != "darwin/arm64" {
		t.Errorf("read back: platforms %v, reachability %+v", r.Platforms, r.Reachability)
	}
}

func TestPlatformNote(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"windows/amd64"}, "windows/amd64 build"},
		{[]string{"a", "b", "c"}, "a, b and c builds"},
	} {
		if got := platformNote(c.in); got != c.want {
			t.Errorf("platformNote(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
