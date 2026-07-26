package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A client should never be able to start a scan unless the operator said so: a scan clones
// repositories, executes external tools and reaches the network.
func TestScanIsNotExposedUnlessAllowed(t *testing.T) {
	for _, tc := range []struct {
		allow    bool
		wantScan bool
	}{{false, false}, {true, true}} {
		names := toolNames(t, Options{Registry: builtins.Registry(), AllowScan: tc.allow})
		if got := names["scan"]; got != tc.wantScan {
			t.Errorf("AllowScan=%v: scan exposed=%v, want %v (tools: %v)", tc.allow, got, tc.wantScan, names)
		}
		// The read-only tools are always there.
		for _, want := range []string{"list_controls", "get_saga_schema", "validate_saga", "summarize_report"} {
			if !names[want] {
				t.Errorf("AllowScan=%v: missing %q", tc.allow, want)
			}
		}
	}
}

// The instructions are what a client shows the model, so a read-only server has to say so —
// otherwise the model plans around a scan it can't run.
func TestInstructionsSayWhenScanningIsOff(t *testing.T) {
	if off := instructions(false); !strings.Contains(off, "not enabled") {
		t.Errorf("read-only instructions should say scanning is unavailable:\n%s", off)
	}
	if on := instructions(true); strings.Contains(on, "not enabled") {
		t.Errorf("scan-enabled instructions should not claim otherwise:\n%s", on)
	}
}

func TestNewServerRequiresARegistry(t *testing.T) {
	if _, err := NewServer(Options{}); err == nil {
		t.Error("want an error without a registry")
	}
}

func toolNames(t *testing.T, opts Options) map[string]bool {
	t.Helper()
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	sess, err := c.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = sess.Close() }()

	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	out := map[string]bool{}
	for _, tool := range res.Tools {
		if tool.Description == "" {
			t.Errorf("tool %q has no description; the model chooses tools by reading these", tool.Name)
		}
		out[tool.Name] = true
	}
	return out
}

func TestListControls(t *testing.T) {
	out := ListControls(builtins.Registry())
	if len(out.Controls) == 0 {
		t.Fatal("no controls")
	}
	byName := map[string]Control{}
	for _, c := range out.Controls {
		byName[c.Name] = c
		if c.Purpose == "" {
			t.Errorf("%s has no purpose; an agent picks controls by reading it", c.Name)
		}
	}
	sast, ok := byName["sast"]
	if !ok {
		t.Fatalf("no sast control in %v", byName)
	}
	if len(sast.DefaultScanners) == 0 {
		t.Error("sast should report its default scanners")
	}
	// gosec backs sast but isn't a default, so it must be reported as opt-in — an agent that
	// enables it as if it were a default writes a Saga that silently does nothing.
	if len(sast.OptInScanners) == 0 {
		t.Errorf("sast should report opt-in scanners, got %+v", sast)
	}
	if out.Hint == "" {
		t.Error("capability without a way to use it is half an answer")
	}
}

func TestGetSchemaReturnsTheEmbeddedSchema(t *testing.T) {
	out, err := GetSchema()
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if out.Schema["$schema"] == nil {
		t.Errorf("no $schema key; this should be a JSON Schema document: %v", out.Schema)
	}
	if out.Version == "" {
		t.Error("the schema must say which build it came from — that's the point of asking Draugr rather than the web")
	}
}

// misspelledKey is built rather than written so the spell checker doesn't flag the fixture;
// a typo'd field is exactly what this test needs the descriptor to contain.
var misspelledKey = "nm" + "ae"

func TestValidateSaga(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.saga.yaml")
	if err := os.WriteFile(good, []byte(
		"release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: api\n    repositories:\n      - url: .\nconfig:\n  controllers:\n    secrets:\n      enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, out, err := ValidateSagaTool(context.Background(), nil, ValidateInput{Path: good})
	if err != nil {
		t.Fatalf("valid descriptor returned an error: %v", err)
	}
	if !out.Valid {
		t.Fatalf("want valid, got %+v", out)
	}
	if len(out.Components) != 1 || out.Components[0] != "api" {
		t.Errorf("components = %v", out.Components)
	}
	if len(out.Controls) != 1 || out.Controls[0] != "secrets" {
		t.Errorf("controls = %v", out.Controls)
	}

	// A bad descriptor is an answer, not a tool failure — an error would tell the agent the
	// call went wrong rather than the file.
	_, bad, err := ValidateSagaTool(context.Background(), nil, ValidateInput{Content: "release:\n  " + misspelledKey + ": typo\n"})
	if err != nil {
		t.Fatalf("an invalid descriptor should not be a tool error: %v", err)
	}
	if bad.Valid || bad.Error == "" {
		t.Errorf("want invalid with a reason, got %+v", bad)
	}

	for _, in := range []ValidateInput{{}, {Path: "a", Content: "b"}} {
		if _, _, err := ValidateSagaTool(context.Background(), nil, in); err == nil {
			t.Errorf("%+v should be rejected", in)
		}
	}
}

func TestSummarizeRanksAndCaps(t *testing.T) {
	rep := sarif.Report{
		Results: []sarif.Result{
			{RuleID: "low", Level: sarif.LevelNote, Priority: "P4", Message: "meh"},
			{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Message: "bad",
				Location: sarif.Location{URI: "go.mod", StartLine: 3}, Score: 9.1, HasScore: true},
			{RuleID: "mid", Level: sarif.LevelWarning, Priority: "P2", Message: "meh"},
		},
	}
	out := summarize(rep, "", 0)
	if out.Total != 3 || out.Returned != 3 {
		t.Errorf("total/returned = %d/%d, want 3/3", out.Total, out.Returned)
	}
	if out.Findings[0].RuleID != "CVE-1" {
		t.Errorf("most urgent first: got %v", out.Findings[0])
	}
	if out.Findings[0].Location != "go.mod:3" {
		t.Errorf("location = %q, want go.mod:3", out.Findings[0].Location)
	}
	// The derived advisory link is how an agent finds out what a rule means without asking us.
	if out.Findings[0].HelpURI == "" {
		t.Error("a CVE should carry a help link")
	}

	// Filtering narrows the list, not the counts: the rest of the backlog didn't vanish.
	narrowed := summarize(rep, "p2", 0)
	if narrowed.Returned != 2 {
		t.Errorf("returned = %d, want 2", narrowed.Returned)
	}
	if narrowed.Total != 3 {
		t.Errorf("total = %d, want the whole report's 3", narrowed.Total)
	}

	// Truncation has to announce itself, or the agent reads a partial list as complete.
	capped := summarize(rep, "", 1)
	if len(capped.Findings) != 1 || capped.Note == "" {
		t.Errorf("capped = %+v, want 1 finding and a note", capped)
	}
}

// An unprioritized finding must survive a priority filter: dropping it would answer a different
// question than the one asked, and Sagas without classification are common.
func TestSummarizeKeepsUnprioritizedFindings(t *testing.T) {
	rep := sarif.Report{Results: []sarif.Result{{RuleID: "r", Level: sarif.LevelError, Message: "m"}}}
	if out := summarize(rep, "p1", 0); out.Returned != 1 {
		t.Errorf("returned = %d, want the unprioritized finding kept", out.Returned)
	}
}

func TestSummarizeReportToolReadsAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.sarif")
	data, err := sarif.Report{Tool: "trivy", Results: []sarif.Result{
		{RuleID: "CVE-1", Level: sarif.LevelError, Message: "bad"},
	}}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, err := SummarizeReportTool(context.Background(), nil, SummarizeInput{Path: path})
	if err != nil {
		t.Fatalf("SummarizeReportTool: %v", err)
	}
	if out.Total != 1 || out.Findings[0].RuleID != "CVE-1" {
		t.Errorf("out = %+v", out)
	}

	if _, _, err := SummarizeReportTool(context.Background(), nil, SummarizeInput{}); err == nil {
		t.Error("want an error without a path")
	}
	if _, _, err := SummarizeReportTool(context.Background(), nil, SummarizeInput{Path: filepath.Join(dir, "nope")}); err == nil {
		t.Error("want an error for a missing file")
	}
	// Pointing at the wrong artifact is an easy mistake; the error should say which one to use.
	bad := filepath.Join(dir, "report.json")
	if err := os.WriteFile(bad, []byte("not sarif"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = SummarizeReportTool(context.Background(), nil, SummarizeInput{Path: bad})
	if err == nil || !strings.Contains(err.Error(), "results.sarif") {
		t.Errorf("error should point at the right artifact, got %v", err)
	}
}

func TestScanToolRejectsAMissingPath(t *testing.T) {
	h := scanTool(builtins.Registry())
	if _, _, err := h(context.Background(), nil, ScanInput{}); err == nil {
		t.Error("want an error without a path")
	}
	if _, _, err := h(context.Background(), nil, ScanInput{Path: "does-not-exist.saga.yaml"}); err == nil {
		t.Error("want an error for an unloadable descriptor")
	}
}

// Exercise the registered handlers the way a client does — the wiring between a tool's
// declared schema and its handler is exactly what a unit test on the handler can't catch.
func TestToolsAnswerOverASession(t *testing.T) {
	ctx := context.Background()
	sess := connect(t, Options{Registry: builtins.Registry()})

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "list_controls"})
	if err != nil {
		t.Fatalf("list_controls: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_controls errored: %+v", res.Content)
	}
	var controls ControlsOutput
	decode(t, res, &controls)
	if len(controls.Controls) == 0 {
		t.Error("no controls came back")
	}

	res, err = sess.CallTool(ctx, &mcp.CallToolParams{Name: "get_saga_schema"})
	if err != nil {
		t.Fatalf("get_saga_schema: %v", err)
	}
	var schema SchemaOutput
	decode(t, res, &schema)
	if len(schema.Schema) == 0 {
		t.Error("no schema came back")
	}

	// A tool error must arrive as a tool error, not a transport failure: the model has to be
	// able to read it and correct itself.
	res, err = sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "summarize_report", Arguments: map[string]any{"path": ""},
	})
	if err != nil {
		t.Fatalf("a bad argument should not break the protocol: %v", err)
	}
	if !res.IsError {
		t.Error("want IsError for a missing path")
	}
}

// A Saga with no controls enabled exercises the whole scan path — load, run, evaluate, rank —
// without needing a scanner binary or a network.
func TestScanToolReturnsAVerdict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, err := scanTool(builtins.Registry())(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if out.Verdict != "pass" {
		t.Errorf("verdict = %q, want pass with nothing enabled", out.Verdict)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
}

func TestSortFindingsBreaksTies(t *testing.T) {
	fs := []Finding{
		{Priority: "P1", Severity: "high", Score: 7},
		{Priority: "P1", Severity: "high", Score: 9}, // same priority and severity, higher score
		{Priority: "P1", Severity: "critical"},       // same priority, worse severity
	}
	sortFindings(fs)
	if fs[0].Severity != "critical" {
		t.Errorf("severity should break a priority tie: %+v", fs)
	}
	if fs[1].Score != 9 {
		t.Errorf("score should break a severity tie: %+v", fs)
	}
}

func connect(t *testing.T, opts Options) *mcp.ClientSession {
	t.Helper()
	srv, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).
		Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func decode(t *testing.T, res *mcp.CallToolResult, into any) {
	t.Helper()
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %T: %v", into, err)
	}
}
