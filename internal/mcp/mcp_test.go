package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
		mode     ScanMode
		wantScan bool
	}{{ScanOff, false}, {ScanAsk, true}, {ScanAlways, true}, {"", false}} {
		names := toolNames(t, Options{Registry: builtins.Registry(), Scan: tc.mode, Root: t.TempDir()})
		if got := names["scan"]; got != tc.wantScan {
			t.Errorf("scan=%q: exposed=%v, want %v (tools: %v)", tc.mode, got, tc.wantScan, names)
		}
		// The read-only tools are always there.
		for _, want := range []string{"list_controls", "get_saga_schema", "validate_saga", "summarize_report"} {
			if !names[want] {
				t.Errorf("scan=%q: missing %q", tc.mode, want)
			}
		}
	}
}

// The instructions are what a client shows the model, so a read-only server has to say so —
// otherwise the model plans around a scan it can't run.
func TestInstructionsDescribeTheScanMode(t *testing.T) {
	if off := instructions(ScanOff); !strings.Contains(off, "not enabled") {
		t.Errorf("read-only instructions should say scanning is unavailable:\n%s", off)
	}
	if ask := instructions(ScanAsk); !strings.Contains(ask, "approve") {
		t.Errorf("ask mode should warn that each call is approved:\n%s", ask)
	}
	if always := instructions(ScanAlways); strings.Contains(always, "not enabled") ||
		strings.Contains(always, "approve") {
		t.Errorf("always mode should promise neither:\n%s", always)
	}
}

func TestParseScanMode(t *testing.T) {
	for in, want := range map[string]ScanMode{"": ScanOff, "off": ScanOff, "ask": ScanAsk, "always": ScanAlways} {
		got, err := ParseScanMode(in)
		if err != nil || got != want {
			t.Errorf("ParseScanMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseScanMode("yes"); err == nil {
		t.Error("want an error for an unknown mode")
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
	h := scanTool(builtins.Registry(), ScanAlways)
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
	sess := connect(t, Options{Registry: builtins.Registry(), Root: t.TempDir()})

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
	_, out, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
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

// The failure this guards against is not a wrong verdict — it is a right one being read as the
// answer to a broader question than Draugr asked. A component declaring an image with the images
// control off passes, and the pass must arrive saying so.
func TestScanToolSaysWhatItDidNotLookAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uncovered.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1.0\"\ncomponents:\n"+
			"  - name: api\n    images:\n      - image: registry.example.com/api:1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if out.Verdict != "pass" {
		t.Fatalf("verdict = %q, want pass with nothing enabled", out.Verdict)
	}
	want := []string{"api declares images, and images is not enabled"}
	if !slices.Equal(out.Uncovered, want) {
		t.Errorf("uncovered = %q, want %q", out.Uncovered, want)
	}
	if out.Unexamined == "" {
		t.Error("a verdict with no statement of its own boundary is the whole defect")
	}
	if out.Controls == nil {
		t.Error("controls must be present even when empty, so the caller sees the scope was none")
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

// In ask mode a scan must not happen unless the user agreed. Fail closed, and say how to
// proceed — a client that can't prompt is common, and "unsupported" alone helps nobody.
func TestAskModeRefusesWithoutApproval(t *testing.T) {
	// A readable descriptor, because the prompt is built from one: a missing file would fail on
	// the load and never reach the consent path this test is about.
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := scanTool(builtins.Registry(), ScanAsk)
	_, _, err := h(context.Background(), nil, ScanInput{Path: path})
	if err == nil {
		t.Fatal("want a refusal when there's no session to ask through")
	}
	if !strings.Contains(err.Error(), "--scan=always") {
		t.Errorf("the refusal should name the way forward, got: %v", err)
	}
	// A client that never declared elicitation support gets a message naming its own limitation.
	req := &mcp.CallToolRequest{}
	if _, _, err := h(context.Background(), req, ScanInput{Path: path}); err == nil {
		t.Error("want a refusal without a session")
	}
	// Always mode doesn't consult anyone, so it gets past consent and fails on the descriptor.
	_, _, err = scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil,
		ScanInput{Path: "does-not-exist.saga.yaml"})
	if err == nil || strings.Contains(err.Error(), "approval") {
		t.Errorf("always mode should not ask for approval, got: %v", err)
	}
}

func TestSagaDescriptorsAreExposedAsResources(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("release:\n  name: app\n  version: \"1.0\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("draugr.saga.yaml")
	write("services/api/azure.saga.yaml")
	write("node_modules/pkg/other.saga.yaml") // dependency tree: not ours
	write("README.md")

	sess := connect(t, Options{Registry: builtins.Registry(), Root: root})
	res, err := sess.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	names := map[string]string{}
	for _, r := range res.Resources {
		names[r.Name] = r.URI
		if r.Description == "" {
			t.Errorf("%s has no description; that's what tells the model to read it", r.Name)
		}
	}
	if _, ok := names["draugr.saga.yaml"]; !ok {
		t.Errorf("top-level descriptor missing: %v", names)
	}
	if _, ok := names["services/api/azure.saga.yaml"]; !ok {
		t.Errorf("nested descriptor missing: %v", names)
	}
	if _, ok := names["node_modules/pkg/other.saga.yaml"]; ok {
		t.Errorf("a dependency's descriptor is not ours to advertise: %v", names)
	}
	if len(names) != 2 {
		t.Errorf("resources = %v, want exactly the two descriptors", names)
	}

	// And it reads back.
	read, err := sess.ReadResource(context.Background(),
		&mcp.ReadResourceParams{URI: names["draugr.saga.yaml"]})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(read.Contents) != 1 || !strings.Contains(read.Contents[0].Text, "release:") {
		t.Errorf("contents = %+v", read.Contents)
	}
	if read.Contents[0].MIMEType != "application/yaml" {
		t.Errorf("mime = %q", read.Contents[0].MIMEType)
	}
}

// Discovery is bounded: descriptors live near the top of a repo, and walking a monorepo to find
// one costs more than it returns.
func TestDiscoveryStopsAtDepth(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "deep.saga.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := findSagas(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("found %v, want nothing that deep", found)
	}
}

// The approval round trip, against a client that actually answers. Accept runs the scan;
// decline must not.
func TestAskModeHonoursTheAnswer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.saga.yaml")
	// No control enabled, so the handshake is exercised without a scanner binary or a network.
	// What the prompt says about a real descriptor is TestDescribeScan's job.
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		action  string
		wantErr bool
	}{{"accept", false}, {"decline", true}, {"cancel", true}} {
		t.Run(tc.action, func(t *testing.T) {
			var asked string
			var sent *mcp.ElicitParams
			sess := connectWith(t,
				Options{Registry: builtins.Registry(), Scan: ScanAsk, Root: dir},
				&mcp.ClientOptions{
					ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
						asked = req.Params.Message
						// Captured, not asserted here: this runs on the client's goroutine, and
						// a t.Fatal on it kills that goroutine mid-RPC, so the call never gets
						// an answer and the test deadlocks instead of failing.
						sent = req.Params
						return &mcp.ElicitResult{Action: tc.action}, nil
					},
				})
			res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "scan", Arguments: map[string]any{"path": path},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if res.IsError != tc.wantErr {
				t.Errorf("action %q: IsError=%v, want %v (%+v)", tc.action, res.IsError, tc.wantErr, res.Content)
			}
			assertWellFormedElicit(t, sent)
			// The user has to be told what they're agreeing to, and this descriptor's honest
			// answer is that it would examine nothing.
			for _, want := range []string{path, "examine nothing"} {
				if !strings.Contains(asked, want) {
					t.Errorf("prompt should contain %q, got %q", want, asked)
				}
			}
		})
	}
}

// An unreadable directory shouldn't stop the server starting; it should just find less.
func TestDiscoverySurvivesAnUnreadableDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "draugr.saga.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil { //nolint:gosec // unreadable on purpose: that's the case under test
		t.Fatal(err)
	}
	// Restore a mode the test framework can remove.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) }) //nolint:gosec // a directory needs the execute bit

	found, err := findSagas(root)
	if err != nil {
		t.Fatalf("discovery should not fail on an unreadable directory: %v", err)
	}
	if len(found) != 1 {
		t.Errorf("found %v, want the readable descriptor", found)
	}
}

// A descriptor that vanishes between discovery and a read is a read error, not a crash.
func TestReadingAVanishedDescriptorErrors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sess := connect(t, Options{Registry: builtins.Registry(), Root: root})
	list, err := sess.ListResources(context.Background(), nil)
	if err != nil || len(list.Resources) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.ReadResource(context.Background(),
		&mcp.ReadResourceParams{URI: list.Resources[0].URI}); err == nil {
		t.Error("want an error reading a file that's gone")
	}
}

func connectWith(t *testing.T, opts Options, copts *mcp.ClientOptions) *mcp.ClientSession {
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
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, copts).
		Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func TestCheckToolsIsAlwaysAvailable(t *testing.T) {
	// Diagnosing the machine is read-only, so it's offered regardless of the scan mode — an
	// assistant on a read-only server still needs to explain why a scan would fail.
	for _, mode := range []ScanMode{ScanOff, ScanAsk, ScanAlways} {
		if !toolNames(t, Options{Registry: builtins.Registry(), Scan: mode, Root: t.TempDir()})["check_tools"] {
			t.Errorf("scan=%q: check_tools missing", mode)
		}
	}
}

// The point of the tool: name what's missing and what fixes it, without doing the fixing.
func TestCheckToolsReportsWhatIsMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1\"\ncomponents:\n  - name: c\n    repositories:\n"+
			"      - url: .\nconfig:\n  controllers:\n    sca:\n      enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An empty PATH makes every scanner missing, which is the case worth getting right.
	t.Setenv("PATH", dir)

	_, out, err := CheckToolsTool(context.Background(), nil, CheckToolsInput{Path: path})
	if err != nil {
		t.Fatalf("CheckToolsTool: %v", err)
	}
	if out.Ready {
		t.Error("nothing is installed; ready should be false")
	}
	if len(out.Missing) == 0 {
		t.Fatal("want the missing tools named")
	}
	// The remedy has to be a command someone can run, not a description of one.
	if !strings.HasPrefix(out.Remedy, "draugr tools install ") {
		t.Errorf("remedy = %q, want a runnable command", out.Remedy)
	}
	// Scoped to the descriptor: a Saga enabling only sca shouldn't demand semgrep.
	for _, tool := range out.Tools {
		if tool.Name == "semgrep" {
			t.Errorf("sca-only Saga should not require semgrep: %+v", out.Tools)
		}
	}
	// It must say it won't install, or an assistant will try to make it.
	if !strings.Contains(out.Note, "will not install") {
		t.Errorf("note should say Draugr won't install for you: %q", out.Note)
	}
}

// A missing *optional* tool is not a problem and must not be reported as one.
func TestCheckToolsIgnoresOptionalTools(t *testing.T) {
	_, out, err := CheckToolsTool(context.Background(), nil, CheckToolsInput{})
	if err != nil {
		t.Fatalf("CheckToolsTool: %v", err)
	}
	for _, tool := range out.Tools {
		if tool.Optional && !tool.Installed {
			for _, m := range out.Missing {
				if m == tool.Name {
					t.Errorf("optional tool %q listed as missing", tool.Name)
				}
			}
		}
	}
}

func TestServerAdvertisesItsIcon(t *testing.T) {
	srv, err := NewServer(Options{Registry: builtins.Registry(), Root: t.TempDir()})
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
	defer func() { _ = sess.Close() }()

	info := sess.InitializeResult().ServerInfo
	if len(info.Icons) != 1 {
		t.Fatalf("want exactly one icon, got %d", len(info.Icons))
	}
	icon := info.Icons[0]
	if icon.Source != iconURL {
		t.Errorf("icon source = %q, want %q", icon.Source, iconURL)
	}
	// A client is only required to render png and jpeg, so an svg-only icon would show up in
	// some clients and not others. Declaring the type keeps that decision explicit.
	if icon.MIMEType != "image/png" {
		t.Errorf("icon mime type = %q, want image/png", icon.MIMEType)
	}
	// Clients are told to check an icon is served from the same origin as the server. The
	// dev.draugr namespace authenticates against draugr.dev, so anywhere else fails that check.
	if !strings.HasPrefix(icon.Source, "https://draugr.dev/") {
		t.Errorf("icon must be served from draugr.dev over https, got %q", icon.Source)
	}
}

// assertWellFormedElicit checks the request we send, not only the reply we get back.
//
// The Go SDK's client allows a nil schema and returns early, so the in-memory transport these
// tests use accepts a request the protocol does not — and a handler that answers without reading
// the question cannot tell the difference. That gap shipped --scan=ask in a state where the
// approval never reached the user: the client rejected the request as malformed, and the mode
// was unusable from the documentation's first example.
func assertWellFormedElicit(t *testing.T, p *mcp.ElicitParams) {
	t.Helper()
	if p == nil {
		t.Fatal("no elicitation was sent")
	}
	if p.Mode != "form" {
		t.Errorf("mode = %q, want %q — inference is not something to rely on across clients", p.Mode, "form")
	}
	if p.RequestedSchema == nil {
		t.Fatal("requestedSchema is nil — it has no omitempty, so this reaches the client as " +
			"`\"requestedSchema\": null` and a spec-conformant client rejects the request")
	}
	// Round-trip it the way the wire does, so the assertion is about what is sent.
	raw, err := json.Marshal(p.RequestedSchema)
	if err != nil {
		t.Fatalf("marshal requestedSchema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("requestedSchema is not a JSON object: %v", err)
	}
	if schema["type"] != "object" {
		t.Errorf("requestedSchema.type = %v, want \"object\" — the spec allows no other root", schema["type"])
	}
	if _, ok := schema["properties"]; !ok {
		t.Error("requestedSchema has no properties key; an empty object is how \"nothing to fill in\" is said")
	}
}

// The consent question is asked by returning it, not by blocking on it: protocol 2026-07-28
// forbids a server sending `elicitation/create` while it is serving a request. What must not
// change is that the failure of consent is never a scan.
func TestConsentAsksByReturningTheQuestion(t *testing.T) {
	t.Parallel()

	// Unanswered: the call ends with the question rather than a result.
	ask, err := consent(&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{}}, "app.saga.yaml", "may I scan?")
	if err != nil {
		t.Fatalf("an unanswered call should return the question, not an error: %v", err)
	}
	if ask == nil {
		t.Fatal("no question was returned, so nothing would ever ask")
	}
	req, ok := ask.InputRequests[consentRequestID]
	if !ok {
		t.Fatalf("the question is not under the id the client echoes back: %v", ask.InputRequests)
	}
	elicit, ok := req.(*mcp.ElicitParams)
	if !ok {
		t.Fatalf("the question is a %T, which no client will render as a prompt", req)
	}
	if elicit.Message != "may I scan?" {
		t.Errorf("the description did not travel with the question: %q", elicit.Message)
	}
	// Not optional even though it asks for nothing: an absent schema serialises as null, and a
	// client holding to the spec rejects the request.
	if elicit.RequestedSchema == nil {
		t.Error("a null requestedSchema is rejected by a conforming client")
	}
	// Content alongside input requests is a server bug the SDK rejects outright.
	if len(ask.Content) != 0 {
		t.Errorf("a question must carry no content, got %d", len(ask.Content))
	}

	// Answered.
	for _, tc := range []struct {
		name    string
		answer  mcp.InputResponse
		wantErr string
	}{
		{"accepted", &mcp.ElicitResult{Action: "accept"}, ""},
		{"declined", &mcp.ElicitResult{Action: "decline"}, "declined"},
		{"cancelled", &mcp.ElicitResult{Action: "cancel"}, "declined"},
		// An answer of a shape Draugr cannot read is not a yes. Treating it as one would turn a
		// protocol mismatch into an unapproved scan.
		// A response of a shape Draugr has no meaning for: the client answered a different
		// question, or the protocol grew one this build predates. Any non-elicitation response
		// serves, and every one of them is deprecated — SEP-2577 retired roots and sampling, so
		// an elicitation is currently the only live kind. The deprecation is the reason this
		// type is here, not a reason to stop testing the case: an answer Draugr cannot read must
		// never be taken for a yes.
		//nolint:staticcheck // deliberately a deprecated response; the point is that it is not an *ElicitResult
		{"unreadable", &mcp.CreateMessageWithToolsResult{}, "does not understand"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := consent(&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
				InputResponses: mcp.InputResponseMap{consentRequestID: tc.answer},
			}}, "app.saga.yaml", "may I scan?")
			switch {
			case tc.wantErr == "":
				if err != nil || res != nil {
					t.Errorf("an accepted scan should proceed, got res=%v err=%v", res, err)
				}
			case err == nil:
				t.Errorf("want a refusal containing %q, got res=%v", tc.wantErr, res)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
