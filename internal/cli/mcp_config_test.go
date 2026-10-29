package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	draugrmcp "github.com/draugr-dev/draugr/internal/mcp"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// servedSession connects a client to the server `draugr mcp` serves, over reg.
func servedSession(t *testing.T, mode draugrmcp.ScanMode, reg *engine.Registry) *mcp.ClientSession {
	t.Helper()
	opts := mcpOptions(mode)
	if reg != nil {
		opts.Registry = reg
	}
	opts.Root = t.TempDir()
	srv, err := draugrmcp.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatal(err)
	}
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// callTool calls one tool and returns its structured result, or the error text when it failed.
func callTool(t *testing.T, sess *mcp.ClientSession, name string, args map[string]any, into any) string {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		return res.Content[0].(*mcp.TextContent).Text
	}
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
	return ""
}

// projectDir makes a fresh working directory holding the project's draugr.config.yaml, or none
// when body is empty, with no home configuration under it.
func projectDir(t *testing.T, body string) string {
	t.Helper()
	configHome(t, "")
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	return dir
}

// Two components declaring images, with the images control left to the configuration.
const sagaImagesFromConfig = `project: app
release:
  version: "1.0"
components:
  - name: api
    images:
      - image: repo/api:1
  - name: worker
    images:
      - image: repo/worker:1
`

// The configuration in the working directory enables a control the descriptor does not, and both
// scans run it over both components and fail the same gate on what it finds. An assistant's scan
// that ignored the file would pass where `draugr scan` in the same directory fails.
func TestAnMCPScanReadsTheConfigurationDraugrScanReads(t *testing.T) {
	projectDir(t, "controllers:\n  images:\n    enabled: true\n")
	reg := fakeRegistry(sarif.LevelError)
	path := writeSaga(t, sagaImagesFromConfig)

	var buf bytes.Buffer
	cliErr := runScan(context.Background(), path,
		scanOptions{failOn: "error", format: "json", setFlags: map[string]bool{}}, reg, &buf)
	if cliErr == nil || !strings.Contains(cliErr.Error(), "verdict: fail") {
		t.Fatalf("draugr scan should fail its gate on the configured control: %v", cliErr)
	}

	var out draugrmcp.ScanOutput
	if msg := callTool(t, servedSession(t, draugrmcp.ScanAlways, reg), "scan",
		map[string]any{"path": path}, &out); msg != "" {
		t.Fatalf("scan: %s", msg)
	}
	if out.Verdict != "fail" {
		t.Errorf("verdict = %q, want fail, as draugr scan in this directory", out.Verdict)
	}
	if !slices.Equal(out.Controls, []string{"images"}) {
		t.Errorf("controls = %v, want the one the configuration enables", out.Controls)
	}
	var where []string
	for _, f := range out.Findings {
		where = append(where, f.Location)
	}
	sort.Strings(where)
	if !slices.Equal(where, []string{"api", "worker"}) {
		t.Errorf("findings in %v, want one in each component", where)
	}
}

// Without the file the same descriptor enables nothing, which is what makes the test above a test
// of the file.
func TestAnMCPScanWithoutConfigurationRunsWhatTheDescriptorSays(t *testing.T) {
	projectDir(t, "")
	var out draugrmcp.ScanOutput
	if msg := callTool(t, servedSession(t, draugrmcp.ScanAlways, fakeRegistry(sarif.LevelError)), "scan",
		map[string]any{"path": writeSaga(t, sagaImagesFromConfig)}, &out); msg != "" {
		t.Fatalf("scan: %s", msg)
	}
	if out.Verdict != "pass" || len(out.Controls) != 0 {
		t.Errorf("verdict %q over %v, want a pass over no controls", out.Verdict, out.Controls)
	}
}

// A configuration file `draugr scan` refuses is refused by the assistant's scan, in the same words,
// before anything runs.
func TestAnMCPScanRefusesTheConfigurationDraugrScanRefuses(t *testing.T) {
	projectDir(t, "controllers:\n  imagez:\n    enabled: true\n")
	reg := fakeRegistry(sarif.LevelError)
	path := writeSaga(t, sagaImagesFromConfig)

	cliErr := runScan(context.Background(), path,
		scanOptions{format: "json", setFlags: map[string]bool{}}, reg, &bytes.Buffer{})
	if cliErr == nil {
		t.Fatal("draugr scan accepted a configuration naming a control that does not exist")
	}
	var out draugrmcp.ScanOutput
	msg := callTool(t, servedSession(t, draugrmcp.ScanAlways, reg), "scan", map[string]any{"path": path}, &out)
	if msg != cliErr.Error() {
		t.Errorf("the MCP scan said\n  %q\ndraugr scan said\n  %q", msg, cliErr.Error())
	}
	if !strings.Contains(msg, config.FileName) || !strings.Contains(msg, `"imagez"`) {
		t.Errorf("the refusal does not name the file and the key: %s", msg)
	}
}

// sagaSemgrepTwoServices selects semgrep for sast by its block and leaves SBOM off, over two
// components scoped by paths. gosec can serve sast and syft is in the catalog, and a scan of this
// descriptor runs neither.
const sagaSemgrepTwoServices = `project: shop
config:
  controls:
    secrets:
      enabled: true
    sast:
      enabled: true
      semgrep:
        config: rules.yaml
components:
  - name: api
    repositories:
      - url: .
        paths: [services/api]
  - name: web
    repositories:
      - url: .
        paths: [services/web]
`

// toolsReport is what doctor --json and check_tools each say about one machine.
type toolsReport struct{ listed, missing []string }

// doctorSays runs doctor over path on this machine, as `draugr doctor --json` does.
func doctorSays(t *testing.T, path string) toolsReport {
	t.Helper()
	var buf bytes.Buffer
	detect := func(ctx context.Context, tl tools.Tool) tools.Status { return tools.Detect(ctx, tl, nil, nil) }
	_ = runDoctor(context.Background(), &buf, builtins.Registry(), path, doctorRun{json: true}, detect, nil)
	var doc struct {
		Tools []struct {
			Binary string `json:"binary"`
			Found  bool   `json:"found"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	var r toolsReport
	for _, tl := range doc.Tools {
		r.listed = append(r.listed, tl.Binary)
		if !tl.Found {
			r.missing = append(r.missing, tl.Binary)
		}
	}
	return r
}

// checkToolsSays asks the served check_tools the same question.
func checkToolsSays(t *testing.T, path string) toolsReport {
	t.Helper()
	var out draugrmcp.CheckToolsOutput
	if msg := callTool(t, servedSession(t, draugrmcp.ScanOff, nil), "check_tools",
		map[string]any{"path": path}, &out); msg != "" {
		t.Fatalf("check_tools: %s", msg)
	}
	var r toolsReport
	for _, tl := range out.Tools {
		r.listed = append(r.listed, tl.Name)
	}
	r.missing = out.Missing
	return r
}

// check_tools and doctor answer "is this machine ready for this descriptor" from one function, so
// on a machine with nothing installed they name the same tools as required and the same as
// missing, and neither names a scanner the descriptor did not select.
func TestCheckToolsAndDoctorAgree(t *testing.T) {
	projectDir(t, "")
	t.Setenv("PATH", t.TempDir())
	path := writeSaga(t, sagaSemgrepTwoServices)

	doctor, served := doctorSays(t, path), checkToolsSays(t, path)
	want := []string{"git", "gitleaks", "semgrep"}
	if !slices.Equal(doctor.listed, want) || !slices.Equal(served.listed, want) {
		t.Errorf("required tools: doctor %v, check_tools %v, want %v", doctor.listed, served.listed, want)
	}
	if !slices.Equal(doctor.missing, served.missing) {
		t.Errorf("missing: doctor %v, check_tools %v", doctor.missing, served.missing)
	}
}

// A controller default in draugr.config.yaml that selects a scanner makes its tool required for
// both, because the scan it describes would run it.
func TestCheckToolsAndDoctorReadTheConfiguration(t *testing.T) {
	projectDir(t, "controllers:\n  sast:\n    gosec:\n      enabled: true\n")
	t.Setenv("PATH", t.TempDir())
	path := writeSaga(t, sagaSemgrepTwoServices)

	doctor, served := doctorSays(t, path), checkToolsSays(t, path)
	if !slices.Contains(doctor.missing, "gosec") || !slices.Contains(served.missing, "gosec") {
		t.Errorf("the configuration selects gosec: doctor %v, check_tools %v", doctor.missing, served.missing)
	}
	if !slices.Equal(doctor.listed, served.listed) {
		t.Errorf("required tools: doctor %v, check_tools %v", doctor.listed, served.listed)
	}
}
