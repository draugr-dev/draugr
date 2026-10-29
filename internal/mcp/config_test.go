package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// writeDescriptor puts body in a temporary directory and returns its path.
func writeDescriptor(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// enabling is a loader whose configuration sets one key under a control, as a controller default
// in draugr.config.yaml does.
func enabling(control, key string, value any) ConfigLoader {
	return func(_ context.Context, m *saga.Model) error {
		if m.Config.Controls == nil {
			m.Config.Controls = map[string]saga.ControllerSettings{}
		}
		settings := saga.ControllerSettings{}
		for k, v := range m.Config.Controls[control] {
			settings[k] = v
		}
		settings[key] = value
		m.Config.Controls[control] = settings
		return nil
	}
}

// Semgrep selected for sast by its block, SBOM off, two components scoped by paths.
const semgrepTwoServices = `project: shop
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

func toolNamesOf(out CheckToolsOutput) []string {
	var names []string
	for _, tl := range out.Tools {
		names = append(names, tl.Name)
	}
	return names
}

// check_tools requires what a scan of the descriptor runs. gosec can serve sast and syft is in the
// catalog; this descriptor selects neither, and a machine without them is ready.
func TestCheckToolsRequiresWhatTheScanRuns(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, out, err := checkToolsTool(builtins.Registry(), nil)(context.Background(), nil,
		CheckToolsInput{Path: writeDescriptor(t, semgrepTwoServices)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "gitleaks", "semgrep"}
	if got := toolNamesOf(out); !slices.Equal(got, want) {
		t.Errorf("tools = %v, want %v", got, want)
	}
	if !slices.Equal(out.Missing, want) {
		t.Errorf("missing = %v, want %v", out.Missing, want)
	}
	if out.Remedy != "draugr tools install git gitleaks semgrep" {
		t.Errorf("remedy = %q", out.Remedy)
	}
}

// A scanner the configuration selects is required, because the scan that reads the same
// configuration runs it.
func TestCheckToolsReadsTheConfiguration(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, out, err := checkToolsTool(builtins.Registry(), enabling("sast", "gosec", map[string]any{"enabled": true}))(
		context.Background(), nil, CheckToolsInput{Path: writeDescriptor(t, semgrepTwoServices)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(out.Missing, "gosec") {
		t.Errorf("the configuration selects gosec, and check_tools does not require it: %v", out.Missing)
	}
}

// A configuration the loader refuses stops both tools, with the loader's own words, before either
// detects a tool or plans a scan.
func TestAConfigurationTheLoaderRefusesStopsBothTools(t *testing.T) {
	refused := errors.New("draugr.config.yaml: controllers: \"imagez\" is not a control")
	loader := func(context.Context, *saga.Model) error { return refused }
	path := writeDescriptor(t, semgrepTwoServices)

	if _, _, err := checkToolsTool(builtins.Registry(), loader)(context.Background(), nil,
		CheckToolsInput{Path: path}); !errors.Is(err, refused) {
		t.Errorf("check_tools: err = %v, want the loader's", err)
	}
	if _, _, err := scanTool(builtins.Registry(), ScanAlways, loader)(context.Background(), nil,
		ScanInput{Path: path}); !errors.Is(err, refused) {
		t.Errorf("scan: err = %v, want the loader's", err)
	}
}

// A host-only descriptor with no control enabled.
const hostOnly = `project: shop
components:
  - name: api
    hosts:
      - url: https://staging.shop.example
`

// The configuration is merged before the scan is planned, so a control it enables is part of what
// the approval describes. Here it enables one whose scanner tells a third party about the host, and
// with nobody to ask the scan stops rather than running it unapproved.
func TestTheConfigurationIsPlannedBeforeConsent(t *testing.T) {
	path := writeDescriptor(t, hostOnly)
	if _, out, err := scanTool(builtins.Registry(), ScanEffects, nil)(context.Background(), nil,
		ScanInput{Path: path}); err != nil || out.Verdict != "pass" {
		t.Fatalf("without configuration nothing is enabled: verdict %q, err %v", out.Verdict, err)
	}
	_, _, err := scanTool(builtins.Registry(), ScanEffects, enabling("threats", "enabled", true))(
		context.Background(), nil, ScanInput{Path: path})
	if err == nil || !strings.Contains(err.Error(), "needs approval") {
		t.Errorf("a control the configuration enables ran without the approval it needs: %v", err)
	}
}

// The hint names the key a descriptor holds today.
func TestListControlsHintNamesTheCurrentKey(t *testing.T) {
	out := ListControls(builtins.Registry())
	if !strings.Contains(out.Hint, "config.controls.<control>.<scanner>.enabled") {
		t.Errorf("hint = %q, want config.controls.<control>.<scanner>.enabled", out.Hint)
	}
	if strings.Contains(strings.ReplaceAll(out.Hint, "config.controls", ""), "controllers.") {
		t.Errorf("hint names the deprecated controllers key: %q", out.Hint)
	}
}
