package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// The failure this guards against is a prompt that reads identically whatever it is asking about.
// A reader approving five read-only controls over a checkout learns nothing about having approved
// probing traffic at a live host, and the person answering is usually not the one who wrote the
// descriptor.
func TestDescribeScanNamesWhatThisDescriptorDoes(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"secrets": {"enabled": true},
			"sca":     {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "https://example.com/a.git"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "https://example.com/b.git"}}},
		},
	}
	got := describeScan(builtins.Registry(), model, "app.saga.yaml")
	for _, want := range []string{"app.saga.yaml", "sca", "secrets", "2 components"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt should contain %q:\n%s", want, got)
		}
	}
	// Nothing here touches a live service, so nothing should claim to.
	if strings.Contains(got, "live service") {
		t.Errorf("a repository scan should not warn about live traffic:\n%s", got)
	}
}

func TestDescribeScanSaysWhenItWillProbeALiveHost(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{
			Controllers: map[string]saga.ControllerSettings{"dast": {"enabled": true}},
			AllowEffects: []string{
				string("network"),
			},
		},
		Components: []saga.Component{
			{Name: "api", Hosts: []saga.Host{{URL: "https://api.example.com"}}},
		},
	}
	got := describeScan(builtins.Registry(), model, "app.saga.yaml")
	if !strings.Contains(got, "live service") {
		t.Errorf("a dast scan must say it sends traffic:\n%s", got)
	}
	if !strings.Contains(got, "nuclei") {
		t.Errorf("the prompt should name the scanner doing it:\n%s", got)
	}
	if !strings.Contains(got, "authorized") {
		t.Errorf("probing a host you do not own is unlawful in many places; say so:\n%s", got)
	}
}

// Delivery is an effect on the user's machine and on third parties. Approving a scan is not
// approving an upload, so the prompt has to name what will be delivered and where.
func TestDescribeScanNamesWhereResultsGo(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{
			Controllers: map[string]saga.ControllerSettings{"secrets": {"enabled": true}},
			Publishers: []saga.PublisherConfig{
				{Kind: "file", Dir: "out/reports"},
				{Kind: "github", Repo: "acme/app"},
			},
		},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "https://example.com/a.git"}}},
		},
	}
	got := describeScan(builtins.Registry(), model, "app.saga.yaml")
	for _, want := range []string{"delivered to", "file: out/reports", "github: acme/app"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt should contain %q:\n%s", want, got)
		}
	}
}

// A descriptor that would examine nothing says so, rather than describing a scan that is not
// going to happen.
func TestDescribeScanSaysWhenNothingIsEnabled(t *testing.T) {
	model := &saga.Model{Components: []saga.Component{{Name: "api"}}}
	got := describeScan(builtins.Registry(), model, "app.saga.yaml")
	if !strings.Contains(got, "examine nothing") {
		t.Errorf("an empty plan should say so:\n%s", got)
	}
}

// The point of the delivered list: a caller that knows a file exists can read it back with
// summarize_report instead of paying for another scan.
func TestScanDeliversTheDescriptorsPublishers(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "reports")
	path := filepath.Join(dir, "published.saga.yaml")
	// No control enabled, so this needs no scanner binary and no network — the publisher still
	// has a complete run to render, which is the part under test.
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1.0\"\n"+
			"config:\n  reports:\n    - format: sarif\n  publishers:\n    - kind: file\n      dir: "+out+"\n"+
			"components:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, res, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Delivered) != 1 || !strings.Contains(res.Delivered[0], out) {
		t.Errorf("delivered = %v, want the file publisher's directory", res.Delivered)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("the publisher wrote nothing: %v", err)
	}
	if len(entries) == 0 {
		t.Error("the publisher's directory is empty")
	}
}

// A descriptor with no publishers must not invent a destination.
func TestScanReportsNoDeliveryWhenNoneIsConfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, res, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Delivered) != 0 {
		t.Errorf("delivered = %v, want none", res.Delivered)
	}
}
