package publish

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func sampleData() report.Data {
	run := engine.Result{Controls: map[string]plugin.ControlResult{
		"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy"},
		}}},
	}}
	verdict := norn.Result{Verdict: norn.Fail}
	return report.Data{Release: saga.Release{Name: "app", Version: "1.0"}, Run: run, Verdict: verdict}
}

func TestForKnownAndUnknown(t *testing.T) {
	if _, err := For(saga.PublisherConfig{Kind: "file", Dir: "x"}); err != nil {
		t.Errorf("file publisher should resolve: %v", err)
	}
	if _, err := For(saga.PublisherConfig{Kind: "bogus"}); err == nil {
		t.Error("expected error for unknown kind")
	}
}

func TestFilePublisherRequiresDir(t *testing.T) {
	if _, err := For(saga.PublisherConfig{Kind: "file"}); err == nil {
		t.Error("file publisher without dir should error")
	}
}

func TestKinds(t *testing.T) {
	got := Kinds()
	if len(got) != 2 || got[0] != "file" || got[1] != "github" {
		t.Errorf("Kinds() = %v", got)
	}
}

func TestRunWritesReports(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}, {Format: "sarif"}, {Format: "markdown"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.json", "results.sarif", "report.md"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to be written: %v", f, err)
		}
	}
}

func TestRunNoPublishersIsNoop(t *testing.T) {
	if err := Run(context.Background(), []saga.ReportConfig{{Format: "json"}}, nil, sampleData()); err != nil {
		t.Errorf("no publishers should be a no-op, got %v", err)
	}
}

func TestRunUnknownFormatErrors(t *testing.T) {
	dir := t.TempDir()
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "bogus"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: dir}},
		sampleData(),
	)
	if err == nil {
		t.Error("expected error for unknown report format")
	}
}

func TestRunUnknownPublisherErrors(t *testing.T) {
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}},
		[]saga.PublisherConfig{{Kind: "bogus"}},
		sampleData(),
	)
	if err == nil {
		t.Error("expected error for unknown publisher kind")
	}
}

func TestRunPublisherErrorSurfaced(t *testing.T) {
	// A file publisher pointed at a path that can't be created surfaces an error.
	bad := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(),
		[]saga.ReportConfig{{Format: "json"}},
		[]saga.PublisherConfig{{Kind: "file", Dir: filepath.Join(bad, "sub")}}, // parent is a file
		sampleData(),
	)
	if err == nil {
		t.Error("expected a publish error when the output dir can't be created")
	}
}
