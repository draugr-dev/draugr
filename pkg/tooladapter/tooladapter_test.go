package tooladapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const sampleSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy"}},` +
	`"results":[{"ruleId":"CVE-1","level":"error","message":{"text":"boom"}}]}]}`

func imageArgv(_ plugin.Target, _ plugin.Config) ([]string, error) {
	return []string{"trivy", "image", "x"}, nil
}

func TestScanWithInjectedRunner(t *testing.T) {
	a := New(Config{
		Name: "trivy",
		Argv: imageArgv,
		Run: func(_ context.Context, _ []string) ([]byte, error) {
			return []byte(sampleSARIF), nil
		},
	})
	rep, err := a.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "CVE-1" {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if rep.Results[0].Tool != "trivy" {
		t.Errorf("tool should be backfilled, got %q", rep.Results[0].Tool)
	}
}

func TestScanArgvError(t *testing.T) {
	a := New(Config{Name: "x", Argv: func(plugin.Target, plugin.Config) ([]string, error) {
		return nil, errors.New("bad target")
	}})
	if _, err := a.Scan(context.Background(), plugin.ImageTarget{}, nil); err == nil {
		t.Fatal("expected argv error")
	}
}

func TestScanEmptyArgv(t *testing.T) {
	a := New(Config{Name: "x", Argv: func(plugin.Target, plugin.Config) ([]string, error) {
		return nil, nil
	}})
	if _, err := a.Scan(context.Background(), plugin.ImageTarget{}, nil); err == nil {
		t.Fatal("expected empty-command error")
	}
}

func TestScanRunError(t *testing.T) {
	a := New(Config{Name: "x", Argv: imageArgv, Run: func(context.Context, []string) ([]byte, error) {
		return nil, errors.New("exec failed")
	}})
	if _, err := a.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil); err == nil {
		t.Fatal("expected run error")
	}
}

func TestScanBadSARIF(t *testing.T) {
	a := New(Config{Name: "x", Argv: imageArgv, Run: func(context.Context, []string) ([]byte, error) {
		return []byte("{not sarif"), nil
	}})
	if _, err := a.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil); err == nil {
		t.Fatal("expected parse error")
	}
}

// TestExecRunViaEcho exercises the real default exec runner using `echo` to emit SARIF.
func TestExecRunViaEcho(t *testing.T) {
	a := New(Config{
		Name: "echoer",
		Argv: func(plugin.Target, plugin.Config) ([]string, error) {
			return []string{"echo", sampleSARIF}, nil
		},
	})
	rep, err := a.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil)
	if err != nil {
		t.Fatalf("exec run failed: %v", err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("want 1 result via echo, got %d", len(rep.Results))
	}
}

func TestInfo(t *testing.T) {
	a := New(Config{Name: "trivy", Version: "1.0", Controls: []string{"images"}, TargetKinds: []plugin.TargetKind{plugin.TargetImage}})
	info := a.Info()
	if info.Name != "trivy" || info.Version != "1.0" || len(info.Controls) != 1 {
		t.Fatalf("info = %+v", info)
	}
}

func TestAdapterCacheVersion(t *testing.T) {
	// Not configured → empty.
	if v := New(Config{Name: "trivy", Argv: imageArgv}).CacheVersion(context.Background()); v != "" {
		t.Errorf("unset CacheVersion should be empty, got %q", v)
	}
	// Configured → returns the wired value.
	a := New(Config{
		Name: "trivy", Argv: imageArgv,
		CacheVersion: func(context.Context) string { return "trivy@1.2.3;db@X" },
	})
	if v := a.CacheVersion(context.Background()); v != "trivy@1.2.3;db@X" {
		t.Errorf("CacheVersion = %q", v)
	}
}

func TestAdapterPrewarm(t *testing.T) {
	// Not configured → no-op nil.
	if err := New(Config{Name: "trivy", Argv: imageArgv}).Prewarm(context.Background()); err != nil {
		t.Errorf("unset Prewarm should be a nil no-op, got %v", err)
	}
	// Configured → calls the hook.
	called := false
	a := New(Config{Name: "trivy", Argv: imageArgv, Prewarm: func(context.Context) error { called = true; return nil }})
	if err := a.Prewarm(context.Background()); err != nil || !called {
		t.Errorf("Prewarm should invoke the hook (called=%v, err=%v)", called, err)
	}
}

// Most tools emit SARIF; some report in their own JSON. The Parse hook is how the second kind
// gets a scanner without needing a scanner type of its own.
func TestAdapterUsesTheConfiguredParser(t *testing.T) {
	a := New(Config{
		Name:        "custom",
		TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
		Argv: func(plugin.Target, plugin.Config) ([]string, error) {
			return []string{"custom", "run"}, nil
		},
		Run: func(context.Context, []string) ([]byte, error) {
			return []byte(`{"whatever": true}`), nil // not SARIF; FromSARIF would find no results
		},
		Parse: func(_ []byte, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
			return sarif.Report{Results: []sarif.Result{
				{RuleID: "custom/1", Level: sarif.LevelError, Location: sarif.Location{URI: target.Identity()}},
			}}, nil
		},
	})
	rep, err := a.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes", Ref: "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "custom/1" {
		t.Fatalf("the configured parser should have produced the report, got %+v", rep.Results)
	}
	if got := rep.Results[0].Location.URI; got != "kubernetes/prod" {
		t.Errorf("the parser should see the target: location = %q", got)
	}
	// The adapter still backfills the tool name the parser left unset.
	if rep.Results[0].Tool != "custom" {
		t.Errorf("tool = %q, want custom", rep.Results[0].Tool)
	}
}

// A parser that fails should say which tool's output it choked on — the caller has several.
func TestAdapterReportsParserFailures(t *testing.T) {
	a := New(Config{
		Name:        "custom",
		TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
		Argv:        func(plugin.Target, plugin.Config) ([]string, error) { return []string{"custom"}, nil },
		Run:         func(context.Context, []string) ([]byte, error) { return []byte("{}"), nil },
		Parse: func([]byte, plugin.Target, plugin.Config) (sarif.Report, error) {
			return sarif.Report{}, errors.New("bad shape")
		},
	})
	_, err := a.Scan(context.Background(), plugin.InfraTarget{}, nil)
	if err == nil {
		t.Fatal("expected the parser error to surface")
	}
	if !strings.Contains(err.Error(), "custom") || !strings.Contains(err.Error(), "bad shape") {
		t.Errorf("error should name the tool and the cause, got: %v", err)
	}
}

// The default Run path — used by any adapter that does not supply its own. Draugr's built-in
// scanners inject a shared implementation, so without this nothing would exercise it.
func TestAdapterDefaultRunExecutesTheTool(t *testing.T) {
	a := New(Config{
		Name:        "echo",
		TargetKinds: []plugin.TargetKind{plugin.TargetHost},
		Argv: func(plugin.Target, plugin.Config) ([]string, error) {
			return []string{"printf", "%s", sampleSARIF}, nil
		},
	})
	rep, err := a.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "CVE-1" {
		t.Errorf("want the tool's SARIF parsed, got %+v", rep.Results)
	}
}

func TestAdapterDefaultRunReportsAFailingTool(t *testing.T) {
	a := New(Config{
		Name:        "false",
		TargetKinds: []plugin.TargetKind{plugin.TargetHost},
		Argv:        func(plugin.Target, plugin.Config) ([]string, error) { return []string{"false"}, nil },
	})
	_, err := a.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil)
	if err == nil {
		t.Fatal("a tool that exits non-zero should surface as an error")
	}
	if !strings.Contains(err.Error(), "false") {
		t.Errorf("the error should name the tool, got: %v", err)
	}
}
