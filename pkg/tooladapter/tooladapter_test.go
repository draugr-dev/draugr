package tooladapter

import (
	"context"
	"errors"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
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
