package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// limitsSeen is what each job's tools were told about the machine, as a scanner reads it from the
// context it is handed.
type limitsSeen struct {
	mu            sync.Mutex
	jobs          int
	limitsThreads int
	sharesWorkers int
}

// limitsScanner records, for every job, whether its context limits the tools' threads and asks
// them to share their worker pools.
type limitsScanner struct{ seen *limitsSeen }

func (limitsScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "limits-probe"} }

func (s limitsScanner) Scan(ctx context.Context, _ plugin.Target, _ plugin.Config) (sarif.Report, error) {
	s.seen.mu.Lock()
	defer s.seen.mu.Unlock()
	s.seen.jobs++
	if toolexec.LimitsThreads(ctx) {
		s.seen.limitsThreads++
	}
	if toolexec.SharesWorkers(ctx) {
		s.seen.sharesWorkers++
	}
	return sarif.Report{Tool: "limits-probe"}, nil
}

// limitsController plans one job per image a component declares.
type limitsController struct{}

func (limitsController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (limitsController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, img := range comp.Images {
		jobs = append(jobs, plugin.ScanJob{Scanner: "limits-probe", Target: plugin.ImageTarget{Ref: img.Image}})
	}
	return jobs, nil
}

func (limitsController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// fileConfig is a loader that reads draugr.config.yaml from dir, and ~/.draugr/config.yaml under it,
// through the layering pkg/config gives `draugr scan`.
func fileConfig(dir string) ConfigLoader {
	return func(context.Context, *saga.Model) (config.ScanSettings, error) {
		res, err := config.Load("", dir)
		return res.File.Scan, err
	}
}

// limitsRun is what one MCP scan's engine and tools were given.
type limitsRun struct {
	concurrency   int
	jobs          int
	limitsThreads int
	sharesWorkers int
}

// scanWithConfig runs the MCP scan over two components with two images between them, from a working
// directory whose draugr.config.yaml holds body, or none where body is empty, and reads back the
// concurrency the run's report.json records.
func scanWithConfig(t *testing.T, body string) limitsRun {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv(config.EnvVar, "")
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, config.FileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "reports")
	path := writeDescriptor(t, "project: shop\nrelease:\n  version: \"1.0\"\n"+
		"config:\n  controls:\n    images:\n      enabled: true\n"+
		"  publishers:\n    - kind: file\n      dir: "+out+"\n      reports:\n        - format: json\n"+
		"components:\n"+
		"  - name: api\n    images:\n      - image: repo/api:1\n"+
		"  - name: web\n    images:\n      - image: repo/web:1\n")

	seen := &limitsSeen{}
	reg := engine.NewRegistry()
	reg.RegisterController(limitsController{})
	reg.RegisterScanner(limitsScanner{seen: seen})
	if _, _, err := scanTool(reg, ScanAlways, fileConfig(dir))(context.Background(), nil, ScanInput{Path: path}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(out, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Stats struct {
			Concurrency int `json:"concurrency"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return limitsRun{concurrency: doc.Stats.Concurrency, jobs: seen.jobs,
		limitsThreads: seen.limitsThreads, sharesWorkers: seen.sharesWorkers}
}

// Each scan.* key in draugr.config.yaml reaches the MCP scan: scan.jobs as the engine's job count,
// scan.limitToolThreads and scan.shareWorkers on the context every job's tools are started under,
// shareWorkers bringing the thread limit with it as --share-workers does. A scan that ignored them
// would run the whole machine on a host whose operator asked it not to.
func TestTheMCPScanTakesEachScanSettingFromTheConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       func(limitsRun) bool
	}{
		{"scan.jobs", "scan:\n  jobs: 1\n", func(r limitsRun) bool {
			return r.concurrency == 1 && r.limitsThreads == 0 && r.sharesWorkers == 0
		}},
		{"scan.limitToolThreads", "scan:\n  limitToolThreads: true\n", func(r limitsRun) bool {
			return r.limitsThreads == r.jobs && r.sharesWorkers == 0
		}},
		{"scan.shareWorkers", "scan:\n  shareWorkers: true\n", func(r limitsRun) bool {
			return r.limitsThreads == r.jobs && r.sharesWorkers == r.jobs
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scanWithConfig(t, tc.body)
			if got.jobs != 2 {
				t.Fatalf("%d jobs ran, want one per image", got.jobs)
			}
			if !tc.want(got) {
				t.Errorf("%s in draugr.config.yaml: concurrency %d, %d of %d jobs limited, %d sharing workers",
					tc.name, got.concurrency, got.limitsThreads, got.jobs, got.sharesWorkers)
			}
		})
	}
}

// With no scan.* key set, the MCP scan runs as `draugr scan` with no flags does: the machine's
// default job count, and each tool sized to the machine.
func TestTheMCPScanWithoutScanSettingsRunsAtTheDefaults(t *testing.T) {
	for name, body := range map[string]string{"no file": "", "a file without scan": "output:\n  top: 5\n"} {
		t.Run(name, func(t *testing.T) {
			got := scanWithConfig(t, body)
			if got.concurrency != toolexec.DefaultJobs() {
				t.Errorf("concurrency %d, want the machine's default %d", got.concurrency, toolexec.DefaultJobs())
			}
			if got.limitsThreads != 0 || got.sharesWorkers != 0 {
				t.Errorf("%d jobs limited and %d sharing workers, want none", got.limitsThreads, got.sharesWorkers)
			}
		})
	}
}

// A scan with no loader at all reads no scan.* settings, and runs at the defaults too.
func TestTheMCPScanWithoutALoaderRunsAtTheDefaults(t *testing.T) {
	seen := &limitsSeen{}
	reg := engine.NewRegistry()
	reg.RegisterController(limitsController{})
	reg.RegisterScanner(limitsScanner{seen: seen})
	path := writeDescriptor(t, "project: shop\nconfig:\n  controls:\n    images:\n      enabled: true\n"+
		"components:\n  - name: api\n    images:\n      - image: repo/api:1\n")
	if _, _, err := scanTool(reg, ScanAlways, nil)(context.Background(), nil, ScanInput{Path: path}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if seen.jobs != 1 || seen.limitsThreads != 0 || seen.sharesWorkers != 0 {
		t.Errorf("%d jobs, %d limited, %d sharing workers, want one job with neither", seen.jobs, seen.limitsThreads, seen.sharesWorkers)
	}
}
