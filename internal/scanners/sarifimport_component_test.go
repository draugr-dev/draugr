package scanners

import (
	"context"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/pkg/cache"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// importAccounts is the component each account of an imported file in control names, sorted.
func importAccounts(res engine.Result, control string) []string {
	var named []string
	for _, p := range res.Controls[control].Report.Provenance {
		if p.Tool != plugin.ImportScanner {
			continue
		}
		for _, f := range p.Fields {
			if f.Key == "component" {
				named = append(named, f.Value)
			}
		}
	}
	slices.Sort(named)
	return named
}

// importHits counts the cache's answers that were an imported file's read.
type importHits struct {
	*cache.Memory
	hits atomic.Int32
}

func (c *importHits) Get(key string) (sarif.Report, bool) {
	rep, ok := c.Memory.Get(key)
	if ok && slices.ContainsFunc(rep.Provenance, func(p sarif.Provenance) bool { return p.Tool == plugin.ImportScanner }) {
		c.hits.Add(1)
	}
	return rep, ok
}

// One file imported by two components of one repository with the same scope gives each component
// its own account of the file, naming that component, both when the run reads it once per
// component and when a later run answers both from the cache.
func TestOneFileImportedByTwoComponentsIsAccountedToEach(t *testing.T) {
	semgrep, config := replayingSemgrep(t)
	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewSAST())
	reg.RegisterScanner(semgrep)
	reg.RegisterScanner(NewSARIFImport())
	repo := t.TempDir()
	imports := []saga.Import{{Control: "sast", File: writeFile(t, exampleLog(foundAt("EX2", "app.py"), ""))}}
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sast": {"enabled": true, "semgrep": map[string]any{"config": config}}}},
		Components: []saga.Component{
			{Name: "api", Imports: imports, Repositories: []saga.Repository{{URL: repo}}},
			{Name: "web", Imports: imports, Repositories: []saga.Repository{{URL: repo}}},
		},
	}
	store := &importHits{Memory: cache.NewMemory()}
	for _, run := range []string{"fresh", "cached"} {
		res, err := engine.New(reg, engine.WithCache(store)).Run(context.Background(), model)
		if err != nil {
			t.Fatalf("%s: %v", run, err)
		}
		if got, want := importAccounts(res, "sast"), []string{"api", "web"}; !reflect.DeepEqual(got, want) {
			t.Errorf("%s run: the file's accounts name %v, want %v", run, got, want)
		}
		for _, r := range res.Controls["sast"].Report.Results {
			if r.Scanner == plugin.ImportScanner && r.Component == "" {
				t.Errorf("%s run: an imported finding names no component", run)
			}
		}
		if hits := store.hits.Swap(0); run == "cached" && hits != 2 {
			t.Errorf("cached run: the cache answered %d reads of the file, want 2, one per component", hits)
		}
	}
}
