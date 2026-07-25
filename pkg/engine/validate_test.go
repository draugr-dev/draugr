package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// schemaScanner declares a ConfigSchema so the engine validates jobs against it.
type schemaScanner struct{}

func (schemaScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name: "cfg",
		ConfigSchema: json.RawMessage(
			`{"type":"object","additionalProperties":false,"properties":{"config":{"type":"string"}}}`),
	}
}

func (s schemaScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: "cfg"}, nil
}

// cfgController plans one component-scoped job carrying a fixed config.
type cfgController struct{ cfg plugin.Config }

func (cfgController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "cfgctl", Scope: plugin.ScopeComponent}
}

func (c cfgController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: "cfg", Target: plugin.ImageTarget{Ref: comp.Name}, Config: c.cfg}}, nil
}

func (cfgController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "cfgctl", Report: sarif.Merge(reports...)}, nil
}

func cfgModel() saga.Model {
	return saga.Model{
		Config:     saga.Config{Controllers: map[string]saga.ControllerSettings{"cfgctl": {"enabled": true}}},
		Components: []saga.Component{{Name: "a"}},
	}
}

func TestPlanValidatesConfig_Reject(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(schemaScanner{})
	reg.RegisterController(cfgController{cfg: plugin.Config{"nope": 1}})

	planned, err := New(reg).Plan(cfgModel())
	if err == nil || !strings.Contains(err.Error(), `unknown option "nope"`) {
		t.Fatalf("want config validation error, got %v", err)
	}
	if len(planned) != 0 {
		t.Errorf("invalid job should be dropped, got %d planned", len(planned))
	}
}

func TestPlanValidatesConfig_Accept(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterScanner(schemaScanner{})
	reg.RegisterController(cfgController{cfg: plugin.Config{"config": "p/ci"}})

	planned, err := New(reg).Plan(cfgModel())
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(planned) != 1 {
		t.Errorf("valid job should be planned, got %d", len(planned))
	}
}

func TestPlanValidatesConfig_NoConfigNoError(t *testing.T) {
	// A nil config is valid against a schema with no required keys.
	reg := NewRegistry()
	reg.RegisterScanner(schemaScanner{})
	reg.RegisterController(cfgController{cfg: nil})

	planned, err := New(reg).Plan(cfgModel())
	if err != nil || len(planned) != 1 {
		t.Fatalf("nil config should pass: err=%v planned=%d", err, len(planned))
	}
}
