package controllers

import (
	"maps"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	kubeBenchScanner      = "kube-bench"
	infrastructureControl = "infrastructure"
	kubernetesPlatform    = "kubernetes"
)

// Infrastructure assesses the platform a component runs on against the CIS Kubernetes
// Benchmark.
//
// Component-scoped rather than project-scoped, because that is where the Saga puts the data:
// `infrastructure:` is a list on a component, describing what that component runs on. Two
// components on the same cluster produce two jobs with the same target, which the engine
// collapses — so the shared case costs one scan, not two.
type Infrastructure struct{}

// NewInfrastructure returns the infrastructure controller.
func NewInfrastructure() plugin.Controller { return Infrastructure{} }

// Info identifies the controller.
func (Infrastructure) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            infrastructureControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Audit a Kubernetes cluster against the CIS Kubernetes Benchmark.",
		DefaultScanners: []string{kubeBenchScanner},
	}
}

// Plan produces one scan job per Kubernetes infrastructure entry on the component.
//
// Infrastructure of another kind is skipped rather than failed: a Saga may describe surfaces
// Draugr has no benchmark for, and refusing to plan the ones it does understand would make the
// descriptor less useful the more honestly it was written.
func (Infrastructure) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	cfg := infraConfig(model, comp)
	var jobs []plugin.ScanJob
	for _, infra := range comp.Infrastructure {
		if !strings.EqualFold(infra.Kind, kubernetesPlatform) {
			continue
		}
		jobs = append(jobs, plugin.ScanJob{
			Scanner: kubeBenchScanner,
			Target:  plugin.InfraTarget{Platform: kubernetesPlatform, Ref: infra.Ref},
			Config:  cfg,
		})
	}
	return jobs, nil
}

// infraConfig resolves the control's settings for a component: the project's, with the
// component's layered over.
func infraConfig(model saga.Model, comp *saga.Component) plugin.Config {
	settings := mergedSettings(model.Config.Controllers[infrastructureControl], comp.Controllers[infrastructureControl])
	if len(settings) == 0 {
		return nil
	}
	cfg := plugin.Config{}
	maps.Copy(cfg, settings)
	return cfg
}

// mergedSettings layers a component's settings over the project's.
func mergedSettings(project, component saga.ControllerSettings) saga.ControllerSettings {
	out := saga.ControllerSettings{}
	maps.Copy(out, project)
	maps.Copy(out, component)
	return out
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (Infrastructure) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: infrastructureControl,
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
