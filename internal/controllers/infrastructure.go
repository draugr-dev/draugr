package controllers

import (
	"maps"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	kubeBenchScanner    = "kube-bench"
	kubeBenchJobScanner = "kube-bench-job"
	k8sPoliciesScanner  = "k8s-policies"

	// The default reads the policies section through the Kubernetes API rather than exec'ing
	// kube-bench. Both answer the same 11 of the section's 34 checks, so the choice costs no
	// coverage; what differs is that one needs no kubectl, creates nothing, and asks the API a
	// handful of questions where the other runs a subprocess per check and, for the pod-security
	// ones, per pod. On a cluster of eight thousand pods that is seconds against tens of minutes.
	//
	// kube-bench stays available as `kubeBench: { enabled: true }` — it is the reference the
	// native reader is checked against, and the thing to reach for if the two ever disagree.
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
		DefaultScanners: []string{k8sPoliciesScanner},
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
	// Control-level settings apply to every scanner the control runs: `context` names the
	// cluster, not a tool, and repeating it per scanner would be a way to get them out of step.
	// A scanner block overlays them, so a per-scanner value still wins.
	shared := infraConfig(model, comp)
	selections := resolveScanners(model, comp, infrastructureControl, []string{k8sPoliciesScanner})
	var jobs []plugin.ScanJob
	for _, infra := range comp.Infrastructure {
		if !strings.EqualFold(infra.Kind, kubernetesPlatform) {
			continue
		}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{
				Scanner: sel.Name,
				Target:  plugin.InfraTarget{Platform: kubernetesPlatform, Ref: infra.Ref, Namespaces: infra.Namespaces},
				Config:  withShared(shared, sel.Config),
			})
		}
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

// withShared layers a scanner's own block over the control's settings.
func withShared(shared, block plugin.Config) plugin.Config {
	if len(shared) == 0 && len(block) == 0 {
		return nil
	}
	cfg := plugin.Config{}
	maps.Copy(cfg, shared)
	maps.Copy(cfg, block)
	return cfg
}
