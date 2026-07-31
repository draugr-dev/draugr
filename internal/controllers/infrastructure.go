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
	kubeBenchJobScanner   = "kube-bench-job"
	k8sPoliciesScanner    = "k8s-policies"
	infrastructureControl = "infrastructure"
	kubernetesPlatform    = "kubernetes"
	// modeKey chooses how the benchmark is run: read-only through the API (the default), or
	// inside the cluster as a Job.
	modeKey = "mode"
	modeJob = "job"
	// modeAPI reads the policies section through the Kubernetes API instead of exec'ing
	// kube-bench. Opt-in while its coverage of the section grows.
	modeAPI = "api"
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
		for _, scanner := range scannersFor(cfg) {
			jobs = append(jobs, plugin.ScanJob{
				Scanner: scanner,
				Target:  plugin.InfraTarget{Platform: kubernetesPlatform, Ref: infra.Ref},
				Config:  cfg,
			})
		}
	}
	return jobs, nil
}

// scannersFor picks how the benchmark runs.
//
// Separate scanners rather than one with a flag, because the difference is not an implementation
// detail: reading the cluster through its API creates nothing, while the in-cluster run schedules
// a privileged Job on a node. Effects are declared per scanner, so separating them is what lets
// the read-only paths run unguarded while the other one has to be accepted first.
//
// `job` plans two, because the benchmark splits in two and neither half is optional. The Job
// covers the sections that read a node's own filesystem and cannot be answered any other way;
// it does not run `policies`, and running it there would shell out to kubectl once per pod
// inside a Job that has a timeout. So the native reader covers that section alongside it —
// which creates nothing, needs no privilege beyond read, and takes about a second on a cluster
// of eighty namespaces.
//
// Asking for the benchmark and receiving half of it, with a pass on the half that ran, is the
// same silence this control exists to refuse.
func scannersFor(cfg plugin.Config) []string {
	mode, _ := cfg[modeKey].(string)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case modeJob:
		return []string{kubeBenchJobScanner, k8sPoliciesScanner}
	case modeAPI:
		return []string{k8sPoliciesScanner}
	default:
		return []string{kubeBenchScanner}
	}
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
