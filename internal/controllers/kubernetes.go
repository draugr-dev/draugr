package controllers

import (
	"maps"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	kubeBenchScanner         = "kube-bench"
	kubeBenchJobScanner      = "kube-bench-job"
	draugrK8sPoliciesScanner = "draugr-k8s-policies"

	// The default reads the policies section through the Kubernetes API rather than exec'ing
	// kube-bench. Both answer the same 11 of the section's 34 checks, so the choice costs no
	// coverage; what differs is that one needs no kubectl, creates nothing, and asks the API a
	// handful of questions where the other runs a subprocess per check and, for the pod-security
	// ones, per pod. On a cluster of eight thousand pods that is seconds against tens of minutes.
	//
	// kube-bench stays available as `kubeBench: { enabled: true }`. It is the reference the
	// native reader is checked against, and the thing to reach for if the two ever disagree.
	kubernetesControl = "kubernetes"
)

// Kubernetes assesses the clusters a component runs on against the CIS Kubernetes Benchmark.
//
// Component-scoped rather than project-scoped, because that is where the Saga puts the data:
// `kubernetes:` is a list on a component, naming the clusters it runs on. Two components on the
// same cluster produce two jobs with the same target, which the engine collapses. So the shared
// case costs one scan, not two.
type Kubernetes struct{}

// NewKubernetes returns the kubernetes controller.
func NewKubernetes() plugin.Controller { return Kubernetes{} }

// Info identifies the controller.
func (Kubernetes) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            kubernetesControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Check a Kubernetes cluster against the CIS Benchmark, rather than taking it on trust.",
		DefaultScanners: []string{draugrK8sPoliciesScanner},
	}
}

// Plan produces one scan job per cluster on the component, for each scanner selected.
func (Kubernetes) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	// Control-level settings apply to every scanner the control runs: `context` names the
	// cluster, not a tool, and repeating it per scanner would be a way to get them out of step.
	// A scanner block overlays them, so a per-scanner value still wins.
	shared := clusterConfig(model, comp)
	selections := resolveScanners(model, comp, kubernetesControl, []string{draugrK8sPoliciesScanner})
	var jobs []plugin.ScanJob
	for _, cluster := range comp.Kubernetes {
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{
				Scanner: sel.Name,
				Target: plugin.KubernetesTarget{
					Ref: cluster.Ref, Namespaces: cluster.Namespaces,
					ProviderOperated: cluster.OperatedBy == saga.OperatedByProvider,
				},
				Config: withShared(shared, sel.Config),
			})
		}
	}
	return jobs, nil
}

// clusterConfig resolves the control's settings for a component: the project's, with the
// component's layered over.
func clusterConfig(model saga.Model, comp *saga.Component) plugin.Config {
	settings := mergedSettings(model.Config.Controls[kubernetesControl], comp.Controls[kubernetesControl])
	if len(settings) == 0 {
		return nil
	}
	cfg := plugin.Config{}
	for k, v := range settings {
		// `enabled` is the control's own flag, and a nested mapping is a scanner's block. Copying
		// either into a scanner's config hands it keys that are not its own, and a scanner that
		// declares what it accepts then refuses the whole job, naming a key the descriptor never
		// wrote at that level.
		//
		// A scanner that declares no schema accepts them and ignores them, which is the same silent
		// drop the schemas exist to end. So this is invisible until a scanner starts validating, and
		// then it rejects `enabled`, the flag that turns the control on.
		if k == enabledKey {
			continue
		}
		switch v.(type) {
		case saga.ControllerSettings, map[string]any:
			continue
		}
		cfg[k] = v
	}
	if len(cfg) == 0 {
		return nil
	}
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
func (Kubernetes) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: kubernetesControl,
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
