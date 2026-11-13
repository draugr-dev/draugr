package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const trivyFSScanner = "trivy-fs"

// govulncheckScanner decides reachability; it is enabled by config.reachability, never by a
// scanner block. See ReachabilityConfig.
const govulncheckScanner = "govulncheck"

// SCA is the Software Composition Analysis control: dependency vulnerabilities (and, later,
// licenses) for a component's source repositories. It plans one scan per repository.
type SCA struct{}

// NewSCA returns the sca controller.
func NewSCA() plugin.Controller { return SCA{} }

// Info identifies the controller (component-scoped).
func (SCA) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            scaControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Find known flaws in the libraries a repo depends on (software composition analysis).",
		DefaultScanners: []string{"trivy-fs"},
		OptionSchema:    scaOptionSchema,
	}
}

const (
	scaControl = "sca"
	// devDependenciesKey decides whether the findings in development dependencies count.
	devDependenciesKey = "devDependencies"
	// devSuppress and devReport are its two values, and providedDependencies', cpeMatches' and
	// ownPackages'.
	devSuppress = "suppress"
	devReport   = "report"
	// includeDevDepsKey is trivy-fs's deprecated spelling of devDependencies: true is report.
	includeDevDepsKey = "includeDevDeps"
	// providedDependenciesKey decides whether the findings in dependencies the runtime provides
	// count.
	providedDependenciesKey = "providedDependencies"
	// cpeMatchesKey decides whether the findings a scanner matched only through a CPE count.
	cpeMatchesKey = "cpeMatches"
	// ownPackagesKey decides whether the findings about the project's own package count.
	ownPackagesKey = "ownPackages"
)

// scaOptionSchema describes devDependencies, providedDependencies, cpeMatches, ownPackages and
// nonShippingPaths where they sit, under the control.
//
// The control's rather than a scanner's, because the answer is the same whichever scanner found
// the flaw: a development dependency Grype reported takes its mark from Trivy's copy of the same
// package, a provided one takes its mark from the pom whichever scanner read it, and one setting
// then decides each.
var scaOptionSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "devDependencies": {
      "type": "string",
      "default": "suppress",
      "anyOf": [
        { "const": "suppress", "description": "Each finding in a development dependency stays in the report, suppressed with the reason development dependency, and out of the counts and the gate. The default." },
        { "const": "report", "description": "Each finding in a development dependency is counted, marked dev." }
      ],
      "description": "Whether findings in development dependencies count. A component's setting replaces the project's."
    },
    "providedDependencies": {
      "type": "string",
      "default": "suppress",
      "anyOf": [
        { "const": "suppress", "description": "Each finding in a dependency the runtime provides stays in the report, suppressed with the reason provided by the runtime, and out of the counts and the gate. The default." },
        { "const": "report", "description": "Each finding in a dependency the runtime provides is counted, marked provided." }
      ],
      "description": "Whether findings in provided and system dependencies, which the runtime supplies, count. A component's setting replaces the project's."
    },
    ` + cpeMatchesProperty(devSuppress) + `,
    "ownPackages": {
      "type": "string",
      "default": "suppress",
      "anyOf": [
        { "const": "suppress", "description": "Each finding about the project's own package stays in the report, suppressed with the reason \"the project's own package\", and out of the counts and the gate. The default." },
        { "const": "report", "description": "Each finding about the project's own package is counted, with own beside its package." }
      ],
      "description": "Whether findings about the project's own package count, such as a package-lock.json's root or a Cargo workspace member. A component's setting replaces the project's."
    },
    ` + nonShippingProperty + `
  }
}`)

// cpeMatchesProperty describes cpeMatches where it sits, as a property of a control's schema, with
// def as that control's default. sca and images each take it, because a match Grype made only
// through a CPE reaches both, and they default differently: see Images.ReportsCPEMatches.
func cpeMatchesProperty(def string) string {
	suppress, report := "", ""
	if def == devReport {
		report = " The default."
	} else {
		suppress = " The default."
	}
	return `"cpeMatches": {
      "type": "string",
      "default": "` + def + `",
      "anyOf": [
        { "const": "suppress", "description": "Each finding matched only by CPE stays in the report, suppressed with the reason matched by CPE only, and out of the counts and the gate.` + suppress + `" },
        { "const": "report", "description": "Each finding matched only by CPE is counted, marked cpe.` + report + `" }
      ],
      "description": "Whether findings Grype matched only through a CPE built from the package's name count: on a package type it has no matcher for, such as dart-pub and pod, and on an Alpine apk package, for a flaw Alpine's own data does not list. A component's setting replaces the project's."
    }`
}

// ReportsProvidedDependencies resolves providedDependencies for one component, and names the key
// that decided it: the component's setting first, then the project's, and with neither written the
// default, suppress, named by the project's key.
func (SCA) ReportsProvidedDependencies(model saga.Model, component string) (bool, string) {
	return scaSetting(model, component, providedDependenciesKey)
}

// scaSetting resolves one of the control's suppress-or-report settings for one component, and names
// the key that decided it: the component's setting first, then the project's, and with neither
// written the default, suppress, named by the project's key.
func scaSetting(model saga.Model, component, key string) (bool, string) {
	return controlSetting(model, component, scaControl, key, false)
}

// ReportsCPEMatches resolves cpeMatches for one component, and names the key that decided it, as
// ReportsProvidedDependencies does.
func (SCA) ReportsCPEMatches(model saga.Model, component string) (bool, string) {
	return scaSetting(model, component, cpeMatchesKey)
}

// ReportsOwnPackages resolves ownPackages for one component, and names the key that decided it, as
// ReportsProvidedDependencies does.
func (SCA) ReportsOwnPackages(model saga.Model, component string) (bool, string) {
	return scaSetting(model, component, ownPackagesKey)
}

// ReportsDevDependencies resolves devDependencies for one component, and names the key that
// decided it.
//
// The component's setting first, then the project's, as every other setting merges. At each level
// the deprecated trivyFs.includeDevDeps is read where devDependencies is absent, true as report and
// false as suppress, so a descriptor written before the setting existed keeps the answer it chose.
// With neither written anywhere the default, suppress, is named by the project's key, which is the
// one a reader writes to change it.
func (SCA) ReportsDevDependencies(model saga.Model, component string) (bool, string) {
	project := "config.controls." + scaControl
	if comp := componentNamed(model, component); comp != nil {
		where := fmt.Sprintf("components[%q].controls.%s", comp.Name, scaControl)
		if report, key, ok := devDependenciesAt(comp.Controls[scaControl]); ok {
			return report, where + "." + key
		}
	}
	if report, key, ok := devDependenciesAt(model.Config.Controls[scaControl]); ok {
		return report, project + "." + key
	}
	return false, project + "." + devDependenciesKey
}

// devDependenciesAt reads the setting from one level's sca block, and the key it was read from:
// devDependencies, or the deprecated trivyFs.includeDevDeps where that is absent.
func devDependenciesAt(settings saga.ControllerSettings) (report bool, key string, ok bool) {
	if v, written := settings[devDependenciesKey].(string); written {
		return v == devReport, devDependenciesKey, true
	}
	trivy, _ := asMap(settings[configKeyFor(trivyFSScanner)])
	if v, written := trivy[includeDevDepsKey].(bool); written {
		return v, configKeyFor(trivyFSScanner) + "." + includeDevDepsKey, true
	}
	return false, "", false
}

// componentNamed is the component of that name, or nil.
func componentNamed(model saga.Model, name string) *saga.Component {
	for i := range model.Components {
		if model.Components[i].Name == name {
			return &model.Components[i]
		}
	}
	return nil
}

// Warnings names each trivyFs.includeDevDeps the descriptor still writes, and what to write
// instead: devDependencies: report for true, and nothing for false, which is the default.
func (SCA) Warnings(model saga.Model) []string {
	out := deprecatedDevDeps("config.controls."+scaControl, model.Config.Controls[scaControl])
	for i := range model.Components {
		comp := &model.Components[i]
		out = append(out, deprecatedDevDeps(fmt.Sprintf("components[%q].controls.%s", comp.Name, scaControl), comp.Controls[scaControl])...)
	}
	return out
}

// deprecatedDevDeps is the warning for one level's includeDevDeps, or nothing where it is not
// written.
func deprecatedDevDeps(where string, settings saga.ControllerSettings) []string {
	trivy, _ := asMap(settings[configKeyFor(trivyFSScanner)])
	v, written := trivy[includeDevDepsKey]
	if !written {
		return nil
	}
	old := where + "." + configKeyFor(trivyFSScanner) + "." + includeDevDepsKey
	if _, set := settings[devDependenciesKey]; set {
		return []string{fmt.Sprintf("%s is deprecated and ignored beside %s.%s. Remove it.", old, where, devDependenciesKey)}
	}
	if on, _ := v.(bool); on {
		return []string{fmt.Sprintf("%s is deprecated and stops being read in the next release. Replace it with %s.%s: %s.",
			old, where, devDependenciesKey, devReport)}
	}
	return []string{fmt.Sprintf("%s is deprecated and stops being read in the next release. Delete it; %s is the default.",
		old, devSuppress)}
}

// Plan produces one scan job per repository, for each scanner this component selects.
//
// Trivy runs by default; anything else is opt-in, because the others reach a third party and one
// of them writes into an account. See scanner selection in the Saga reference.
func (SCA) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	selections := resolveScanners(model, comp, "sca", []string{trivyFSScanner})
	// Reachability analyzers are planned from config.reachability rather than selected from the
	// scanner block, because enabling one is a decision about how findings are ranked rather than
	// about which tools run. They still plan as sca jobs: an analyzer needs the same checkout the
	// manifest scanner reads.
	for _, name := range reachabilitySelections(model) {
		selections = append(selections, scannerSelection{Name: name})
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(selections))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision,
			Paths: repo.Paths, Ignore: repo.Ignore,
			Upstream: comp.PublishedBy(repo) == saga.BuiltByUpstream}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
func (SCA) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "sca",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
