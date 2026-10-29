// Package needs answers what a scan of a descriptor would run: the scanners its enabled controls
// select, and the external tools those scanners execute.
//
// One answer for every command that asks. `draugr doctor`, the install offer `draugr scan` makes,
// `draugr tools install` with a descriptor and the MCP server's check_tools all read it, so a tool
// one of them calls missing is a tool every one of them calls missing. Two derivations of the same
// list disagree the first time a control gains a second scanner, and the one that over-counts tells
// somebody a machine that can scan is not ready.
package needs

import (
	"sort"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/sbom"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Use is a scanner a scan would run and the enabled controls it would run for.
type Use struct {
	Info     plugin.ScannerInfo
	Controls []string
}

// Tools returns the external tools needed by the controls enabled anywhere in the model: for each
// scanner a scan would run, its binary and anything it also requires, plus git when the scanner
// works on a checked-out repository, plus syft when config.sbom is on. Sorted by binary.
func Tools(reg *engine.Registry, model *saga.Model) []tools.Tool {
	catalog := tools.Catalog()
	seen := map[string]bool{}
	var out []tools.Tool
	// A binary the catalog does not describe is still checked. Dropping it would report every
	// required tool present for a control whose scanner is not installed at all.
	add := func(binary string) {
		if binary == "" || seen[binary] {
			return
		}
		seen[binary] = true
		if t, ok := catalog[binary]; ok {
			// Everything reaching this function was selected by the descriptor: a scanner serving
			// an enabled control, something that scanner also requires, or a block the Saga turned
			// on. `Optional` in the catalog is about the inventory view, where nothing has been
			// chosen and the question is "what could Draugr use". Carried through to here it would
			// report a clean environment for a scan that cannot run.
			t.Optional = false
			out = append(out, t)
			return
		}
		out = append(out, tools.Tool{
			Binary:      binary,
			Category:    tools.CategoryScanner,
			InstallHint: ExternalInstallHint(binary),
		})
	}

	for _, info := range Scanners(reg, model) {
		add(info.Binary)
		for _, extra := range info.AlsoRequires {
			add(extra)
		}
		for _, tk := range info.TargetKinds {
			if tk == plugin.TargetRepository {
				add("git")
			}
		}
	}

	// SBOM generation is not a control, so no scanner declares it. It is required by the Saga's
	// config.sbom block instead.
	if s := model.Config.SBOM; s != nil && s.Enabled {
		add(sbom.Binary)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Binary < out[j].Binary })
	return out
}

// Scanners returns the scanners a scan of model would run: each one serving a control the model
// enables, and among several serving one control, only those the control selects.
func Scanners(reg *engine.Registry, model *saga.Model) []plugin.ScannerInfo {
	uses := Uses(reg, model)
	out := make([]plugin.ScannerInfo, len(uses))
	for i, u := range uses {
		out[i] = u.Info
	}
	return out
}

// Uses is Scanners with the controls each scanner serves, which is what a message naming the
// controls a missing tool blocks needs. In registry order.
func Uses(reg *engine.Registry, model *saga.Model) []Use {
	enabled := func(control string) bool {
		if model.Config.ControllerEnabled(control) {
			return true
		}
		for i := range model.Components {
			if model.Components[i].ControllerEnabled(control, model.Config) {
				return true
			}
		}
		return false
	}

	// A control served by several scanners only requires the ones it will actually run. Asking
	// for the rest sends someone to install a tool the scan would never have used, and reports a
	// control as unable to run when it can.
	selected := map[string]map[string]bool{}
	for _, c := range reg.Controllers() {
		ci := c.Info()
		if len(ci.DefaultScanners) == 0 {
			continue
		}
		selected[ci.Name] = controllers.SelectedScanners(*model, c)
	}

	// An analyzer named in config.reachability is required and is not selectable from a scanner
	// block, which refuses it there deliberately, so the selection above filters it out with every
	// scanner the control will not run.
	analyzer := map[string]bool{}
	if r := model.Config.Reachability; r != nil {
		for _, name := range r.Analyzers {
			analyzer[name] = true
		}
	}

	var out []Use
	for _, s := range reg.Scanners() {
		info := s.Info()
		var controls []string
		for _, c := range info.Controls {
			if !enabled(c) {
				continue
			}
			// Named as an analyzer, so the control runs it whatever its scanner block says. Still
			// inside the enabled check: config.reachability is project-wide, and an analyzer whose
			// control is switched off is a tool this scan will never reach for.
			if analyzer[info.Name] {
				controls = append(controls, c)
				continue
			}
			if set, selectable := selected[c]; selectable && !set[info.Name] {
				continue // a scanner this control will not run for this model
			}
			controls = append(controls, c)
		}
		if len(controls) > 0 {
			out = append(out, Use{Info: info, Controls: controls})
		}
	}
	return out
}

// ExternalInstallHint says where a tool `draugr tools install` does not fetch comes from.
//
// `draugr tools install` fetches pinned releases Draugr has verified, which it can only do for
// tools it vouched for. For the rest, proprietary ones especially, naming the source is the whole
// of the help available, and it is much more use than telling somebody to run a command that will
// not find it.
func ExternalInstallHint(binary string) string {
	if from, ok := externalTools[binary]; ok {
		return from
	}
	return "required by a registered scanner; not in Draugr's tool catalog"
}

// externalTools names where to get a tool Draugr execs but never downloads.
var externalTools = map[string]string{
	"mend": "proprietary; install the Mend CLI from Mend's documentation, which `draugr tools " +
		"install` does not fetch. See internal/scanners/mend-sca.md",
}
