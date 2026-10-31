package cli

import (
	"slices"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/needs"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// found is the report's FOUND section: what the tree held and what the run did with each kind of
// file, from the rows `draugr init` prints for the same tree. Called after turnOffUnrunnable, so a
// scanner it turned off reads as off.
func (zc *zeroConfig) found() []report.Found {
	rows := foundRows(zc.tree)
	out := make([]report.Found, len(rows))
	for i, r := range rows {
		out[i] = report.Found{Kind: r.kind, Files: r.where, Did: r.scanSays(zc.turnedOff)}
	}
	return out
}

// turnOffUnrunnable turns off each scanner the tree chose that this machine cannot run, and
// returns the files each one would have examined.
//
// A scanner the tree chose is one the model runs and the base does not: gosec and govulncheck for a
// go.mod, retire.js for copied JavaScript, Grype for a file only it reads. No descriptor asked for
// it, and a reader who never chose a scanner cannot be told their configuration is broken, so a
// missing tool or runtime is a gap in what the run covered rather than a control that failed, and
// the run says which files went unexamined and what would examine them. A scanner the base runs
// keeps the behavior a descriptor's would: missing, it fails its control.
//
// Called once the install offer has had its answer, so what `draugr tools install` can fetch is
// offered before anything is turned off. A control outside the scope is left alone, since the run
// would not have reached its scanners.
func (zc *zeroConfig) turnOffUnrunnable(reg *engine.Registry, scope engine.Scope, lookPath func(string) (string, error)) []report.Unexamined {
	base, err := zeroConfigBase()
	if err != nil {
		return nil
	}
	inBase := map[string]bool{}
	for _, u := range needs.Uses(reg, base) {
		inBase[u.Info.Name] = true
	}
	rows := foundRows(zc.tree)
	var out []report.Unexamined
	for _, u := range needs.Uses(reg, zc.model) {
		if inBase[u.Info.Name] || !slices.ContainsFunc(u.Controls, func(c string) bool { return inScope(scope, c) }) {
			continue
		}
		why := cannotRun(u.Info, lookPath)
		if why == "" {
			continue
		}
		turnOff(zc.model, u.Info)
		zc.turnedOff = append(zc.turnedOff, u.Info.Name)
		out = append(out, report.Unexamined{
			Component: zc.model.Components[0].Name, Files: foundFiles(rows, u.Info.Name), Why: why,
		})
	}
	return out
}

// cannotRun says what this machine lacks to run the scanner, or "" when it lacks nothing: the
// runtime one of its tools runs on, or a tool itself, with the command that installs it where
// `draugr tools install` can.
//
// The runtime first. A tool installed with nothing to run it on still cannot run, and govulncheck
// cannot even be installed without Go.
func cannotRun(info plugin.ScannerInfo, lookPath func(string) (string, error)) string {
	catalog := tools.Catalog()
	var binaries []string
	for _, b := range append([]string{info.Binary}, info.AlsoRequires...) {
		if b != "" {
			binaries = append(binaries, b)
		}
	}
	for _, b := range binaries {
		rt := catalog[b].Runtime
		if rt.Binary == "" {
			continue
		}
		if _, err := lookPath(rt.Binary); err != nil {
			return b + " needs " + rt.Name
		}
	}
	for _, b := range binaries {
		if _, err := lookPath(b); err == nil {
			continue
		}
		if tools.Provisionable(b) {
			return b + " not installed · draugr tools install " + b
		}
		return b + " not installed"
	}
	return ""
}

// turnOff stops the model running the scanner: a reachability analyzer leaves
// config.reachability, and any other scanner's block under each of its controls is set to
// enabled: false.
func turnOff(m *saga.Model, info plugin.ScannerInfo) {
	if info.Reachability {
		if r := m.Config.Reachability; r != nil {
			r.Analyzers = slices.DeleteFunc(r.Analyzers, func(a string) bool { return a == info.Name })
			if len(r.Analyzers) == 0 {
				m.Config.Reachability = nil
			}
		}
		return
	}
	key := controllers.ScannerConfigKey(info.Name)
	for _, control := range info.Controls {
		settings, ok := m.Config.Controls[control]
		if !ok {
			continue
		}
		block := saga.ControllerSettings{}
		switch b := settings[key].(type) {
		case saga.ControllerSettings:
			block = b
		case map[string]any:
			block = b
		}
		block["enabled"] = false
		settings[key] = block
	}
}
