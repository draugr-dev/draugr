package cli

import (
	"path"
	"slices"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/detect"
	"github.com/draugr-dev/draugr/internal/needs"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// found is the report's FOUND section: what each repository held and what the run did with each
// kind of file, from the rows `draugr init` prints for the same tree, then each repository detect
// could not read. Called after turnOffUnrunnable, so a scanner it turned off reads as off, and so
// does anything the descriptor turned off itself.
func (d *detection) found(reg *engine.Registry) []report.Found {
	off := d.off(reg)
	var out []report.Found
	for i := range d.result.Read {
		for _, r := range d.rows(i) {
			out = append(out, report.Found{Kind: r.kind, Files: r.where(), Paths: r.paths, Did: r.scanSays(off)})
		}
	}
	for _, u := range d.result.Unread {
		out = append(out, report.Found{Kind: "repository", Files: u.URL, Paths: []string{u.URL},
			Did: "not read · " + detect.UnreadReason})
	}
	return out
}

// rows are the FOUND rows of the i-th repository detect read. Where it read more than one, each
// path is the repository's url joined to it, so a row says which repository holds the file.
func (d *detection) rows(i int) []foundRow {
	repo := d.result.Read[i]
	rows := foundRows(repo.Tree)
	if len(d.result.Read) < 2 {
		return rows
	}
	for j := range rows {
		paths := make([]string, len(rows[j].paths))
		for k, p := range rows[j].paths {
			paths[k] = path.Join(repo.URL, p)
		}
		rows[j].paths = paths
	}
	return rows
}

// off are the names a FOUND row may give that the run will not run: each scanner turnOffUnrunnable
// turned off, and each control or scanner the model leaves off, which for a descriptor is one it
// turned off itself, `sast: {enabled: false}` turning sast off whatever detect found.
func (d *detection) off(reg *engine.Registry) []string {
	off := slices.Clone(d.turnedOff)
	running := map[string]bool{}
	for _, u := range needs.Uses(reg, d.model) {
		running[u.Info.Name] = true
		for _, c := range u.Controls {
			running[c] = true
		}
	}
	for i := range d.result.Read {
		for _, r := range foundRows(d.result.Read[i].Tree) {
			for _, name := range r.on {
				if registered(reg, name) && !running[name] && !slices.Contains(off, name) {
					off = append(off, name)
				}
			}
		}
	}
	return off
}

// registered reports whether name is a control or a scanner the registry knows, which a FOUND row
// may name. A row also names what is neither, such as the file patterns trivy-fs is given.
func registered(reg *engine.Registry, name string) bool {
	if _, ok := reg.Controller(name); ok {
		return true
	}
	_, ok := reg.Scanner(name)
	return ok
}

// turnOffUnrunnable turns off each scanner detect chose that this machine cannot run, and returns
// the files each one would have examined.
//
// A scanner detect chose is one the model runs that neither the base nor the descriptor asked for
// by name: gosec and govulncheck for a go.mod, retire.js for copied JavaScript, Grype for a file
// only it reads. Nobody chose it, and a reader who never chose a scanner cannot be told their
// configuration is broken, so a missing tool or runtime is a gap in what the run covered rather
// than a control that failed, and the run says which files went unexamined and what would examine
// them. A scanner the base runs, sca, secrets and sast's own, and one the descriptor names, keep
// the behavior a descriptor's always had: missing, it fails its control.
//
// Called once the install offer has had its answer, so what `draugr tools install` can fetch is
// offered before anything is turned off. A control outside the scope is left alone, since the run
// would not have reached its scanners.
func (d *detection) turnOffUnrunnable(reg *engine.Registry, scope engine.Scope, lookPath func(string) (string, error)) []report.Unexamined {
	base, err := zeroConfigBase()
	if err != nil {
		return nil
	}
	named := map[string]bool{}
	for _, m := range []*saga.Model{base, d.result.AsWritten(d.model)} {
		for _, u := range needs.Uses(reg, m) {
			named[u.Info.Name] = true
		}
	}
	var out []report.Unexamined
	for _, u := range needs.Uses(reg, d.model) {
		if named[u.Info.Name] || !slices.ContainsFunc(u.Controls, func(c string) bool { return inScope(scope, c) }) {
			continue
		}
		why := cannotRun(u.Info, lookPath)
		if why == "" {
			continue
		}
		turnOff(d.model, u.Info)
		keys := foundKeys(u, base)
		d.turnedOff = append(d.turnedOff, keys...)
		out = append(out, d.unexamined(keys, why)...)
	}
	return out
}

// unexamined is a caveat for each repository holding files a row turned one of keys on for, under
// the first component naming the repository, since the scanner is off for every component alike.
func (d *detection) unexamined(keys []string, why string) []report.Unexamined {
	var out []report.Unexamined
	for i, repo := range d.result.Read {
		rows := d.rows(i)
		paths := foundPaths(rows, keys...)
		if len(paths) == 0 {
			continue
		}
		out = append(out, report.Unexamined{Component: repo.Components[0], Files: foundFiles(rows, keys...),
			Paths: paths, Why: why})
	}
	return out
}

// foundKeys are the names a FOUND row may give for what turned a scanner on: the scanner's own, and
// each of its controls the base leaves off, which only the tree can have turned on. A row names iac
// for an infrastructure file, and trivy-config is the scanner iac runs.
func foundKeys(u needs.Use, base *saga.Model) []string {
	keys := []string{u.Info.Name}
	for _, c := range u.Controls {
		if !base.Config.ControllerEnabled(c) {
			keys = append(keys, c)
		}
	}
	return keys
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
