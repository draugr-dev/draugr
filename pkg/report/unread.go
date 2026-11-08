package report

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/internal/registry"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// unreadGroup is one component's unread files, each named once however many controls missed it
// for the same reason.
type unreadGroup struct {
	component string
	files     []unreadFile
}

type unreadFile struct {
	label, reason string
	controls      []string
	// path and kind are the file's path in its repository and the scanner's name for its format, and
	// repository is the repository, which label only names where the component scans several.
	path, kind, repository string
}

// unreadByComponent folds per-control coverage into one entry per component.
//
// Per component because the fix is per file: a pyproject.toml with no lockfile is one lockfile to
// commit, whether one control or two passed it by, and a block per control would print it twice.
// Two controls that give one file different reasons keep a row each, because a reason names what
// clears it for the controls beside it: a pom.xml Trivy did not resolve clears for licenses with
// `mvn dependency:resolve`, while under sca with grype-fs alone nothing clears it. A path is named with its repository where the component scans more than one, because two
// repositories can each hold a package.json. That is decided by the repositories the run planned
// for the component, not only by the ones holding an unread file: with one of two repositories'
// files unread, a bare path does not say which repository to open.
func unreadByComponent(inputs []engine.InputCoverage, targets []engine.TargetOutcome) []unreadGroup {
	var out []unreadGroup
	index := map[string]int{}
	type fileKey struct{ repository, path, reason string }
	files := map[string]map[fileKey]int{}
	repos := map[string]map[string]bool{}
	for _, c := range inputs {
		for _, u := range c.Unread {
			i, ok := index[c.Component]
			if !ok {
				i = len(out)
				index[c.Component] = i
				out = append(out, unreadGroup{component: c.Component})
				files[c.Component] = map[fileKey]int{}
				repos[c.Component] = map[string]bool{}
			}
			repos[c.Component][u.Repository] = true
			k := fileKey{u.Repository, u.Path, u.Reason}
			j, seen := files[c.Component][k]
			if !seen {
				j = len(out[i].files)
				files[c.Component][k] = j
				out[i].files = append(out[i].files, unreadFile{label: u.Repository + "\x00" + u.Path, reason: u.Reason,
					path: u.Path, kind: u.Kind, repository: u.Repository})
			}
			out[i].files[j].controls = append(out[i].files[j].controls, c.Control)
		}
	}
	planned := repositoriesByComponent(targets)
	for i := range out {
		several := len(repos[out[i].component]) > 1 || planned[out[i].component] > 1
		for j := range out[i].files {
			repo, path, _ := strings.Cut(out[i].files[j].label, "\x00")
			if out[i].files[j].kind == sarif.InputOperatingSystem {
				// An image, named as the errors block names one, its digest shortened.
				out[i].files[j].label = registry.ShortDigest(path)
				continue
			}
			out[i].files[j].label = path
			if several {
				out[i].files[j].label = shortRepository(repo) + ":" + path
			}
		}
	}
	return out
}

// unreadRow is one caveat row for a component's unread files: one file, or several folded into one.
type unreadRow struct {
	what, reason string
	controls     []string
	// files are the files a folded row stands for, which --evidence lists; nil for a row of one.
	files []unreadFile
	// places are the files the row names, one or several, which a SARIF notification locates.
	places []unreadFile
}

// unreadRows is a component's caveat rows, one per file except where files are folded.
//
// Folded only where the license scan read a file's packages and none of their licenses, and only
// with the component's other files of the same format whose licenses are cleared by the same command
// or by none. Those rows differ in nothing but a count, and a workspace of forty crates otherwise
// prints forty of them. Every other reason names something about its own file, a dependency, a
// module, a parser's error, and keeps its row.
func unreadRows(g unreadGroup) []unreadRow {
	type key struct{ kind, command string }
	var out []unreadRow
	at := map[key]int{}
	packages := map[key]int{}
	for _, f := range g.files {
		n, command, ok := manifests.ParseLicensesNotRead(f.reason)
		if !ok || !slices.Equal(f.controls, []string{"licenses"}) {
			out = append(out, unreadRow{what: f.label, reason: f.reason, controls: f.controls, places: []unreadFile{f}})
			continue
		}
		k := key{cmp.Or(f.kind, path.Base(f.path)), command}
		i, seen := at[k]
		if !seen {
			at[k] = len(out)
			packages[k] = n
			out = append(out, unreadRow{what: f.label, reason: f.reason, controls: f.controls,
				files: []unreadFile{f}, places: []unreadFile{f}})
			continue
		}
		packages[k] += n
		out[i].files = append(out[i].files, f)
		out[i].places = append(out[i].places, f)
		out[i].what = foldedName(k.kind, out[i].files)
		out[i].reason = manifests.LicensesNotRead(packages[k], command)
	}
	for i := range out {
		if len(out[i].files) < 2 {
			out[i].files = nil
		}
	}
	return out
}

// kindNames are the formats whose files go by more than one name, by the scanner's name for the
// format, as a folded row of mixed names calls them.
var kindNames = map[string]string{
	"nuget":          "NuGet files",
	"pip":            "requirements files",
	"gradle":         "Gradle lockfiles",
	"dotnet-core":    ".deps.json files",
	"packages-props": "Packages.props files",
	"bundler":        "Bundler lockfiles",
}

// foldedName is what a folded row names: the files' own name and how many, as `Cargo.lock ×3`,
// where they share one, which is the name a reader searches the tree for. Where the names differ,
// a packages.lock.json beside a packages.config, the format's name, as `NuGet files ×2`.
func foldedName(kind string, files []unreadFile) string {
	name := path.Base(files[0].path)
	for _, f := range files[1:] {
		if path.Base(f.path) != name {
			name = cmp.Or(kindNames[kind], kind+" files")
			break
		}
	}
	return fmt.Sprintf("%s ×%d", name, len(files))
}

// foldedLines are the evidence rows for the files a folded caveat row stands for, one per file, as
// `licenses · api · crates/cli/Cargo.lock · records no licenses for 3 packages`. A row of one file
// already names its path, and is not repeated here.
func foldedLines(groups []unreadGroup) []string {
	var out []string
	for _, g := range groups {
		for _, r := range unreadRows(g) {
			for _, f := range r.files {
				out = append(out, strings.Join([]string{strings.Join(f.controls, ", "), g.component, f.label, f.reason}, " · "))
			}
		}
	}
	return out
}

// missedLines are the evidence rows for the files one scanner of a control read no packages from
// while another scanner of the control read them, one per file and scanner, as `sca: grype-fs ·
// android · buildscript-gradle.lockfile · no packages read`.
//
// Evidence and not a caveat: the file's packages were checked, by the other scanner, so nothing in
// it went unexamined. What the row records is which scanner a finding from that file could have come
// from. The path carries its repository where the component scans more than one, as a caveat's does.
func missedLines(inputs []engine.InputCoverage, targets []engine.TargetOutcome) []string {
	planned := repositoriesByComponent(targets)
	repos := map[string]map[string]bool{}
	for _, c := range inputs {
		for _, m := range c.Missed {
			if repos[c.Component] == nil {
				repos[c.Component] = map[string]bool{}
			}
			repos[c.Component][m.Repository] = true
		}
	}
	var out []string
	for _, c := range inputs {
		several := len(repos[c.Component]) > 1 || planned[c.Component] > 1
		for _, m := range c.Missed {
			file := m.Path
			if several {
				file = shortRepository(m.Repository) + ":" + m.Path
			}
			out = append(out, strings.Join([]string{c.Control + ": " + m.Scanner, c.Component, file, m.Reason}, " · "))
		}
	}
	return out
}

// unreadNote is what a control's row says about the files its scans did not read in full, across
// every component, as `11 files unread`, and empty where there are none. The caveats name them.
func unreadNote(inputs []engine.InputCoverage, control string) string {
	files, systems := 0, 0
	for _, c := range inputs {
		if c.Control != control {
			continue
		}
		for _, u := range c.Unread {
			if u.Kind == sarif.InputOperatingSystem {
				systems++
			} else {
				files++
			}
		}
	}
	var parts []string
	if files > 0 {
		parts = append(parts, english.Count(files, "file")+" unread")
	}
	if systems > 0 {
		parts = append(parts, english.Count(systems, "operating system")+" not checked")
	}
	return strings.Join(parts, " · ")
}

// repositoriesByComponent counts the distinct repositories the run planned for each component. One
// repository at two revisions is one repository.
func repositoriesByComponent(targets []engine.TargetOutcome) map[string]int {
	seen := map[string]map[string]bool{}
	for _, t := range targets {
		if t.Kind != "repository" {
			continue
		}
		source, _, _ := strings.Cut(t.Target, "@")
		for _, c := range t.Components {
			if seen[c] == nil {
				seen[c] = map[string]bool{}
			}
			seen[c][source] = true
		}
	}
	out := make(map[string]int, len(seen))
	for c, s := range seen {
		out[c] = len(s)
	}
	return out
}
