package engine

import (
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// InputCoverage is what the dependency scans of one component read for one control: how many
// dependency files at least one scanner took packages from, and the ones none did.
//
// Per control and not per scanner, because a file one scanner skips and another reads was read. Two
// scanners serving `sca` differ in what they accept, and reporting each one's gaps would warn about
// a requirements-dev.txt that Grype read while Trivy passed it by. A file an analysis could not cover
// (sarif.Input.Analysis), such as a Go module govulncheck could not load, is listed whoever read its
// packages, because reading them is not the analysis.
type InputCoverage struct {
	Component string
	Control   string
	// Scanners are the scanners that accounted for what they read, sorted. A scanner that does not
	// account says nothing either way and is not named.
	Scanners []string
	// Read counts the dependency files at least one of them took packages from.
	Read int
	// Unread are the files none of them did, by repository and path, and the files they read in
	// part, which Read counts too.
	Unread []UnreadInput
}

// UnreadInput is a dependency file no scan of a control read packages from.
type UnreadInput struct {
	Repository string
	Path       string
	// Reason is why it contributed nothing: "no lockfile", "no pinned versions" or "no packages
	// read", for a Terraform file the module blocks not loaded, as `module "vpc" not loaded`, and
	// for a Terraform root module the calls not evaluated, as `32 of 33 module calls checked;
	// "zbad" skipped`. For a file searched for secrets, "name has an archive extension", or at the
	// repository root "no files read". For a source file Semgrep skipped or did not finish,
	// `over 1 MB, not scanned` or the rules that timed out on it, as `1 rule timed out, not checked:
	// "x"`. For a go.mod, why govulncheck could not load the module.
	//
	// For a requirements file read in part, the requirements not read, as `1 requirement not
	// pinned: urllib3`, and for a pom.xml Trivy did not resolve, `2 dependency versions not
	// resolved, run mvn dependency:resolve` or `transitive dependencies not resolved, run mvn
	// dependency:resolve`.
	Reason string
}

// inputCoverage folds each control's reports into one coverage per component, sorted by
// component and then control.
func inputCoverage(byCtl map[string][]sarif.Report) []InputCoverage {
	type fileKey struct{ repository, path string }
	type scope struct{ component, control string }
	type acc struct {
		scanners map[string]bool
		read     map[fileKey]bool
		unread   map[fileKey]string
		// partly holds the files a scanner took some packages from, with what it did not take.
		partly map[fileKey]string
		// analysis holds the files an analysis of their code did not cover, which listed as unread
		// whoever read their packages.
		analysis map[fileKey]bool
	}
	scopes := map[scope]*acc{}
	for control, reports := range byCtl {
		for _, rep := range reports {
			for _, in := range rep.Inputs {
				k := scope{in.Component, control}
				a := scopes[k]
				if a == nil {
					a = &acc{scanners: map[string]bool{}, read: map[fileKey]bool{}, unread: map[fileKey]string{},
						partly: map[fileKey]string{}, analysis: map[fileKey]bool{}}
					scopes[k] = a
				}
				a.scanners[in.Scanner] = true
				f := fileKey{in.Repository, in.Path}
				if in.Analysis && in.Unread != "" {
					a.analysis[f] = true
				}
				if in.Unread == "" {
					a.read[f] = true
					continue
				}
				if in.Packages > 0 {
					// Read in part, so counted as read, and listed with what was not read unless
					// another scanner read all of it.
					if r, ok := a.partly[f]; !ok || in.Unread < r {
						a.partly[f] = in.Unread
					}
					continue
				}
				// Every scanner states the reason from the same recognizer, so the first is the
				// reason; kept stable across runs by preferring the lower one.
				if r, ok := a.unread[f]; !ok || in.Unread < r {
					a.unread[f] = in.Unread
				}
			}
		}
	}
	out := make([]InputCoverage, 0, len(scopes))
	for k, a := range scopes {
		cov := InputCoverage{Component: k.component, Control: k.control, Read: len(a.read)}
		for s := range a.scanners {
			cov.Scanners = append(cov.Scanners, s)
		}
		slices.Sort(cov.Scanners)
		for f, reason := range a.unread {
			if a.read[f] && !a.analysis[f] {
				continue
			}
			if _, some := a.partly[f]; some {
				continue
			}
			cov.Unread = append(cov.Unread, UnreadInput{Repository: f.repository, Path: f.path, Reason: reason})
		}
		for f, reason := range a.partly {
			if a.read[f] {
				continue
			}
			cov.Read++
			cov.Unread = append(cov.Unread, UnreadInput{Repository: f.repository, Path: f.path, Reason: reason})
		}
		slices.SortFunc(cov.Unread, func(x, y UnreadInput) int {
			if c := strings.Compare(x.Repository, y.Repository); c != 0 {
				return c
			}
			return strings.Compare(x.Path, y.Path)
		})
		out = append(out, cov)
	}
	slices.SortFunc(out, func(x, y InputCoverage) int {
		if c := strings.Compare(x.Component, y.Component); c != 0 {
			return c
		}
		return strings.Compare(x.Control, y.Control)
	})
	return out
}
