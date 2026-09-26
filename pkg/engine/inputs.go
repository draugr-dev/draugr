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
// a requirements-dev.txt that Grype read while Trivy passed it by.
type InputCoverage struct {
	Component string
	Control   string
	// Scanners are the scanners that accounted for what they read, sorted. A scanner that does not
	// account says nothing either way and is not named.
	Scanners []string
	// Read counts the dependency files at least one of them took packages from.
	Read int
	// Unread are the files none of them did, by repository and path.
	Unread []UnreadInput
}

// UnreadInput is a dependency file no scan of a control read packages from.
type UnreadInput struct {
	Repository string
	Path       string
	// Reason is why it contributed nothing: "no lockfile", "no pinned versions" or "no packages
	// read", or for a Terraform file the module blocks not loaded, as `module "vpc" not loaded`.
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
	}
	scopes := map[scope]*acc{}
	for control, reports := range byCtl {
		for _, rep := range reports {
			for _, in := range rep.Inputs {
				k := scope{in.Component, control}
				a := scopes[k]
				if a == nil {
					a = &acc{scanners: map[string]bool{}, read: map[fileKey]bool{}, unread: map[fileKey]string{}}
					scopes[k] = a
				}
				a.scanners[in.Scanner] = true
				f := fileKey{in.Repository, in.Path}
				if in.Unread == "" {
					a.read[f] = true
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
			if a.read[f] {
				continue
			}
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
