package engine

import (
	"cmp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// InputCoverage is what the dependency scans of one component read for one control: how many
// dependency files at least one scanner took packages from, and the ones none did.
//
// Unread is per control and not per scanner, because a file one scanner skips and another reads was
// read: it is the caveat, and what the gate counts. A file an analysis could not cover
// (sarif.Input.Analysis), such as a Go module govulncheck could not load, is listed whoever read its
// packages, because reading them is not the analysis. What each scanner missed of a file another
// read is kept apart, in Missed, as a record of which scanner a finding from that file could have
// come from.
type InputCoverage struct {
	Component string
	Control   string
	// Scanners are the scanners that accounted for what they read, sorted. A scanner that does not
	// account says nothing either way and is not named.
	Scanners []string
	// Read counts the dependency files at least one of them took packages from, the files read in
	// part included.
	Read int
	// Unread are the files none of them did, by repository and path, and the files they read in
	// part, which Read counts too and which are marked Partly.
	Unread []UnreadInput
	// Missed are the files a scanner took no packages from where another scanner of the control
	// took some, one entry per file and scanner, by repository, path and scanner. Read counts them,
	// and Unread does not list them.
	Missed []MissedInput
}

// UnreadInput is a dependency file no scan of a control read packages from.
type UnreadInput struct {
	Repository string
	Path       string
	// Reason is why it contributed nothing: "no lockfile", "no pinned versions", "no packages
	// read", or for a file Trivy failed to parse "not parsed: " and the parser's error, as
	// `not parsed: JSON decode error: json: cannot unmarshal JSON string into Go
	// map[string]interface {} within "/packages/left-pad"`. For a Terraform file the module blocks
	// not loaded, as `module "vpc" not loaded`, and for a Terraform root module the calls not
	// evaluated, as `32 of 33 module calls checked; "zbad" skipped`. For a Helm chart's Chart.yaml,
	// what stopped Trivy rendering the chart, as `run helm dependency build; redis not in
	// charts/`. For a file searched for
	// secrets, "name has an archive extension", or at the repository root "no files read". For a
	// source file Semgrep skipped or did not finish, `over 1 MB, not scanned` or the rules that
	// timed out on it, as `1 rule timed out, not checked: "x"`. For a go.mod, why govulncheck could
	// not load the module.
	//
	// For a requirements file read in part, the requirements not read, as `1 requirement not
	// pinned: urllib3`, and for a pom.xml Trivy did not resolve, `2 dependency versions not
	// resolved, run mvn dependency:resolve` or `transitive dependencies not resolved, run mvn
	// dependency:resolve`. For a file whose packages the license scan read with no license for any,
	// `records no licenses for 12 packages`, or `licenses of 12 packages not read, run dotnet
	// restore` (or `run go mod download`) where a command fills the cache the licenses are read from.
	Reason string
	// Kind is the scanner's name for the file's format (sarif.Input.Kind), empty where none said.
	Kind string
	// Partly marks a file a scan took some packages from and not all, which Read counts as read.
	Partly bool
}

// MissedInput is a dependency file one scanner of a control read no packages from while another
// scanner of the control read it.
type MissedInput struct {
	Repository string
	Path       string
	// Scanner is the scanner that read no packages from it.
	Scanner string
	// Reason is that scanner's reason, in the words UnreadInput.Reason uses.
	Reason string
}

// inputCoverage folds each control's reports into one coverage per component, sorted by
// component and then control.
func inputCoverage(byCtl map[string][]sarif.Report) []InputCoverage {
	type fileKey struct{ repository, path string }
	type scope struct{ component, control string }
	type acc struct {
		scanners map[string]bool
		// read holds the files a scanner took every package from, with the scanners that did.
		read   map[fileKey]map[string]bool
		unread map[fileKey]string
		// partly holds the files a scanner took some packages from, with what it did not take, and
		// partlyBy the scanners that did.
		partly   map[fileKey]string
		partlyBy map[fileKey]map[string]bool
		// analysis holds the files an analysis of their code did not cover, which listed as unread
		// whoever read their packages.
		analysis map[fileKey]bool
		// missed holds, for each file, the scanners that took no package from it and their reasons.
		// A file another scanner read is a record of that scanner's gap, and not a caveat.
		missed map[fileKey]map[string]string
		// kinds holds the format a scanner named for each file.
		kinds map[fileKey]string
	}
	scopes := map[scope]*acc{}
	for control, reports := range byCtl {
		for _, rep := range reports {
			for _, in := range rep.Inputs {
				k := scope{in.Component, control}
				a := scopes[k]
				if a == nil {
					a = &acc{scanners: map[string]bool{}, read: map[fileKey]map[string]bool{}, unread: map[fileKey]string{},
						partly: map[fileKey]string{}, partlyBy: map[fileKey]map[string]bool{}, analysis: map[fileKey]bool{},
						missed: map[fileKey]map[string]string{}, kinds: map[fileKey]string{}}
					scopes[k] = a
				}
				a.scanners[in.Scanner] = true
				f := fileKey{in.Repository, in.Path}
				if in.Kind != "" && a.kinds[f] == "" {
					a.kinds[f] = in.Kind
				}
				if in.Analysis && in.Unread != "" {
					a.analysis[f] = true
				}
				if in.Unread == "" {
					addTo(a.read, f, in.Scanner)
					continue
				}
				if in.Packages > 0 {
					// Read in part, so counted as read, and listed with what was not read unless
					// another scanner read all of it.
					if r, ok := a.partly[f]; !ok || betterPartReason(in.Unread, r) {
						a.partly[f] = in.Unread
					}
					addTo(a.partlyBy, f, in.Scanner)
					continue
				}
				if r, ok := a.unread[f]; !ok || betterReason(in.Unread, r) {
					a.unread[f] = in.Unread
				}
				if in.Analysis {
					continue
				}
				if a.missed[f] == nil {
					a.missed[f] = map[string]string{}
				}
				if r, ok := a.missed[f][in.Scanner]; !ok || betterReason(in.Unread, r) {
					a.missed[f][in.Scanner] = in.Unread
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
			if len(a.read[f]) > 0 && !a.analysis[f] {
				continue
			}
			if _, some := a.partly[f]; some {
				continue
			}
			cov.Unread = append(cov.Unread, UnreadInput{Repository: f.repository, Path: f.path, Reason: reason, Kind: a.kinds[f]})
		}
		for f, reason := range a.partly {
			if len(a.read[f]) > 0 {
				continue
			}
			cov.Read++
			cov.Unread = append(cov.Unread, UnreadInput{Repository: f.repository, Path: f.path, Reason: reason, Kind: a.kinds[f], Partly: true})
		}
		for f, byScanner := range a.missed {
			if len(a.read[f]) == 0 && len(a.partlyBy[f]) == 0 {
				continue
			}
			for s, reason := range byScanner {
				if a.read[f][s] || a.partlyBy[f][s] {
					continue
				}
				cov.Missed = append(cov.Missed, MissedInput{Repository: f.repository, Path: f.path, Scanner: s, Reason: reason})
			}
		}
		slices.SortFunc(cov.Unread, func(x, y UnreadInput) int {
			return cmp.Or(strings.Compare(x.Repository, y.Repository), strings.Compare(x.Path, y.Path))
		})
		slices.SortFunc(cov.Missed, func(x, y MissedInput) int {
			return cmp.Or(strings.Compare(x.Repository, y.Repository), strings.Compare(x.Path, y.Path),
				strings.Compare(x.Scanner, y.Scanner))
		})
		out = append(out, cov)
	}
	slices.SortFunc(out, func(x, y InputCoverage) int {
		return cmp.Or(strings.Compare(x.Component, y.Component), strings.Compare(x.Control, y.Control))
	})
	return out
}

// addTo records that scanner did something with file.
func addTo[K comparable](m map[K]map[string]bool, file K, scanner string) {
	if m[file] == nil {
		m[file] = map[string]bool{}
	}
	m[file][scanner] = true
}

// betterReason reports whether reason a says more than b about a file. A reason that names a cause,
// such as the parser's error, says more than "no packages read", which every scanner gives for a
// file it passed over; otherwise the lower is kept, so the reason is stable across runs.
func betterReason(a, b string) bool {
	generic := string(manifests.NotRead)
	if (a == generic) != (b == generic) {
		return b == generic
	}
	return a < b
}

// betterPartReason reports whether reason a, for a file a scanner read in part, is the one to show
// over b. A reason that names a scanner's own limit (manifests.ScannerLimit) gives way to one the
// reader can act on; otherwise the lower is kept, so the reason is stable across runs.
func betterPartReason(a, b string) bool {
	if la, lb := manifests.ScannerLimit(a), manifests.ScannerLimit(b); la != lb {
		return lb
	}
	return a < b
}
