package engine

import (
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// InputCoverage is what the dependency scans of one component read for one control: how many
// dependency files at least one scanner took packages from, and the ones a scanner did not.
//
// A file one scanner read and another did not is listed with the scanner that missed it. Its
// packages were checked, but only by the scanner that read them, so a finding from that file has
// one source where the control has two, and a finding the other scanner would have made is absent
// for a reason the report has to state.
type InputCoverage struct {
	Component string
	Control   string
	// Scanners are the scanners that accounted for what they read, sorted. A scanner that does not
	// account says nothing either way and is not named.
	Scanners []string
	// Read counts the dependency files at least one of them took packages from.
	Read int
	// Unread are the files a scanner listed as unread and did not read, by repository and path.
	Unread []UnreadInput
}

// UnreadInput is a dependency file a scan of a control read no packages from.
type UnreadInput struct {
	Repository string
	Path       string
	// Scanners are the scanners that read no packages from the file where another scanner of the
	// control did, sorted. Empty when no scanner of the control read it.
	Scanners []string
	// Reason is why it contributed nothing: "no lockfile", "no pinned versions", "no packages
	// read", or for a file Trivy failed to parse "not parsed: " and the parser's error, as
	// `not parsed: JSON decode error: json: cannot unmarshal JSON string into Go map[string]interface
	// {} within "/packages/left-pad"`. For a Terraform file the module
	// blocks not loaded, as `module "vpc" not loaded`, and for a Terraform root module the calls
	// not evaluated, as `32 of 33 module calls checked; "zbad" skipped`. For a file searched for secrets, "name has an archive extension", or at the
	// repository root "no files read". For a source file Semgrep skipped or did not finish,
	// `over 1 MB, not scanned` or the rules that timed out on it, as `1 rule timed out, not checked:
	// "x"`.
	Reason string
}

// inputCoverage folds each control's reports into one coverage per component, sorted by
// component and then control.
func inputCoverage(byCtl map[string][]sarif.Report) []InputCoverage {
	type fileKey struct{ repository, path string }
	type scope struct{ component, control string }
	type acc struct {
		scanners map[string]bool
		// read and unread are keyed by file, then by scanner. unread holds each scanner's reason.
		read   map[fileKey]map[string]bool
		unread map[fileKey]map[string]string
	}
	scopes := map[scope]*acc{}
	for control, reports := range byCtl {
		for _, rep := range reports {
			for _, in := range rep.Inputs {
				k := scope{in.Component, control}
				a := scopes[k]
				if a == nil {
					a = &acc{scanners: map[string]bool{}, read: map[fileKey]map[string]bool{}, unread: map[fileKey]map[string]string{}}
					scopes[k] = a
				}
				a.scanners[in.Scanner] = true
				f := fileKey{in.Repository, in.Path}
				if in.Unread == "" {
					if a.read[f] == nil {
						a.read[f] = map[string]bool{}
					}
					a.read[f][in.Scanner] = true
					continue
				}
				if a.unread[f] == nil {
					a.unread[f] = map[string]string{}
				}
				// One scanner can state two reasons for one file, from its log and from the tree walk;
				// the lower is kept, so the reason is stable across runs.
				if r, ok := a.unread[f][in.Scanner]; !ok || in.Unread < r {
					a.unread[f][in.Scanner] = in.Unread
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
		for f, byScanner := range a.unread {
			if u, ok := unreadInput(f.repository, f.path, byScanner, a.read[f]); ok {
				cov.Unread = append(cov.Unread, u)
			}
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

// unreadInput is one file as the scanners of a control left it: unread by every scanner that
// listed it, or by the ones that listed it unread while another read it. False when every scanner
// that listed it unread also read it, which one scanner reading a file in two passes can produce.
//
// The reason is the lowest of the missing scanners' reasons, so it is stable across runs.
func unreadInput(repository, path string, unread map[string]string, read map[string]bool) (UnreadInput, bool) {
	u := UnreadInput{Repository: repository, Path: path}
	var missed []string
	for s, reason := range unread {
		if read[s] {
			continue
		}
		missed = append(missed, s)
		if u.Reason == "" || reason < u.Reason {
			u.Reason = reason
		}
	}
	if len(missed) == 0 {
		return UnreadInput{}, false
	}
	if len(read) > 0 {
		slices.Sort(missed)
		u.Scanners = missed
	}
	return u, true
}
