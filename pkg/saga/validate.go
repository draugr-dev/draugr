package saga

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// validDigest reports whether s is an OCI content digest of the form "algorithm:hex"
// (e.g. "sha256:…"): a non-empty lowercase-alphanumeric algorithm, a colon, and a
// non-empty lowercase-hex encoded value.
func validDigest(s string) bool {
	algo, hex, ok := strings.Cut(s, ":")
	if !ok || algo == "" || hex == "" {
		return false
	}
	for _, r := range algo {
		if !isLowerAlnum(r) {
			return false
		}
	}
	for _, r := range hex {
		if !isLowerHex(r) {
			return false
		}
	}
	return true
}

func isLowerAlnum(r rune) bool { return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }
func isLowerHex(r rune) bool   { return r >= 'a' && r <= 'f' || r >= '0' && r <= '9' }

// Validate checks the descriptor for structural correctness, returning all problems at
// once (joined) rather than only the first.
func (m *Model) Validate() error {
	var errs []error

	if m.Release.Version == "" {
		errs = append(errs, errors.New("release.version is required"))
	}

	errs = append(errs, validateControllerKeys("", m.Config.Controllers)...)

	errs = append(errs, validateComponents(m.Components)...)

	for i, r := range m.Config.Reports {
		if r.Format == "" {
			errs = append(errs, fmt.Errorf("config.reports[%d].format is required", i))
		}
		if r.MinPriority != "" && !slices.Contains(Priorities, r.MinPriority) {
			errs = append(errs, fmt.Errorf("config.reports[%d].minPriority is %q, but a priority band is one of %v",
				i, r.MinPriority, Priorities))
		}
	}
	if g := m.Config.Gate; g != nil {
		for control, level := range g.Controls {
			if !slices.Contains(GateLevels, level) {
				errs = append(errs, fmt.Errorf("config.gate.controls[%q] = %q is not a threshold (want one of %v)",
					control, level, GateLevels))
			}
		}
	}
	errs = append(errs, validateExclusions(m.Config.Exclude, "config.exclude")...)
	errs = append(errs, validateFragmentRefs(m.Fragments, "fragments")...)

	if x := m.Config.Exploitability; x != nil {
		if t := x.EPSSThreshold; t != nil && (*t < 0 || *t > 1) {
			errs = append(errs, fmt.Errorf(
				"config.exploitability.epssThreshold is %v, but EPSS is a probability (0–1)", *t))
		}
		if x.MaxAge != "" {
			if _, err := time.ParseDuration(x.MaxAge); err != nil {
				errs = append(errs, fmt.Errorf(
					"config.exploitability.maxAge %q is not a duration (want e.g. 24h, 30m, 168h)", x.MaxAge))
			}
		}
		// A path is anything else, and cannot be checked here — the descriptor may name a file
		// this machine does not have, which is a legitimate thing for a shared descriptor to do
		// and a scan-time error rather than a validation one.
	}
	if s := m.Config.SBOM; s != nil && s.Format != "" && !s.Format.Valid() {
		errs = append(errs, fmt.Errorf("config.sbom.format %q is not a known format (want one of %v)", s.Format, SBOMFormats))
	}
	if s := m.Config.SBOM; s != nil && s.Scope != "" && !s.Scope.Valid() {
		errs = append(errs, fmt.Errorf("config.sbom.scope %q is not a known scope (want one of %v)", s.Scope, SBOMScopes))
	}
	for i, p := range m.Config.Publishers {
		if p.Kind == "" {
			errs = append(errs, fmt.Errorf("config.publishers[%d].kind is required", i))
		}
	}

	return errors.Join(errs...)
}

// camelCaseKey converts a hyphenated key to the camelCase form the descriptor uses, so the error
// can name the replacement instead of only rejecting what was written.
func camelCaseKey(key string) string {
	parts := strings.Split(key, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

// removedControllerKeys are settings that no longer exist, and what replaced them.
//
// A removed key is not inert: it is read by nothing and changes nothing, so a descriptor asking
// for behaviour it no longer has scans differently than its author believes and reports a pass
// either way. Naming the replacement costs one line here and saves the reader from discovering
// it by comparing two reports.
var removedControllerKeys = map[string]map[string]string{
	// Empty on purpose. A key that names no scanner is already rejected with the list of keys
	// the control does accept, which covers every rename without an entry here.
	//
	// This is for the case that error cannot serve: a setting whose replacement is not a
	// renaming but a different shape, where knowing the old name is the only way to explain the
	// new one. `infrastructure.mode` was one — it became per-scanner blocks — and there are no
	// users to migrate today, so it is gone with it.
}

// validateControllerKeys rejects descriptor keys that do not follow the schema's convention.
//
// Every field in a Saga is camelCase. Controller settings are a free-form tree, so nothing in the
// type system holds them to it, and a hyphenated key does not fail — it is simply never matched.
// A scanner block written as `kube-bench-job: { enabled: true }` selects no scanner and produces
// a scan that ran one fewer than asked for, reporting a pass on a benchmark half of which never
// ran. Silence is the failure mode; this makes it an error at load, before any work is done.
// validateRepoScope rejects scope entries that cannot mean what they appear to.
//
// Caught at load rather than at scan time: a pattern that matches nothing narrows the scan
// silently, and the run that follows reports fewer findings against a tree it never looked at.
// That is the same shape as a clean result, which is why it has to be an error and not a
// smaller report.
func validateRepoScope(where string, r Repository) []error {
	var errs []error
	check := func(field string, values []string) {
		for i, v := range values {
			at := fmt.Sprintf("%s.%s[%d]", where, field, i)
			t := strings.TrimSpace(v)
			switch {
			case t == "":
				errs = append(errs, fmt.Errorf("%s is empty", at))
			case strings.HasPrefix(t, "/"):
				errs = append(errs, fmt.Errorf(
					"%s is absolute (%q) — scope is relative to the repository root", at, v))
			case t == ".." || strings.HasPrefix(t, "../") || strings.Contains(t, "/../"):
				errs = append(errs, fmt.Errorf(
					"%s escapes the repository (%q)", at, v))
			}
		}
	}
	check("paths", r.Paths)
	check("ignore", r.Ignore)
	return errs
}

func validateControllerKeys(where string, controllers map[string]ControllerSettings) []error {
	var errs []error
	for control, settings := range controllers {
		for key := range settings {
			if replacement, gone := removedControllerKeys[control][key]; gone {
				errs = append(errs, fmt.Errorf(
					"%scontrollers.%s.%s was removed. Use %s",
					where, control, key, replacement))
				continue
			}
			if !strings.Contains(key, "-") {
				continue
			}
			errs = append(errs, fmt.Errorf(
				"%scontrollers.%s.%s: descriptor keys are camelCase — use %q",
				where, control, key, camelCaseKey(key)))
		}
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}

// validateComponents checks each component's own fields, and that no two share a name.
//
// Shared by a Model and a Fragment, so a fragment is held to the same rules on its own as it will
// be once merged. A fragment that only validates in context is one nobody can check.
func validateComponents(comps []Component) []error {
	var errs []error
	seen := map[string]bool{}
	for i, c := range comps {
		errs = append(errs, validateControllerKeys(fmt.Sprintf("components[%d].", i), c.Controllers)...)
		where := fmt.Sprintf("components[%d]", i)
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", where))
		} else {
			if seen[c.Name] {
				errs = append(errs, fmt.Errorf("%s: duplicate component name %q", where, c.Name))
			}
			seen[c.Name] = true
			where = fmt.Sprintf("component %q", c.Name)
		}

		if c.Exposure != "" && !c.Exposure.Valid() {
			errs = append(errs, fmt.Errorf("%s: invalid exposure %q (want one of %v)", where, c.Exposure, Exposures))
		}
		if c.Criticality != "" && !c.Criticality.Valid() {
			errs = append(errs, fmt.Errorf("%s: invalid criticality %q (want one of %v)", where, c.Criticality, Criticalities))
		}

		for j, r := range c.Repositories {
			if r.URL == "" {
				errs = append(errs, fmt.Errorf("%s: repositories[%d].url is required", where, j))
			}
			errs = append(errs, validateRepoScope(fmt.Sprintf("%s: repositories[%d]", where, j), r)...)
		}
		for j, img := range c.Images {
			if img.Image == "" {
				errs = append(errs, fmt.Errorf("%s: images[%d].image is required", where, j))
			}
			if img.Digest != "" && !validDigest(img.Digest) {
				errs = append(errs, fmt.Errorf("%s: images[%d].digest %q must be of the form algorithm:hex (e.g. sha256:…)", where, j, img.Digest))
			}
		}
		for j, h := range c.Hosts {
			if h.URL == "" {
				errs = append(errs, fmt.Errorf("%s: hosts[%d].url is required", where, j))
			}
		}
	}
	return errs
}

// validateExclusions checks an exclusion block. prefix names it, so the same errors read
// correctly whether they came from a descriptor or from a fragment.
func validateExclusions(rules []ExcludeRule, prefix string) []error {
	var errs []error
	for i, e := range rules {
		where := fmt.Sprintf("%s[%d]", prefix, i)
		// Without a reason an exclusion is indistinguishable from an oversight six months on,
		// and a reviewer has nothing to judge. It is the cheapest guard against a scanner
		// being quietly defanged.
		if strings.TrimSpace(e.Reason) == "" {
			errs = append(errs, fmt.Errorf("%s: reason is required — say why this is excluded", where))
		}
		// A date that does not parse is worse than no date: the exclusion would keep suppressing
		// forever while the descriptor claims it lapses, which is the belief this field exists
		// to make true.
		if e.Expires != "" {
			if _, err := time.Parse(expiresLayout, e.Expires); err != nil {
				errs = append(errs, fmt.Errorf(
					"%s: expires must be a date as YYYY-MM-DD, got %q — an unreadable date would "+
						"suppress indefinitely while claiming not to", where, e.Expires))
			}
		}
		// Neither selector set would match every finding in the project.
		if len(e.Paths) == 0 && len(e.Rules) == 0 {
			errs = append(errs, fmt.Errorf("%s: set paths, rules, or both — an exclusion with neither would suppress everything", where))
		}
		for j, p := range e.Paths {
			if strings.TrimSpace(p) == "" {
				errs = append(errs, fmt.Errorf("%s: paths[%d] is empty", where, j))
			}
		}
		// A VEX status is a claim a consumer acts on without reading it, so a value outside the
		// vocabulary cannot be passed through and cannot be dropped: either would publish
		// something other than what the descriptor says.
		if v := e.VEX; v != nil {
			switch {
			case v.Status == "":
				errs = append(errs, fmt.Errorf("%s: vex.status is required when vex is set (one of %s)",
					where, strings.Join(VEXStatuses, ", ")))
			case !ValidVEXStatus(v.Status):
				hint := ""
				if v.Status == VEXUnderInvestigation {
					hint = " — a finding you have suppressed is one you have finished investigating; " +
						"it is what Draugr already reports for findings nobody has triaged"
				}
				errs = append(errs, fmt.Errorf("%s: vex.status %q is not a status an exclusion may declare (want %s)%s",
					where, v.Status, strings.Join(VEXStatuses, ", "), hint))
			}
			if v.Justification != "" {
				if v.Status != VEXNotAffected && v.Status != "" {
					errs = append(errs, fmt.Errorf(
						"%s: vex.justification applies only to status %s, not %q — it answers why the "+
							"product is unaffected", where, VEXNotAffected, v.Status))
				} else if !ValidVEXJustification(v.Justification) {
					errs = append(errs, fmt.Errorf(
						"%s: vex.justification %q is not one of VEX's justifications (want %s)",
						where, v.Justification, strings.Join(VEXJustifications, ", ")))
				}
			}
		}
	}

	return errs
}

// validateFragmentRefs checks the references used to pull in further fragments.
func validateFragmentRefs(refs []FragmentRef, prefix string) []error {
	var errs []error
	for i, f := range refs {
		where := fmt.Sprintf("%s[%d]", prefix, i)
		if strings.TrimSpace(f.Path) == "" {
			errs = append(errs, fmt.Errorf("%s: path is required — it selects which files to merge", where))
		}
		// A remote fragment with no revision is a gate that changes with no commit in your own
		// repository. Refusing costs one line in the descriptor; defaulting to the default branch
		// would make every scan quietly depend on somebody else's next push.
		if f.Remote() && strings.TrimSpace(f.Revision) == "" {
			errs = append(errs, fmt.Errorf(
				"%s: revision is required when url is set — name a tag, branch or commit so the "+
					"fragment cannot change without a change here", where))
		}
		if !f.Remote() && f.Revision != "" {
			errs = append(errs, fmt.Errorf(
				"%s: revision applies only with url — a local path is read from this checkout", where))
		}
	}
	return errs
}

// joinErrs collapses a slice of problems into one error, or nil.
func joinErrs(errs []error) error { return errors.Join(errs...) }
