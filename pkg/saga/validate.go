package saga

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/converter"
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

// projectName is what a project may be called: the shape of a slug, because it is what a platform
// files runs under and what appears in a URL.
var projectName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Validate checks the descriptor for structural correctness, returning all problems at
// once (joined) rather than only the first.
func (m *Model) Validate() error {
	var errs []error

	if m.Project != "" && !projectName.MatchString(m.Project) {
		errs = append(errs, fmt.Errorf(
			"project %q: lowercase letters, digits and dashes, starting and ending with a letter "+
				"or digit", m.Project))
	}
	// A reference without its link points a reader at nothing, and one without its type does not
	// say what the document is.
	for i, r := range m.References {
		if r.Type == "" {
			errs = append(errs, fmt.Errorf("references[%d].type is required, the kind of document, such as ThreatModel", i))
		}
		if r.Link == "" {
			errs = append(errs, fmt.Errorf("references[%d].link is required, the document's address", i))
		}
	}

	errs = append(errs, validateControllerKeys("config.", m.Config.Controls)...)

	errs = append(errs, validateComponents(m.Components)...)
	errs = append(errs, validateClusters(m.Clusters, m.Components)...)
	errs = append(errs, validateAccounts(m.Accounts, m.Components)...)
	for _, conflict := range m.accountConflicts {
		errs = append(errs, errors.New(conflict))
	}
	for _, conflict := range m.clusterConflicts {
		errs = append(errs, errors.New(conflict))
	}
	errs = append(errs, m.Config.AllowEffects.validate()...)

	for i, p := range m.Config.Publishers {
		for j, r := range p.Reports {
			if r.Format == "" {
				errs = append(errs, fmt.Errorf("config.publishers[%d].reports[%d].format is required", i, j))
			}
			if r.MinPriority != "" && !slices.Contains(Priorities, r.MinPriority) {
				errs = append(errs, fmt.Errorf(
					"config.publishers[%d].reports[%d].minPriority is %q, but a priority band is %s",
					i, j, r.MinPriority, orList(Priorities)))
			}
		}
		errs = append(errs, p.validateIssueFields(i)...)
	}
	if f := m.Config.Fixes; f != nil && f.Upgrade != "" && !f.Upgrade.Valid() {
		errs = append(errs, fmt.Errorf("config.fixes.upgrade %q is not %s", f.Upgrade, orList(UpgradeSteps)))
	}
	if g := m.Config.Gate; g != nil {
		if g.FailOnPriority != "" && !slices.Contains(Priorities, g.FailOnPriority) {
			errs = append(errs, fmt.Errorf("config.gate.failOnPriority is %q, but a priority band is %s",
				g.FailOnPriority, orList(Priorities)))
		}
		kind, _, err := ParseGate(g.FailOn)
		if err != nil {
			errs = append(errs, fmt.Errorf("config.gate.failOn: %w", err))
		}
		// `failOnPriority` is the older spelling of the same decision. Refused beside `failOn`
		// rather than resolved by a precedence nobody can see in the file, because whichever lost
		// would be a rule sitting in a reviewed descriptor doing nothing.
		if g.FailOn != "" && g.FailOnPriority != "" {
			errs = append(errs, fmt.Errorf(
				"config.gate sets both failOn and failOnPriority, which are two spellings of one "+
					"decision. Write the band in failOn: it takes a band (%s) or a severity (%s)",
				strings.Join(Priorities, ", "), strings.Join(gateSeverityWords(), ", ")))
		}
		errs = append(errs, validateCaveatKinds(g.FailOnCaveats, "config.gate.failOnCaveats")...)
		if _, _, err := ParseGate(g.FailOnNew); err != nil {
			errs = append(errs, fmt.Errorf("config.gate.failOnNew: %w", err))
		}
		// The same vocabulary throughout, because the run asks one question. A band under a
		// severity gate, or a severity under a band gate, is a second question asked of one
		// control and puts the reader back where two keys left them.
		//
		// Nothing written is not nothing in force. The gate defaults to a band, so a descriptor
		// that sets only per-control thresholds has one to refine and simply did not write it
		// down.
		want := kind
		if want == GateNone {
			want = GatePriority
		}
		for control, value := range g.Controls {
			got, _, err := ParseGate(value)
			if err != nil {
				errs = append(errs, fmt.Errorf("config.gate.controls[%q]: %w", control, err))
				continue
			}
			if got == want {
				continue
			}
			// Which gate it disagrees with decides what to say. A reader who wrote `failOn` is
			// told their two halves ask different questions; a reader who wrote none is told the
			// default moved under them, which is what actually happened and is not their mistake.
			if kind == GateNone && g.FailOnPriority == "" {
				errs = append(errs, fmt.Errorf(
					"config.gate.controls[%q] is %q and the gate it refines is the band %s, which "+
						"asks the other question. Write `failOn: %s` to judge this run on "+
						"severity, or write these thresholds as bands (%s)",
					control, value, DefaultGateBand, value, strings.Join(Priorities, ", ")))
				continue
			}
			errs = append(errs, fmt.Errorf(
				"config.gate.controls[%q] is %q and config.gate.failOn asks the other "+
					"question. One run, one vocabulary: write both as bands, or both as "+
					"severities", control, value))
		}
	}
	errs = append(errs, validateVEXSources("config", m.Config.VEXSources)...)
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
		if len(x.Advisories) > 0 && x.KEV == "" && x.EPSS == "" {
			errs = append(errs, errors.New("config.exploitability.advisories needs config.exploitability.kev or "+
				"epss, which match the CVEs it finds: set one, or remove advisories"))
		}
		seen := map[AdvisoryEcosystem]bool{}
		for _, e := range x.Advisories {
			switch {
			case !slices.Contains(AdvisoryEcosystems, e):
				errs = append(errs, fmt.Errorf("config.exploitability.advisories %q is not an ecosystem Draugr reads "+
					"advisories for (want %s)", e, orList(AdvisoryEcosystems)))
			case seen[e]:
				errs = append(errs, fmt.Errorf("config.exploitability.advisories lists %q twice", e))
			}
			seen[e] = true
		}
		// A path is anything else, and cannot be checked here, the descriptor may name a file this
		// machine does not have, which is a legitimate thing for a shared descriptor to do and a
		// scan-time error rather than a validation one.
	}
	if s := m.Config.SBOM; s != nil && s.Format != "" && !s.Format.Valid() {
		errs = append(errs, fmt.Errorf("config.sbom.format %q is not a known format (want %s)", s.Format, orList(SBOMFormats)))
	}
	if s := m.Config.SBOM; s != nil && s.Scope != "" && !s.Scope.Valid() {
		errs = append(errs, fmt.Errorf("config.sbom.scope %q is not a known scope (want %s)", s.Scope, orList(SBOMScopes)))
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
// for behavior it no longer has scans differently than its author believes and reports a pass
// either way. Naming the replacement costs one line here and saves the reader from discovering
// it by comparing two reports.
var removedControllerKeys = map[string]map[string]string{
	// A key that names no scanner is already rejected with the list of keys the control does
	// accept, which covers every rename without an entry here. This is for the case that error
	// cannot serve: a setting whose replacement is not a renaming but a different shape, where
	// knowing the old name is the only way to explain the new one.
	"kubernetes": {
		"context":   clusterFact("context"),
		"benchmark": clusterFact("benchmark"),
		"version":   clusterFact("version"),
	},
}

// clusterFact explains a kubernetes control setting that became a fact about each cluster.
func clusterFact(key string) string {
	return fmt.Sprintf("`%s` on the cluster's entry under the top-level `clusters:`, since one value "+
		"cannot fit two clusters", key)
}

// validateControllerKeys rejects descriptor keys that do not follow the schema's convention.
//
// Every field in a Saga is camelCase. Controller settings are a free-form tree, so nothing in the
// type system holds them to it, and a hyphenated key does not fail. It is simply never matched. A
// scanner block written as `kube-bench-job: { enabled: true }` selects no scanner and produces a
// scan that ran one fewer than asked for, reporting a pass on a benchmark half of which never ran.
// Silence is the failure mode; this makes it an error at load, before any work is done.
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
					"%s is absolute (%q), scope is relative to the repository root", at, v))
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
					"%scontrols.%s.%s was removed. Use %s",
					where, control, key, replacement))
				continue
			}
			if !strings.Contains(key, "-") {
				continue
			}
			errs = append(errs, fmt.Errorf(
				"%scontrols.%s.%s: descriptor keys are camelCase. Use %q",
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
		errs = append(errs, validateControllerKeys(fmt.Sprintf("components[%d].", i), c.Controls)...)
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
			errs = append(errs, fmt.Errorf("%s: invalid exposure %q (want %s)", where, c.Exposure, orList(Exposures)))
		}
		if c.Criticality != "" && !c.Criticality.Valid() {
			errs = append(errs, fmt.Errorf("%s: invalid criticality %q (want %s)", where, c.Criticality, orList(Criticalities)))
		}
		if c.Fixes != nil && c.Fixes.Upgrade != "" && !c.Fixes.Upgrade.Valid() {
			errs = append(errs, fmt.Errorf("%s: fixes.upgrade %q is not %s", where, c.Fixes.Upgrade, orList(UpgradeSteps)))
		}
		if c.BuiltBy != "" && !c.BuiltBy.Valid() {
			errs = append(errs, fmt.Errorf("%s: builtBy %q is not %s", where, c.BuiltBy, orList(BuiltByValues)))
		}
		errs = append(errs, validateImports(c.Imports, c.Repositories, where)...)

		for j, r := range c.Repositories {
			if r.URL == "" {
				errs = append(errs, fmt.Errorf("%s: repositories[%d].url is required", where, j))
			}
			if r.BuiltBy != "" && !r.BuiltBy.Valid() {
				errs = append(errs, fmt.Errorf("%s: repositories[%d].builtBy %q is not %s",
					where, j, r.BuiltBy, BuiltByValues))
			}
			errs = append(errs, validateRepoScope(fmt.Sprintf("%s: repositories[%d]", where, j), r)...)
		}
		errs = append(errs, validateVEXSources(where, c.VEX)...)
		for j, img := range c.Images {
			if img.Image == "" {
				errs = append(errs, fmt.Errorf("%s: images[%d].image is required", where, j))
			}
			if img.BuiltBy != "" && !img.BuiltBy.Valid() {
				errs = append(errs, fmt.Errorf("%s: images[%d].builtBy %q is not %s",
					where, j, img.BuiltBy, BuiltByValues))
			}
			if img.Digest != "" && !validDigest(img.Digest) {
				errs = append(errs, fmt.Errorf("%s: images[%d].digest %q must be of the form algorithm:hex (e.g. sha256:…)", where, j, img.Digest))
			}
		}
		for j, h := range c.Hosts {
			if h.URL == "" {
				errs = append(errs, fmt.Errorf("%s: hosts[%d].url is required", where, j))
			}
			switch {
			case h.Type == "" || slices.Contains(HostTypes, h.Type):
			case slices.Contains(HostTypes, strings.ToLower(h.Type)):
				errs = append(errs, lowercaseOnly(fmt.Sprintf("%s: hosts[%d].type", where, j), h.Type))
			default:
				errs = append(errs, fmt.Errorf("%s: hosts[%d].type %q is not one of %s",
					where, j, h.Type, strings.Join(HostTypes, ", ")))
			}
			errs = append(errs, validateHostAuth(h.Auth, fmt.Sprintf("%s: hosts[%d].auth", where, j))...)
			errs = append(errs, validateHostSpec(h.Spec, fmt.Sprintf("%s: hosts[%d].spec", where, j))...)
		}
	}
	return errs
}

// validateClusters checks the declared clusters and every component's use of them.
//
// A name that matches no declaration is refused rather than skipped, because a skipped cluster is a
// component scanned for everything except what it runs on, and reads as covered. The same cluster
// twice in one component is refused too: it counts one cluster as two, and the whole-cluster entry
// already covers the namespaces the other names.
func validateClusters(clusters map[string]Cluster, components []Component) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(clusters)) {
		c := clusters[name]
		if strings.TrimSpace(name) == "" {
			errs = append(errs, errors.New("clusters: a cluster needs a name"))
		}
		// A misspelling here reads as "self", so the findings a managed control plane cannot act on
		// stay at the top of the list, the descriptor claims a decision it is not making, and the run
		// looks the same either way.
		if c.OperatedBy != "" && !c.OperatedBy.Valid() {
			errs = append(errs, fmt.Errorf("clusters.%s.operatedBy %q is not %s",
				name, c.OperatedBy, orList(OperatedByValues)))
		}
	}
	for i, comp := range components {
		where := fmt.Sprintf("components[%d] (%s)", i, comp.Name)
		seen := map[string]int{}
		for j, ref := range comp.Kubernetes {
			switch {
			case strings.TrimSpace(ref.Cluster) == "":
				errs = append(errs, fmt.Errorf("%s: kubernetes[%d].cluster is required, naming an entry "+
					"in clusters", where, j))
				continue
			case clusters == nil || !hasCluster(clusters, ref.Cluster):
				msg := fmt.Sprintf("%s: kubernetes[%d].cluster %q is not declared in clusters",
					where, j, ref.Cluster)
				if names := slices.Sorted(maps.Keys(clusters)); len(names) > 0 {
					msg += " (it has " + strings.Join(names, ", ") + ")"
				}
				errs = append(errs, errors.New(msg))
			}
			if first, dup := seen[ref.Cluster]; dup {
				errs = append(errs, fmt.Errorf("%s: kubernetes[%d] names cluster %q again, after "+
					"kubernetes[%d]; a component runs on a cluster once, whole or by namespaces",
					where, j, ref.Cluster, first))
				continue
			}
			seen[ref.Cluster] = j
		}
	}
	return errs
}

func hasCluster(clusters map[string]Cluster, name string) bool {
	_, ok := clusters[name]
	return ok
}

// validateHostAuth checks an endpoint's auth block.
//
// Every failure here is one that would otherwise surface as a scan that ran, found nothing, and
// reported a pass, because an unauthenticated scan of an authenticated application tests the login
// page and nothing behind it.
func validateHostAuth(a *HostAuth, where string) []error {
	if a == nil {
		return nil
	}
	var errs []error
	switch a.Type {
	case HostAuthBearer:
		if a.Header != "" {
			errs = append(errs, fmt.Errorf(
				"%s.header is not used with type \"bearer\", which always sets Authorization; "+
					"use type \"header\" to name your own", where))
		}
	case HostAuthHeader:
		if strings.TrimSpace(a.Header) == "" {
			errs = append(errs, fmt.Errorf("%s.header is required with type \"header\" "+
				"(e.g. X-API-Key)", where))
		}
	case "":
		errs = append(errs, fmt.Errorf("%s.type is required: \"bearer\" or \"header\"", where))
	default:
		errs = append(errs, fmt.Errorf("%s.type %q is not a kind Draugr supports: "+
			"\"bearer\" or \"header\"", where, a.Type))
	}
	if strings.TrimSpace(a.TokenEnv) == "" {
		errs = append(errs, fmt.Errorf(
			"%s.tokenEnv is required, it names the environment variable holding the credential. "+
				"A descriptor is committed, so there is no field for the credential itself", where))
	}
	return errs
}

// validateHostSpec checks an endpoint's spec block.
func validateHostSpec(spec *HostSpec, where string) []error {
	if spec == nil {
		return nil
	}
	var errs []error
	if strings.TrimSpace(spec.Path) == "" {
		errs = append(errs, fmt.Errorf("%s.path is required, the OpenAPI document to scan", where))
	}
	// An empty list is not "no restriction": it describes a scan that sends nothing, which is a
	// descriptor quietly not working. Absent means read-only; present means say what you accept.
	if spec.Methods != nil && len(spec.Methods) == 0 {
		errs = append(errs, fmt.Errorf(
			"%s.methods is empty, which would scan nothing. Remove it for read-only, or name the "+
				"methods you accept", where))
	}
	for i, m := range spec.Methods {
		switch {
		case validSpecMethod(m):
		case validSpecMethod(strings.ToLower(m)):
			errs = append(errs, lowercaseOnly(fmt.Sprintf("%s.methods[%d]", where, i), m))
		default:
			errs = append(errs, fmt.Errorf(
				"%s.methods[%d] %q is not an HTTP method Draugr will exercise: %s",
				where, i, m, strings.Join(SpecMethods, ", ")))
		}
	}
	return errs
}

// SpecMethods are the methods a spec-driven scan may be told to exercise.
var SpecMethods = []string{"get", "head", "options", "post", "put", "patch", "delete"}

// validSpecMethod accepts the lowercase spelling only, the one the JSON Schema offers. Accepting
// `GET` here while an editor rejected it would leave two readers of one file disagreeing.
func validSpecMethod(m string) bool {
	return slices.Contains(SpecMethods, m)
}

// lowercaseOnly refuses a vocabulary value written in the wrong case, and says which spelling to
// use. Every value a descriptor chooses from a list is lowercase, in the schema and here, so an
// editor and `draugr validate` never disagree about one.
func lowercaseOnly(where, got string) error {
	return fmt.Errorf("%s %q must be lowercase: %s", where, got, strings.ToLower(got))
}

// The ways a host's `auth` sends its credential.
const (
	// HostAuthBearer sends `Authorization: Bearer <token>`.
	HostAuthBearer = "bearer"
	// HostAuthHeader sends the credential in a header the descriptor names.
	HostAuthHeader = "header"
)

// HostAuthTypes are the values a host's `auth.type` accepts.
var HostAuthTypes = []string{HostAuthBearer, HostAuthHeader}

// HostTypes are the values a host's `type` accepts.
//
// Checked because the headers scanner treats anything that is not "api" as a browser, so a
// misspelled `apii` is scanned with the browser rules the descriptor meant to turn off.
var HostTypes = []string{"browser", "api"}

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
			errs = append(errs, fmt.Errorf("%s: reason is required. Say why this is excluded", where))
		}
		// A date that does not parse is worse than no date: the exclusion would keep suppressing
		// forever while the descriptor claims it lapses, which is the belief this field exists
		// to make true.
		if e.Expires != "" {
			if _, err := time.Parse(expiresLayout, e.Expires); err != nil {
				errs = append(errs, fmt.Errorf(
					"%s: expires must be a date as YYYY-MM-DD, got %q, an unreadable date would "+
						"suppress indefinitely while claiming not to", where, e.Expires))
			}
		}
		// Neither selector set would match every finding in the project.
		if len(e.Paths) == 0 && len(e.Rules) == 0 {
			errs = append(errs, fmt.Errorf("%s: set paths, rules, or both, an exclusion with neither would suppress everything", where))
		}
		for j, p := range e.Paths {
			if strings.TrimSpace(p) == "" {
				errs = append(errs, fmt.Errorf("%s: paths[%d] is empty", where, j))
			}
			// `**` is not a syntax this matcher has, and the way it fails is the problem: nothing
			// rejects it, `path.Match` reads the second star as another single-segment wildcard,
			// and `tests/**` matches exactly one level down. Somebody writing it means any depth,
			// which is what every tool that supports it does, so the suppression they reviewed and
			// agreed to covers a fraction of what they think and the part it misses is the deep
			// part of the tree that motivated writing it.
			//
			// Refused rather than supported. The trailing-slash form already matches everything
			// beneath a directory at any depth, so supporting `**` would add a second path
			// semantics to keep true beside one that already expresses the same thing.
			//
			// The error names `ignore`, because that is where somebody learned the syntax. Two
			// fields in one descriptor take path patterns and only one of them crosses a
			// separator, which is a difference nothing on the page announces and the reason this
			// is worth an error rather than a shrug.
			if strings.Contains(p, "**") {
				errs = append(errs, fmt.Errorf(
					"%s: paths[%d] %q uses ** which this field does not have, and * does not "+
						"cross /. Write %q to exclude a directory and everything beneath it. "+
						"(repositories[].ignore is a different matcher and does support **)",
					where, j, p, doubleStarAsDirectory(p)))
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
					hint = ", a finding you have suppressed is one you have finished investigating; " +
						"it is what Draugr already reports for findings nobody has triaged"
				}
				errs = append(errs, fmt.Errorf("%s: vex.status %q is not a status an exclusion may declare (want %s)%s",
					where, v.Status, strings.Join(VEXStatuses, ", "), hint))
			}
			if v.Justification != "" {
				if v.Status != VEXNotAffected && v.Status != "" {
					errs = append(errs, fmt.Errorf(
						"%s: vex.justification applies only to status %s, not %q, it answers why the "+
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
			errs = append(errs, fmt.Errorf("%s: path is required, it selects which files to merge", where))
		}
		// A remote fragment with no revision is a gate that changes with no commit in your own
		// repository. Refusing costs one line in the descriptor; defaulting to the default branch
		// would make every scan quietly depend on somebody else's next push.
		if f.Remote() && strings.TrimSpace(f.Revision) == "" {
			errs = append(errs, fmt.Errorf(
				"%s: revision is required when url is set. Name a tag, branch or commit so the "+
					"fragment cannot change without a change here", where))
		}
		if !f.Remote() && f.Revision != "" {
			errs = append(errs, fmt.Errorf(
				"%s: revision applies only with url, a local path is read from this checkout", where))
		}
	}
	return errs
}

// joinErrs collapses a slice of problems into one error, or nil.
func joinErrs(errs []error) error { return errors.Join(errs...) }

// validateVEXSources checks that each supplier VEX source names exactly one place to read from.
//
// Exactly one, refused rather than resolved by precedence. A source carrying both a path and a URL
// is a descriptor whose author believed two different things about where the document lives, and
// picking one silently means the run reads a document nobody meant, which then either excuses
// findings nobody excused, or excuses none and looks like a supplier with nothing to say.
func validateVEXSources(where string, sources []VEXSource) []error {
	var errs []error
	for j, s := range sources {
		at := fmt.Sprintf("%s: vex[%d]", where, j)
		named := 0
		if s.Path != "" {
			named++
		}
		if s.URL != "" {
			named++
		}
		if s.Repository != nil {
			named++
		}
		switch {
		case named == 0:
			errs = append(errs, fmt.Errorf("%s: needs one of path, url or repository", at))
			continue
		case named > 1:
			errs = append(errs, fmt.Errorf(
				"%s: names more than one of path, url and repository, a source is one document", at))
			continue
		}
		if s.URL != "" && !strings.HasPrefix(s.URL, "https://") && !strings.HasPrefix(s.URL, "http://") {
			errs = append(errs, fmt.Errorf("%s: url %q must be http(s). Use path for a local file", at, s.URL))
		}
		if r := s.Repository; r != nil {
			if r.URL == "" {
				errs = append(errs, fmt.Errorf("%s: repository.url is required", at))
			}
			// Without a path there is nothing to read: a repository is not a document, and
			// guessing at a conventional filename would make the descriptor's meaning depend on
			// what a supplier happened to call their file.
			if r.Path == "" {
				errs = append(errs, fmt.Errorf("%s: repository.path is required. Name the document inside the repository", at))
			} else if filepath.IsAbs(r.Path) || strings.Contains(r.Path, "..") {
				errs = append(errs, fmt.Errorf("%s: repository.path %q must be inside the repository", at, r.Path))
			}
		}
	}
	return errs
}

// doubleStarAsDirectory rewrites a pattern containing ** into the directory form that means what
// the author meant, for the error to name.
//
// The spelling rather than a description of the semantics. A reader who has just been told their
// pattern is wrong wants the one that is right, and everything up to the first wildcard is the
// part they were trying to name.
func doubleStarAsDirectory(p string) string {
	prefix := p
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		prefix = p[:i]
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		// `**` on its own, or leading. There is no directory to name, and the honest suggestion is
		// the rule the author almost certainly does not want rather than an invented path.
		return "./"
	}
	return prefix + "/"
}

// orList joins values the way a sentence offers a choice, so an error reads as English rather than
// as a Go slice.
//
// `%v` on a string slice prints `[public authenticated internal restricted]`: brackets somebody
// did not type and no separators between the words. It is read by somebody who is stuck, which is
// the worst moment to be shown the shape of a value rather than the choice.
func orList[T ~string](values []T) string {
	words := make([]string, len(values))
	for i, v := range values {
		words[i] = string(v)
	}
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " or " + words[len(words)-1]
}

// article is the indefinite article read before a format's name, by its first letter as written:
// "an osv-scanner-json file", "a mend-json file".
func article(name string) string {
	if name != "" && strings.ContainsRune("aeiou", rune(name[0])) {
		return "an"
	}
	return "a"
}

// OrList is orList for callers outside this package, so one phrasing serves every place a closed
// vocabulary is offered back to somebody who missed it.
func OrList[T ~string](values []T) string { return orList(values) }

// validateIssueFields checks the values of an issue publisher's fields. Whether the kind takes
// them, and whether a selected component or control exists, is decided where the kinds and the
// registry are known.
func (p PublisherConfig) validateIssueFields(i int) []error {
	var errs []error
	if p.Split != "" && !slices.Contains(Splits, p.Split) {
		errs = append(errs, fmt.Errorf("config.publishers[%d].split is %q, but a split is %s",
			i, p.Split, orList(Splits)))
	}
	if p.MinPriority != "" && !slices.Contains(Priorities, p.MinPriority) {
		errs = append(errs, fmt.Errorf("config.publishers[%d].minPriority is %q, but a priority band is %s",
			i, p.MinPriority, orList(Priorities)))
	}
	errs = append(errs, p.validateChildren(i)...)
	// An empty select covers the whole run, which is what leaving it out already says. Written
	// out, it reads as a narrowing that narrows nothing.
	if p.Select != nil && p.Select.IsZero() {
		errs = append(errs, fmt.Errorf(
			"config.publishers[%d].select names no components, labels or controls; remove it to cover the whole run", i))
	}
	// Forges take a label filter as a comma-separated list, so a label holding a comma would be
	// searched for as two labels and its items never found.
	if strings.Contains(p.Label, ",") {
		errs = append(errs, fmt.Errorf("config.publishers[%d].label is %q, but a label cannot hold a comma", i, p.Label))
	}
	// Azure DevOps stores a work item's tags as one string separated by semicolons.
	if p.Kind == "azure-work-item" && strings.Contains(p.Label, ";") {
		errs = append(errs, fmt.Errorf("config.publishers[%d].label is %q, but a tag cannot hold a semicolon", i, p.Label))
	}
	seen := map[string]bool{}
	for _, f := range p.LabelBy {
		switch {
		case !slices.Contains(LabelFacts, f):
			errs = append(errs, fmt.Errorf("config.publishers[%d].labelBy: %q is not a fact. A fact is %s",
				i, f, orList(LabelFacts)))
		case seen[f]:
			errs = append(errs, fmt.Errorf("config.publishers[%d].labelBy names %q twice", i, f))
		}
		seen[f] = true
	}
	// Every run removes a fact label that no longer applies and adds back a configured one that is
	// missing, so a configured label shaped like a fact label would be removed and restored forever.
	configured := []string{p.Label}
	if it := p.Item; it != nil {
		configured = append(append(configured, it.Labels...), it.Tags...)
		errs = append(errs, it.validateAzure(i)...)
	}
	for _, l := range configured {
		if IsFactLabel(l) {
			errs = append(errs, fmt.Errorf("config.publishers[%d]: the label %q is named like the labels labelBy keeps. Choose another name", i, l))
		}
	}
	for _, b := range p.Branches {
		if _, err := path.Match(b, ""); err != nil {
			errs = append(errs, fmt.Errorf("config.publishers[%d].branches: %q is not a valid pattern", i, b))
		}
	}
	return errs
}

// validateChildren checks `children` and `maxChildren`, and that the two agree with `split`.
func (p PublisherConfig) validateChildren(i int) []error {
	var errs []error
	if p.Children != "" && !slices.Contains(ChildKinds, p.Children) {
		errs = append(errs, fmt.Errorf("config.publishers[%d].children is %q, but children is %s",
			i, p.Children, orList(ChildKinds)))
	}
	if p.MaxChildren != nil {
		if n := *p.MaxChildren; n < 1 || n > MaxChildrenLimit {
			errs = append(errs, fmt.Errorf("config.publishers[%d].maxChildren is %d, but it is 1 to %d",
				i, n, MaxChildrenLimit))
		}
		if p.Children == "" || p.Children == ChildrenNone {
			errs = append(errs, fmt.Errorf(
				"config.publishers[%d].maxChildren caps the children of children: actions or controls, and children is none", i))
		}
	}
	// Each item of a split by control already covers one control, so its one child would repeat it.
	if p.Children == ChildrenControls && p.Split == SplitControl {
		errs = append(errs, fmt.Errorf(
			"config.publishers[%d] sets children: controls with split: control, which gives each item one child repeating it", i))
	}
	// A child on GitLab is a task, and GitLab nests no task under another.
	if p.Kind == "gitlab-issue" && p.Item != nil && p.Item.Type == "task" &&
		(p.Children == ChildrenActions || p.Children == ChildrenControls) {
		errs = append(errs, fmt.Errorf(
			"config.publishers[%d] sets children with item.type task, and a GitLab task has no children", i))
	}
	return errs
}

// validateAzure holds the Azure DevOps keys of an item to what a work item takes.
func (it IssueItem) validateAzure(i int) []error {
	var errs []error
	if it.Priority != nil && (*it.Priority < 1 || *it.Priority > 4) {
		errs = append(errs, fmt.Errorf("config.publishers[%d].item.priority is %d, but a work item's priority is 1 to 4", i, *it.Priority))
	}
	for _, t := range it.Tags {
		if strings.ContainsAny(t, ";,") {
			errs = append(errs, fmt.Errorf("config.publishers[%d].item.tags: %q holds a semicolon or a comma, which separate tags", i, t))
		}
	}
	for _, name := range sortedFieldNames(it.Fields) {
		if name == "" {
			errs = append(errs, fmt.Errorf("config.publishers[%d].item.fields names a field with no name", i))
			continue
		}
		for _, owned := range AzureOwnedFields {
			if !strings.EqualFold(name, owned) {
				continue
			}
			if key := AzureFieldKeys[owned]; key != "" {
				errs = append(errs, fmt.Errorf("config.publishers[%d].item.fields sets %s; set it with %s", i, name, key))
			} else {
				errs = append(errs, fmt.Errorf("config.publishers[%d].item.fields sets %s, which the publisher writes", i, name))
			}
		}
	}
	return errs
}

func sortedFieldNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// validateCaveatKinds refuses a kind of caveat this build does not report, and one listed twice.
// A misspelled kind would otherwise be a rule in a reviewed descriptor that never fires, which is a
// gate somebody believes is stricter than it is.
func validateCaveatKinds(kinds []CaveatKind, field string) []error {
	var errs []error
	seen := map[CaveatKind]bool{}
	for i, k := range kinds {
		switch {
		case !k.Valid():
			errs = append(errs, fmt.Errorf("%s[%d] is %q, but a kind of caveat is %s", field, i, k, orList(CaveatKinds)))
		case seen[k]:
			errs = append(errs, fmt.Errorf("%s lists %q twice", field, k))
		}
		seen[k] = true
	}
	return errs
}

// validateImportFormat refuses a format Draugr has no reader for, and a severity mapping or a
// suppressions setting on a format it does not apply to. The mapping names a SARIF result property, and a tool's own JSON is rated as
// Draugr's run of the tool rates it, or by what OSV-Scanner's file states, so a mapping there would
// be ignored without a word.
func validateImportFormat(imp Import, at string) []error {
	switch {
	case imp.Format == "" || slices.Contains(ImportFormats, imp.Format):
	case slices.Contains(ImportFormats, strings.ToLower(imp.Format)):
		return []error{lowercaseOnly(at+".format", imp.Format)}
	default:
		return []error{fmt.Errorf("%s.format %q is not one of %s", at, imp.Format, strings.Join(ImportFormats, ", "))}
	}
	if imp.Severity != nil && imp.ReadFormat() == ImportFormatOSVScannerJSON {
		// Draugr runs no OSV-Scanner of its own, so its file is rated by what the file states.
		return []error{fmt.Errorf("%s.severity maps a SARIF property, and an %s file is rated by the score and "+
			"severity it states. Remove severity", at, imp.Format)}
	}
	if imp.Severity != nil && imp.ReadFormat() == ImportFormatVeracodePipelineJSON {
		// Draugr runs no Veracode, so its file is rated by the severity Veracode states for each flaw.
		return []error{fmt.Errorf("%s.severity maps a SARIF property, and a %s file is rated by the severity "+
			"Veracode states. Remove severity", at, imp.Format)}
	}
	if controls, ok := ImportFormatControls[imp.ReadFormat()]; ok && imp.Control != "" && !slices.Contains(controls, imp.Control) {
		// The reader takes the results of the import's control from the file, and the file holds
		// none for another, so the import would read as a clean scan.
		return []error{fmt.Errorf("%s: %s %s file holds no %s results; import it into %s", at, article(imp.Format),
			imp.Format, imp.Control, orList(controls))}
	}
	if imp.Severity != nil && (imp.ReadFormat() == ImportFormatGitLabSAST ||
		imp.ReadFormat() == ImportFormatGitLabDependencyScanning || imp.ReadFormat() == ImportFormatJFrogSimpleJSON ||
		imp.ReadFormat() == ImportFormatCheckmarxOneJSON || imp.ReadFormat() == ImportFormatMendJSON ||
		imp.ReadFormat() == ImportFormatTwistcliJSON) {
		// The tools that write GitLab's format are many, and Draugr runs few of them, and none of
		// JFrog's, Checkmarx's, Mend's or Prisma Cloud's, so the file is rated by the severity it
		// states for each one.
		return []error{fmt.Errorf("%s.severity maps a SARIF property, and a %s file is rated by the severity "+
			"it states. Remove severity", at, imp.Format)}
	}
	if imp.Severity != nil && imp.ReadFormat() != ImportFormatSARIF {
		return []error{fmt.Errorf("%s.severity maps a SARIF property, and a %s file is rated as Draugr's own run "+
			"of its tool rates it. Remove severity", at, imp.Format)}
	}
	// OSV-Scanner leaves a vulnerability its osv-scanner.toml ignores out of the JSON and says so only
	// on its standard error, so its file holds no suppression to honor or count.
	if imp.Suppressions != "" && imp.ReadFormat() == ImportFormatOSVScannerJSON {
		return []error{fmt.Errorf("%s.suppressions has nothing to apply to, since OSV-Scanner leaves what its "+
			"configuration ignores out of the file. Remove it", at)}
	}
	// Pipeline Scan's results.json records no mitigation or suppression on a flaw.
	if imp.Suppressions != "" && imp.ReadFormat() == ImportFormatVeracodePipelineJSON {
		return []error{fmt.Errorf("%s.suppressions has nothing to apply to, since a Pipeline Scan file records no "+
			"suppression. Remove it", at)}
	}
	// A GitLab report leaves out what the tool's own settings suppressed, and records no suppression
	// on the vulnerabilities it holds.
	if imp.Suppressions != "" && (imp.ReadFormat() == ImportFormatGitLabSAST ||
		imp.ReadFormat() == ImportFormatGitLabDependencyScanning) {
		return []error{fmt.Errorf("%s.suppressions has nothing to apply to, since a GitLab report records no "+
			"suppression. Remove it", at)}
	}
	// JFrog's simple-json records no suppression on the vulnerabilities it holds.
	if imp.Suppressions != "" && imp.ReadFormat() == ImportFormatJFrogSimpleJSON {
		return []error{fmt.Errorf("%s.suppressions has nothing to apply to, since JFrog's simple-json records no "+
			"suppression. Remove it", at)}
	}
	// Mend's dependency JSON records no suppression on the libraries it holds.
	if imp.Suppressions != "" && imp.ReadFormat() == ImportFormatMendJSON {
		return []error{fmt.Errorf("%s.suppressions has nothing to apply to, since Mend's dependency JSON records "+
			"no suppression. Remove it", at)}
	}
	// twistcli's JSON records no suppression on the vulnerabilities it holds.
	if imp.Suppressions != "" && imp.ReadFormat() == ImportFormatTwistcliJSON {
		return []error{fmt.Errorf("%s.suppressions has nothing to apply to, since twistcli's JSON records "+
			"no suppression. Remove it", at)}
	}
	return nil
}

// validateImports refuses an import without a control, or without exactly one of a file and a
// source, and one file or source imported twice into the same control, which would count every
// finding in it twice. Whether the control exists is a question for the registry, asked where control
// names are checked. repositories are the component's, which say whether a source has to name one.
func validateImports(imports []Import, repositories []Repository, where string) []error {
	var errs []error
	seen := map[importKey]bool{}
	for i, imp := range imports {
		at := fmt.Sprintf("%s: imports[%d]", where, i)
		if imp.Control == "" {
			errs = append(errs, fmt.Errorf("%s: control is required, the control its findings belong to", at))
		}
		switch {
		case imp.File == "" && imp.Source == "":
			errs = append(errs, fmt.Errorf("%s: file or source is required, the file to read or the service whose alerts to read", at))
		case imp.File != "" && imp.Source != "":
			errs = append(errs, fmt.Errorf("%s: names both file and source. An import reads one; write a second import for the other", at))
		}
		key := imp.key()
		if imp.Control != "" && imp.Name() != "" && seen[key] {
			errs = append(errs, fmt.Errorf("%s: %s is imported into %s twice", at, imp.Name(), imp.Control))
		}
		seen[key] = true
		if !imp.Suppressions.Valid() {
			errs = append(errs, fmt.Errorf("%s: suppressions %q is not %s", at, imp.Suppressions, orList(ImportSuppressionsValues)))
		}
		if imp.Source != "" {
			errs = append(errs, validateImportSource(imp, repositories, at)...)
			continue
		}
		errs = append(errs, validateFileOnly(imp, at)...)
		errs = append(errs, validateImportFormat(imp, at)...)
		if imp.Severity != nil && imp.ReadFormat() == ImportFormatSARIF {
			errs = append(errs, validateImportSeverity(*imp.Severity, at+".severity")...)
		}
		errs = append(errs, validateImportCommit(imp, at)...)
		errs = append(errs, validateImportConverter(imp, at)...)
	}
	return errs
}

// converterName is what a converter's name may be: lowercase letters, digits and hyphens, as the
// contract's schema holds the file's converter.name to.
var converterName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// validateImportConverter holds an import's converter to its format, to the contract version this
// build reads, and to the fixed list of what a converter may set.
//
// A converter declared beside another format would be read by nobody, and a property outside the
// list would read as granted in a reviewed descriptor while every file setting it was refused. A
// property no converter may set is named as such, so whoever wrote it learns it was never on offer
// rather than that it is misspelled.
func validateImportConverter(imp Import, at string) []error {
	c := imp.Converter
	if imp.ReadFormat() != ImportFormatConverter {
		if c != nil {
			return []error{fmt.Errorf("%s.converter is set, and format %s reads no converter's file. Set format %s",
				at, imp.ReadFormat(), ImportFormatConverter)}
		}
		return nil
	}
	if c == nil {
		return []error{fmt.Errorf("%s: format %s needs converter, the converter that wrote the file", at, ImportFormatConverter)}
	}
	var errs []error
	if !converterName.MatchString(c.Name) {
		errs = append(errs, fmt.Errorf("%s.converter.name %q is not lowercase letters, digits and hyphens", at, c.Name))
	}
	switch {
	case c.Contract == 0:
		errs = append(errs, fmt.Errorf("%s.converter.contract is missing. Draugr reads contract version %d", at, converter.Version))
	case c.Contract != converter.Version:
		errs = append(errs, fmt.Errorf("%s.converter.contract is %d, and Draugr reads contract version %d", at, c.Contract, converter.Version))
	}
	seen := map[string]bool{}
	for i, p := range c.Sets {
		switch {
		case converter.Forbidden(p):
			errs = append(errs, fmt.Errorf("%s.converter.sets[%d] is %s, which no converter may set", at, i, p))
		case !converter.Allowed(p):
			errs = append(errs, fmt.Errorf("%s.converter.sets[%d] is %q, not %s", at, i, p, orList(converter.Properties)))
		case seen[p]:
			errs = append(errs, fmt.Errorf("%s.converter.sets lists %s twice", at, p))
		}
		seen[p] = true
	}
	// A converter's file has no suppressions to honor or count: the contract refuses them.
	if imp.Suppressions != "" {
		errs = append(errs, fmt.Errorf("%s.suppressions has nothing to apply to, since a converter's file records none. Remove it", at))
	}
	return errs
}
