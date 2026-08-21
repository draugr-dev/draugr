package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// govulncheckScanner is the scanner name, and the descriptor key that enables it.
const govulncheckScanner = "govulncheck"

// NewGovulncheck returns the govulncheck scanner: reachability analysis for Go modules.
//
// It answers a different question from the other sca scanners. Trivy reads a manifest and says
// which dependencies have known vulnerabilities; govulncheck builds a call graph from the
// packages that are actually in the build and says which of those vulnerabilities this code can
// reach. The two are complementary rather than competing, which is why what this produces is
// folded onto existing findings rather than reported alongside them.
func NewGovulncheck() plugin.Scanner {
	return newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         govulncheckScanner,
			Origin:       "Go team",
			Reachability: true,
			Binary:       "govulncheck",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		govulncheckArgs,
		parseGovulncheck,
	)
}

// govulncheckArgs builds `govulncheck -format json ./...`, run inside the checkout.
//
// No flag makes it fail on findings, so there is no exit code to neutralize the way Trivy's
// --exit-code 0 does; in JSON mode it reports and exits 0.
//
// Deliberately not -test. Analyzing tests would report vulnerabilities reachable only from code
// that never ships, and the finding a developer cannot act on is the one that teaches them to
// ignore the report.
func govulncheckArgs(_ string, _ plugin.Config) []string {
	return []string{"govulncheck", "-format", "json", "./..."}
}

// govulncheckMessage is one message in govulncheck's output stream.
//
// The stream is concatenated JSON objects rather than one document or one object per line, so it
// is decoded with a streaming decoder in a loop. Each message carries exactly one of these.
type govulncheckMessage struct {
	Config  *govulncheckConfig  `json:"config,omitempty"`
	SBOM    *govulncheckSBOM    `json:"SBOM,omitempty"`
	OSV     *govulncheckOSV     `json:"osv,omitempty"`
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

// govulncheckConfig is the run's own account of what it was able to do.
type govulncheckConfig struct {
	// ScanLevel is "symbol", "package" or "module". Only "symbol" supports a claim that
	// something is unreachable; the others cannot see a call.
	ScanLevel string `json:"scan_level"`
	// ScanMode is "source" or "binary".
	ScanMode string `json:"scan_mode"`
}

// govulncheckSBOM lists what the analysis actually covered.
//
// The field that makes an unreachable verdict safe to state. A module missing from this list was
// never analyzed, whatever the reason — and "we did not look" must not be reported as "nothing
// reaches it".
type govulncheckSBOM struct {
	Modules []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"modules"`
}

// govulncheckOSV is an advisory the run considered. Most are never referenced by a finding;
// the stream carries the slice of the database that was relevant to the build.
type govulncheckOSV struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
	// Affected carries the vulnerable symbols, which are worth reporting whether or not any of
	// them is called: they are what makes an unreachable verdict checkable by hand.
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// govulncheckFinding is one vulnerability at one granularity.
//
// The same advisory is reported more than once — once for the module being in the build, once
// for the vulnerable package being imported, and once per call path when a vulnerable symbol is
// actually called. The three are distinguished only by how much of Trace is filled in, so
// reachability is derived from the set of a vulnerability's findings rather than read off any
// one of them.
type govulncheckFinding struct {
	OSV          string             `json:"osv"`
	FixedVersion string             `json:"fixed_version"`
	Trace        []govulncheckFrame `json:"trace"`
}

// govulncheckFrame is one entry in a finding's trace. Traces are ordered callee first.
type govulncheckFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
	} `json:"position"`
}

// parseGovulncheck converts govulncheck's JSON stream into SARIF results carrying reachability.
//
// One result per (advisory alias, module), because that is the shape the rest of the pipeline
// already speaks: an advisory with three CVEs is three findings to every other scanner, and
// emitting one would leave two of them with no reachability while looking like a complete answer.
func parseGovulncheck(out []byte, _ string, _ plugin.Config) (sarif.Report, error) {
	msgs, err := decodeGovulncheckStream(out)
	if err != nil {
		return sarif.Report{}, err
	}

	var scanLevel string
	analyzed := map[string]bool{}
	advisories := map[string]*govulncheckOSV{}
	byVuln := map[govulncheckKey][]govulncheckFinding{}
	for _, m := range msgs {
		switch {
		case m.Config != nil:
			scanLevel = m.Config.ScanLevel
		case m.SBOM != nil:
			for _, mod := range m.SBOM.Modules {
				analyzed[mod.Path] = true
			}
		case m.OSV != nil:
			advisories[m.OSV.ID] = m.OSV
		case m.Finding != nil && len(m.Finding.Trace) > 0:
			// The vulnerable module is the deepest frame, and traces are callee first.
			key := govulncheckKey{OSV: m.Finding.OSV, Module: m.Finding.Trace[0].Module}
			byVuln[key] = append(byVuln[key], *m.Finding)
		}
	}

	asOf := time.Now().UTC().Format("2006-01-02")
	results := make([]sarif.Result, 0, len(byVuln))
	for _, key := range sortedGovulncheckKeys(byVuln) {
		results = append(results, govulncheckResults(key, byVuln[key], advisories[key.OSV], analyzed, scanLevel, asOf)...)
	}
	return sarif.Report{Tool: govulncheckScanner, Results: results}, nil
}

// govulncheckKey identifies a vulnerability in a module. Both halves are needed: one advisory can
// affect more than one module, and one module has more than one advisory.
type govulncheckKey struct {
	OSV    string
	Module string
}

// sortedGovulncheckKeys orders the keys so a run produces the same report twice.
func sortedGovulncheckKeys(m map[govulncheckKey][]govulncheckFinding) []govulncheckKey {
	keys := make([]govulncheckKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].OSV != keys[j].OSV {
			return keys[i].OSV < keys[j].OSV
		}
		return keys[i].Module < keys[j].Module
	})
	return keys
}

// decodeGovulncheckStream reads the concatenated JSON objects govulncheck writes.
func decodeGovulncheckStream(out []byte) ([]govulncheckMessage, error) {
	dec := json.NewDecoder(strings.NewReader(string(out)))
	var msgs []govulncheckMessage
	for {
		var m govulncheckMessage
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return msgs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode govulncheck output: %w", err)
		}
		msgs = append(msgs, m)
	}
}

// govulncheckResults turns one vulnerability in one module into a result per identifier it is
// known by.
func govulncheckResults(
	key govulncheckKey,
	findings []govulncheckFinding,
	advisory *govulncheckOSV,
	analyzed map[string]bool,
	scanLevel string,
	asOf string,
) []sarif.Result {
	reach := &sarif.Reachability{
		State:    govulncheckState(findings, key.Module, analyzed, scanLevel),
		Analyzer: govulncheckScanner,
		Method:   "call-graph",
		Symbols:  govulncheckSymbols(advisory, key.Module),
		AsOf:     asOf,
	}
	if reach.State == sarif.ReachabilityReachable {
		reach.Paths = govulncheckPaths(findings)
	}

	pkg := &sarif.Package{
		Name:         key.Module,
		Version:      govulncheckModuleVersion(findings),
		FixedVersion: strings.TrimPrefix(govulncheckFixedVersion(findings), "v"),
		Ecosystem:    "gomod",
	}
	pkg.PURL = govulncheckPURL(pkg.Name, pkg.Version)

	var results []sarif.Result
	for _, id := range govulncheckIdentifiers(key.OSV, advisory) {
		results = append(results, sarif.Result{
			Tool:   govulncheckScanner,
			RuleID: id,
			// The Go vulnerability database publishes no severity, so there is none to report.
			// Absent, this normalizes to warning; where another scanner rated the same finding,
			// the fold keeps that scanner's rating rather than replacing it with this one.
			Level:        sarif.LevelWarning,
			Message:      govulncheckMessageText(key, advisory, reach),
			Location:     sarif.Location{URI: "go.mod"},
			Package:      pkg,
			Reachability: reach,
		})
	}
	return results
}

// govulncheckState decides the verdict, and refuses to state the strong one without grounds.
//
// Reachable is a positive observation and needs nothing else: a call path was found. Unreachable
// is a claim about absence, and absence is only meaningful if something looked — so it requires
// both that the run was analyzing symbols and that this module was in what it analyzed. Anything
// else is unknown, which is the honest answer and the one that keeps a report from implying a
// check that never ran.
func govulncheckState(findings []govulncheckFinding, module string, analyzed map[string]bool, scanLevel string) sarif.ReachabilityState {
	for _, f := range findings {
		for _, frame := range f.Trace {
			if frame.Function != "" {
				return sarif.ReachabilityReachable
			}
		}
	}
	if scanLevel == "symbol" && analyzed[module] {
		return sarif.ReachabilityUnreachable
	}
	return sarif.ReachabilityUnknown
}

// govulncheckPaths converts the traces that reached a symbol into call paths, reversed.
//
// govulncheck orders a trace callee first — the vulnerable function, then whatever called it.
// Reversing it puts this project's own code at the top, which is the order a reader follows.
func govulncheckPaths(findings []govulncheckFinding) []sarif.CallPath {
	var paths []sarif.CallPath
	for _, f := range findings {
		if !govulncheckCalled(f) {
			continue
		}
		frames := make([]sarif.CallFrame, 0, len(f.Trace))
		for i := len(f.Trace) - 1; i >= 0; i-- {
			t := f.Trace[i]
			if t.Function == "" {
				continue
			}
			frame := sarif.CallFrame{Function: t.Function, Package: t.Package, Module: t.Module}
			if t.Position != nil {
				frame.File, frame.Line = t.Position.Filename, t.Position.Line
			}
			frames = append(frames, frame)
		}
		if len(frames) > 0 {
			paths = append(paths, sarif.CallPath{Frames: frames})
		}
	}
	return paths
}

// govulncheckCalled reports whether a finding names a called symbol.
func govulncheckCalled(f govulncheckFinding) bool {
	for _, t := range f.Trace {
		if t.Function != "" {
			return true
		}
	}
	return false
}

// govulncheckSymbols lists the vulnerable functions the advisory names for this module.
func govulncheckSymbols(advisory *govulncheckOSV, module string) []string {
	if advisory == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, aff := range advisory.Affected {
		if aff.Package.Name != module {
			continue
		}
		for _, imp := range aff.EcosystemSpecific.Imports {
			for _, sym := range imp.Symbols {
				qualified := sym
				if imp.Path != "" {
					qualified = imp.Path + "." + sym
				}
				if !seen[qualified] {
					seen[qualified] = true
					out = append(out, qualified)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// govulncheckIdentifiers lists every identifier this advisory should be reported under.
//
// The CVEs first and the Go advisory id only when there is no CVE, for the reason retire.js picks
// the same way: a CVE is what a reader can look up, what an exclusion is most likely written
// against, and what every other scanner and every exploitability feed keys on. An advisory with
// several CVEs becomes several findings, because that is how the manifest scanners report it.
func govulncheckIdentifiers(osvID string, advisory *govulncheckOSV) []string {
	var cves []string
	if advisory != nil {
		seen := map[string]bool{}
		for _, alias := range advisory.Aliases {
			if strings.HasPrefix(strings.ToUpper(alias), "CVE-") && !seen[alias] {
				seen[alias] = true
				cves = append(cves, alias)
			}
		}
	}
	if len(cves) == 0 {
		return []string{osvID}
	}
	sort.Strings(cves)
	return cves
}

// govulncheckModuleVersion reports the vulnerable module's version, read from the trace frame
// that names it.
func govulncheckModuleVersion(findings []govulncheckFinding) string {
	for _, f := range findings {
		for _, t := range f.Trace {
			if t.Version != "" {
				return t.Version
			}
		}
	}
	return ""
}

// govulncheckFixedVersion reports the first release that resolves the finding, when there is one.
func govulncheckFixedVersion(findings []govulncheckFinding) string {
	for _, f := range findings {
		if f.FixedVersion != "" {
			return f.FixedVersion
		}
	}
	return ""
}

// govulncheckPURL builds a Go module package URL.
//
// The module path keeps its case: Go module paths are case-sensitive, and lowercasing would make
// pkg:golang/github.com/Masterminds/semver a different package from the one that was scanned.
func govulncheckPURL(module, version string) string {
	if module == "" {
		return ""
	}
	purl := "pkg:golang/" + module
	if version != "" {
		purl += "@" + version
	}
	return purl
}

// govulncheckMessageText describes the finding, leading with the advisory's own summary and
// naming the Go advisory id, which the rule id drops in favor of the CVE.
func govulncheckMessageText(key govulncheckKey, advisory *govulncheckOSV, reach *sarif.Reachability) string {
	summary := ""
	if advisory != nil {
		summary = advisory.Summary
	}
	if summary == "" {
		summary = "vulnerability in " + key.Module
	}
	var b strings.Builder
	b.WriteString(key.Module)
	b.WriteString(": ")
	b.WriteString(summary)
	b.WriteString(" (")
	b.WriteString(key.OSV)
	b.WriteString(")")
	switch reach.State {
	case sarif.ReachabilityReachable:
		b.WriteString(" — reachable: ")
		b.WriteString(govulncheckPathSummary(reach.Paths))
	case sarif.ReachabilityUnreachable:
		b.WriteString(" — the vulnerable code is never called")
	case sarif.ReachabilityUnknown:
		b.WriteString(" — reachability not determined")
	}
	return b.String()
}

// govulncheckPathSummary renders the shortest call path as one line, which is what a reader needs
// before deciding whether to open the full evidence.
func govulncheckPathSummary(paths []sarif.CallPath) string {
	if len(paths) == 0 {
		return "a call path exists"
	}
	shortest := paths[0]
	for _, p := range paths {
		if len(p.Frames) < len(shortest.Frames) {
			shortest = p
		}
	}
	names := make([]string, 0, len(shortest.Frames))
	for _, f := range shortest.Frames {
		names = append(names, f.Function)
	}
	return strings.Join(names, " → ")
}
