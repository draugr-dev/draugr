package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// excludedNucleiTags are template tags Nuclei should skip so the native "headers" control owns
// HTTP security-header findings — dast covers what headers doesn't (XSS, cookies, info
// disclosure, exposures, outdated libraries, default creds). Only "headers" is excluded; never
// "http", which would suppress almost every template.
const excludedNucleiTags = "headers"

// nucleiScanner runs ProjectDiscovery Nuclei against a running endpoint (a component's host) and
// converts its JSONL output to SARIF. It serves the "dast" control. run is injectable for tests.
type nucleiScanner struct {
	info      plugin.ScannerInfo
	run       func(ctx context.Context, argv []string) ([]byte, error)
	templates *nucleiTemplateWarmer
}

// NewNuclei returns a Scanner that runs Nuclei for the "dast" control. Nuclei is a single Go
// binary that probes a live endpoint with a large community template library; Draugr parses its
// JSONL output rather than its SARIF export, so severity, the matched URL, and CWEs map cleanly
// onto Draugr's model.
func NewNuclei() plugin.Scanner {
	return nucleiScanner{
		info: plugin.ScannerInfo{
			Name:         "nuclei",
			Origin:       "projectdiscovery",
			Binary:       "nuclei",
			Controls:     []string{"dast"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetHost},
			ConfigSchema: json.RawMessage(noScannerOptions),
			// Declared rather than gated. A dynamic scanner exists to send traffic, so asking
			// per run for permission to do the thing the control is for would train people to
			// agree without reading. Stating it is still worth doing: probing a host you do not
			// own is unlawful in many jurisdictions, and until now nothing in the tool said so —
			// only the scope and disclaimer, which nobody reads mid-scan.
			Effects: []plugin.Effect{{
				Kind: plugin.EffectNetwork,
				Detail: "sends probe traffic to the endpoint, which is lawful only against " +
					"systems you own or have written permission to test",
			}},
		},
		run:       execArgv,
		templates: sharedNucleiTemplates,
	}
}

// Info describes the scanner.
func (s nucleiScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion reports the *template* version, not the binary's (implements
// plugin.CacheVersioner).
//
// The templates are what decide the answer, and they are republished daily — so a cached "no
// findings" against last week's set is a claim about a question nobody asked. The binary changes
// rarely enough that keying on it instead would be close to keying on nothing.
func (s nucleiScanner) CacheVersion(ctx context.Context) string {
	if v := sharedNucleiVersion.version(ctx); v != "" {
		return "nuclei-templates@" + v
	}
	return ""
}

// Prewarm downloads Nuclei's template set once before a run's concurrent fan-out, so parallel
// host scans don't each cold-start the download (implements plugin.Prewarmer). Best-effort: a
// failure is non-fatal (a real problem resurfaces at scan time).
func (s nucleiScanner) Prewarm(ctx context.Context) error { return s.templates.warm(ctx) }

// nucleiArgv builds the command line for a host URL:
//
//		nuclei -u <url> -jsonl -silent -nc -duc -etags headers
//
//	  - -jsonl writes one finding per line to stdout (parsed by nucleiToResults);
//	  - -silent -nc suppress the banner/progress and ANSI colors so stdout is clean JSONL;
//	  - -duc disables the update-check network call, keeping runs deterministic;
//	  - -etags excludes header templates (see excludedNucleiTags).
func nucleiArgv(url string) []string {
	return []string{
		"nuclei",
		"-u", url,
		"-jsonl",
		"-silent",
		"-nc",
		"-duc",
		"-etags", excludedNucleiTags,
	}
}

// Scan runs Nuclei against the host target and returns its findings as a SARIF report.
func (s nucleiScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("nuclei: unsupported target %T (want host)", target)
	}
	if host.URL == "" {
		return sarif.Report{}, errors.New("nuclei: host target has no url")
	}
	// If the template set could not be obtained, say that rather than letting Nuclei report the
	// symptom. Its own message — "no templates provided for scan" — reads like a mistake in the
	// descriptor, and sends the reader to the wrong place entirely.
	if s.templates != nil {
		if err := s.templates.templatesErr(); err != nil {
			return sarif.Report{}, fmt.Errorf("nuclei has no templates: %w", err)
		}
	}
	out, err := s.run(ctx, nucleiArgv(host.URL))
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run nuclei: %w", err)
	}
	return sarif.Report{Tool: s.info.Name, Results: nucleiToResults(out)}, nil
}

// nucleiFinding is the subset of a Nuclei JSONL result line that Draugr consumes.
type nucleiFinding struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Host       string `json:"host"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Classification struct {
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
}

// nucleiToResults converts Nuclei's JSONL output (one finding per line) into SARIF results.
// Blank and unparseable lines are skipped (best-effort: a corrupt line shouldn't drop the run).
func nucleiToResults(out []byte) []sarif.Result {
	var results []sarif.Result
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f nucleiFinding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		level, score, hasScore := nucleiSeverity(f.Info.Severity)
		uri := f.MatchedAt
		if uri == "" {
			uri = f.Host
		}
		results = append(results, sarif.Result{
			Tool:     "nuclei",
			RuleID:   f.TemplateID,
			Level:    level,
			Message:  nucleiMessage(f),
			Location: sarif.Location{URI: uri},
			Score:    score,
			HasScore: hasScore,
		})
	}
	return results
}

// nucleiMessage builds a finding message from the template name and description, appending any
// CWE identifiers so the classification travels with the finding (SARIF has no dedicated CWE
// field in Draugr's model).
func nucleiMessage(f nucleiFinding) string {
	msg := f.Info.Name
	if msg == "" {
		msg = f.TemplateID
	}
	if d := strings.TrimSpace(f.Info.Description); d != "" {
		msg += ": " + d
	}
	if cwes := nonEmpty(f.Info.Classification.CWEID); len(cwes) > 0 {
		msg += " (" + strings.Join(cwes, ", ") + ")"
	}
	return msg
}

// nucleiSeverity maps a Nuclei severity string to a SARIF level plus a numeric CVSS-style score,
// set together so severity counts and risk prioritization agree. Unknown/empty severities get no
// score and fall through to a note.
func nucleiSeverity(sev string) (sarif.Level, float64, bool) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return sarif.LevelError, 9.5, true
	case "high":
		return sarif.LevelError, 8.0, true
	case "medium":
		return sarif.LevelWarning, 5.0, true
	case "low":
		return sarif.LevelNote, 2.0, true
	case "info":
		return sarif.LevelNote, 1.0, true
	default:
		return sarif.LevelNote, 0, false
	}
}

// nonEmpty returns the non-blank, trimmed elements of s.
func nonEmpty(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// nucleiTemplateWarmer downloads Nuclei's template set once (memoized) so a run's concurrent host
// scans don't each cold-start the download. run is injectable for tests.
type nucleiTemplateWarmer struct {
	once sync.Once
	err  error
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

// warm downloads the template set at most once, and checks that it is actually there.
//
// No -duc here, though the scan invocation uses it and should. On a scan it disables the update
// check, which is what keeps a run deterministic. On `-update-templates` it disables the update
// itself: the command exits 0, downloads nothing, and leaves the directory as it found it. The
// result was a control that could never run — Nuclei is a template engine, and with no templates
// it fails with "no templates provided for scan", which reads like a descriptor mistake.
//
// The exit code is checked and then disbelieved. Nuclei exits 0 whether or not it fetched
// anything, so the only honest confirmation is to ask afterwards what it has.
func (w *nucleiTemplateWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		if _, err := w.run(ctx, []string{"nuclei", "-update-templates"}); err != nil {
			w.err = fmt.Errorf("download nuclei templates: %w", err)
			return
		}
		out, err := w.run(ctx, []string{"nuclei", "-templates-version"})
		if err != nil {
			w.err = fmt.Errorf("check nuclei templates: %w", err)
			return
		}
		if ok, _ := tools.NucleiTemplatesOK(out); !ok {
			w.err = errors.New("nuclei reported no template set after -update-templates — " +
				"dast cannot run without one; try `nuclei -update-templates` by hand to see why")
		}
	})
	return w.err
}

// templatesErr returns the reason the template set is unavailable, if it is.
func (w *nucleiTemplateWarmer) templatesErr() error { return w.err }

// sharedNucleiTemplates warms the template set once per process for the Nuclei scanner.
// Combined output, not stdout: `nuclei -templates-version` prints its answer entirely to
// stderr, so reading stdout alone reports no templates however many are installed.
var sharedNucleiTemplates = &nucleiTemplateWarmer{run: execArgvCombined}
