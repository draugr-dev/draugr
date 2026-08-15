package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
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

// authHeader renders the header line an auth block asks for, resolving the credential from the
// environment at the moment of the scan.
//
// Authenticating declares no additional effect, which is deliberate rather than an omission.
// Writing `tokenEnv` into a descriptor is already an explicit, per-endpoint opt-in, committed and
// reviewable — the consent an effect would ask for has been given by the act of configuring it.
// Effects are also a property of a scanner rather than of a job, so declaring one here would
// demand `allowEffects` from every dast run including the anonymous ones, which teaches people to
// accept without reading. What the scan did is recorded in provenance instead.
//
// The value is read here and nowhere earlier on purpose: it must not reach the descriptor, a
// cache key, a report, or a log. Everything upstream carries the variable's name instead.
func authHeader(a *plugin.HostAuth) (string, error) {
	if a == nil {
		return "", nil
	}
	token := os.Getenv(a.TokenEnv)
	if token == "" {
		// Loudly, because the alternative is the failure this feature exists to remove: a scan
		// that quietly falls back to anonymous, probes the login page, and reports a pass about
		// the application behind it.
		return "", fmt.Errorf("nuclei: $%s is empty, so this scan would run unauthenticated and "+
			"report on the login page rather than the application behind it", a.TokenEnv)
	}
	switch a.Kind {
	case "bearer":
		return "Authorization: Bearer " + token, nil
	case "header":
		return a.Header + ": " + token, nil
	}
	return "", fmt.Errorf("nuclei: unsupported auth type %q", a.Kind)
}

// writeHeaderFile puts the header where Nuclei can read it and a process list cannot.
//
// Nuclei's -H takes a file as readily as a literal, which is the whole reason this exists: a
// credential passed on the command line is readable by every user on the machine for as long as
// the scan runs. The file is created 0600 and removed by the caller.
func writeHeaderFile(header string) (string, func(), error) {
	f, err := os.CreateTemp("", "draugr-nuclei-headers-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if _, err := f.WriteString(header + "\n"); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return f.Name(), cleanup, nil
}

// nucleiArgv builds the command line for a host URL:
//
//		nuclei -u <url> -jsonl -silent -nc -duc -etags headers
//
//	  - -jsonl writes one finding per line to stdout (parsed by nucleiToResults);
//	  - -silent -nc suppress the banner/progress and ANSI colors so stdout is clean JSONL;
//	  - -duc disables the update-check network call, keeping runs deterministic;
//	  - -etags excludes header templates (see excludedNucleiTags).
func nucleiArgv(url, headerFile string) []string {
	return nucleiTargetArgv([]string{"-u", url}, headerFile)
}

// nucleiSpecArgv scans the operations a rewritten OpenAPI document declares, rather than crawling.
//
// -sfv is not optional and not silent. Without it Nuclei refuses a specification whose required
// parameters it cannot fill — which is most of them — and scans nothing at all. With it, those
// requests are skipped quietly, so Draugr counts them while rewriting the document and the run
// reports how much of the API went unexercised.
func nucleiSpecArgv(specPath, headerFile string) []string {
	return nucleiTargetArgv([]string{"-l", specPath, "-im", "openapi", "-sfv"}, headerFile)
}

func nucleiTargetArgv(target []string, headerFile string) []string {
	argv := append([]string{"nuclei"}, target...)
	argv = append(argv,
		"-jsonl",
		"-silent",
		"-nc",
		"-duc",
		"-etags", excludedNucleiTags,
	)
	// A path, never the header itself. -H accepts either, and only one of them keeps the
	// credential out of the process list.
	if headerFile != "" {
		argv = append(argv, "-H", headerFile)
	}
	return argv
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
	header, err := authHeader(host.Auth)
	if err != nil {
		return sarif.Report{}, err
	}
	var headerFile string
	if header != "" {
		path, cleanup, err := writeHeaderFile(header)
		if err != nil {
			return sarif.Report{}, fmt.Errorf("nuclei: prepare credential: %w", err)
		}
		defer cleanup()
		headerFile = path
	}

	argv := nucleiArgv(host.URL, headerFile)
	var spec preparedSpec
	if host.Spec != nil {
		endpoint, err := endpointForSpec(host.URL)
		if err != nil {
			return sarif.Report{}, fmt.Errorf("nuclei: %w", err)
		}
		spec, err = prepareSpec(host.Spec.Path, endpoint, host.Spec.Methods)
		if err != nil {
			return sarif.Report{}, fmt.Errorf("nuclei: %w", err)
		}
		defer spec.Cleanup()
		// What the scan will not cover, said before it runs rather than inferred from a short
		// report afterwards. A spec-driven scan that quietly exercised a third of an API is the
		// shape of pass this control exists to avoid.
		if summary := spec.DroppedSummary(); summary != "" {
			slog.InfoContext(ctx, "some operations are outside the methods this scan may use",
				"endpoint", host.URL, "detail", summary,
				"hint", "add them to spec.methods to include them")
		}
		if spec.Unfillable > 0 {
			slog.WarnContext(ctx, "some operations declare required parameters the scan cannot fill, "+
				"and will be skipped", "endpoint", host.URL, "operations", spec.Unfillable,
				"hint", "give those parameters an example or a default in the specification")
		}
		argv = nucleiSpecArgv(spec.Path, headerFile)
	}

	out, err := s.run(ctx, argv)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("run nuclei: %w", err)
	}
	report := sarif.Report{Tool: s.info.Name, Results: nucleiToResults(out)}
	// Recorded so a reader can tell which of two very different scans produced this. An
	// authenticated run reaches the application; an anonymous one reaches the login page, and
	// their findings are not comparable.
	report.Provenance = append(report.Provenance, nucleiProvenance(host, spec))
	return report, nil
}

// nucleiProvenance says whether the scan authenticated, and as what — by naming the variable,
// never its value.
func nucleiProvenance(host plugin.HostTarget, spec preparedSpec) sarif.Provenance {
	fields := []sarif.Field{{Key: "endpoint", Value: host.Identity()}}
	if host.Spec != nil {
		fields = append(fields,
			sarif.Field{Key: "spec", Value: host.Spec.Path},
			sarif.Field{Key: "methods", Value: strings.Join(plugin.NormaliseMethods(host.Spec.Methods), ", ")},
			sarif.Field{Key: "operations", Value: strconv.Itoa(spec.Kept)})
		if summary := spec.DroppedSummary(); summary != "" {
			fields = append(fields, sarif.Field{Key: "excluded", Value: summary})
		}
		if spec.Unfillable > 0 {
			fields = append(fields, sarif.Field{
				Key: "unfilled", Value: strconv.Itoa(spec.Unfillable) + " with parameters the scan could not supply"})
		}
	}
	if host.Auth != nil {
		fields = append(fields,
			sarif.Field{Key: "authenticated", Value: host.Auth.Kind},
			sarif.Field{Key: "credentialFrom", Value: "$" + host.Auth.TokenEnv})
	}
	return sarif.Provenance{Tool: "nuclei", Fields: fields}
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
