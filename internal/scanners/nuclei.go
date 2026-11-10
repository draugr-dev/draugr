package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// nucleiScanner runs ProjectDiscovery Nuclei against a running endpoint (a component's host) and
// converts its JSONL output to SARIF. It serves the "dast" control. run is injectable for tests.
type nucleiScanner struct {
	info      plugin.ScannerInfo
	run       func(ctx context.Context, argv []string) ([]byte, error)
	templates *nucleiTemplateWarmer
	// reach checks the endpoint answers before Nuclei runs (see nucleiReach). Nil skips the check,
	// for a test that fakes run against an address nothing listens on.
	reach func(ctx context.Context, url, header string) error
	// resolvConf is where the machine's DNS resolvers are read from, for -r. Empty passes no -r, for a
	// test that does not care about the command line's resolvers.
	resolvConf string
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
			Data:         nucleiData,
			Binary:       "nuclei",
			Controls:     []string{"dast"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetHost},
			ConfigSchema: json.RawMessage(nucleiConfigSchema),
			// The network effect is declared rather than gated. A dynamic scanner exists to send
			// traffic, so asking per run for permission to do the thing the control is for would train
			// people to agree without reading. Stating it is still worth doing: probing a host you do
			// not own is unlawful in many jurisdictions, and the scope and disclaimer are not read
			// mid-scan.
			//
			// The mutate effect is gated, for a job whose block sets intrusive and for a job whose host
			// declares spec. The intrusive templates can leave a user, a file or a changed setting
			// behind on the endpoint. A spec scan fuzzes every parameter of the operations it keeps and
			// requests each of them, and a GET with a side effect runs as readily as a read. Either is
			// a decision somebody makes on purpose rather than a property of every dast run.
			Effects: []plugin.Effect{{
				Kind: plugin.EffectNetwork,
				Detail: "sends probe traffic to the endpoint, which is lawful only against " +
					"systems you own or have written permission to test",
			}, {
				Kind:   plugin.EffectMutate,
				Option: nucleiIntrusiveKey,
				Detail: "runs the templates tagged intrusive, some of which change the endpoint, " +
					"such as creating a user or uploading a file with PUT",
			}, {
				Kind: plugin.EffectMutate,
				Spec: true,
				Detail: "sends injection payloads into every parameter of the spec's operations, a GET that " +
					"changes state included",
			}, {
				Kind:    plugin.EffectDisclosure,
				Option:  nucleiInteractshKey,
				Default: true,
				Online:  true,
				Detail: "the templates that detect out-of-band callbacks have the endpoint contact " +
					"ProjectDiscovery's public interactsh servers, which see where each callback came " +
					"from and what it sent",
			}},
		},
		run:        execArgv,
		templates:  sharedNucleiTemplates,
		reach:      nucleiReach,
		resolvConf: nucleiResolvConf,
	}
}

// nucleiReachTimeout bounds the check that the endpoint answers.
const nucleiReachTimeout = 15 * time.Second

// nucleiReach sends one GET to the endpoint, with the scan's header line where it has one, and
// reports whether anything answered.
//
// Nuclei exits 0 and writes nothing when it cannot reach its target: a name with no DNS record, a
// port nothing listens on, a handshake that fails. Its empty output is then the same bytes as a
// scan of a live site that matched no template, and the control would pass on a site that does
// not exist. So the endpoint is asked first, once, and a failure is the control's error.
//
// Any HTTP response counts, whatever its status: a 404 or a 500 is a server answering, and Nuclei
// scans it. A redirect is not followed, because the endpoint answering is the question, and where
// it points is Nuclei's to follow. A connection the server accepted counts as well, whatever fails
// after it: Nuclei does not verify certificates and speaks older TLS than this client offers, so an
// internal service with a self-signed certificate is one it scans, and a handshake failing here
// says nothing about whether Nuclei reaches it.
func nucleiReach(ctx context.Context, url, header string) error {
	ctx, cancel := context.WithTimeout(ctx, nucleiReachTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if name, value, ok := strings.Cut(header, ":"); ok {
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	var connected atomic.Bool
	var dialer net.Dialer
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, network, addr)
				if err == nil {
					connected.Store(true)
				}
				return conn, err
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		if connected.Load() {
			return nil
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.Body.Close()
}

// Info describes the scanner.
func (s nucleiScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion reports the *template* version, not the binary's (implements
// plugin.CacheVersioner).
//
// The templates are what decide the answer, and they are republished daily, so a cached "no
// findings" against last week's set is a claim about a question nobody asked. The binary changes
// rarely enough that keying on it instead would be close to keying on nothing. Draugr's own version
// is in the key too, because Draugr decides which of those templates run and which resolvers they ask,
// and a finding cached under a wider command line would outlive the change that narrowed it.
func (s nucleiScanner) CacheVersion(ctx context.Context) string {
	if v := sharedNucleiVersion.version(ctx); v != "" {
		return draugrCacheVersion() + ";nuclei-templates@" + v
	}
	return ""
}

// Prewarm downloads Nuclei's template set once before a run's concurrent fan-out, so parallel
// host scans don't each cold-start the download (implements plugin.Prewarmer). Best-effort: a
// failure is non-fatal (a real problem resurfaces at scan time).
func (s nucleiScanner) Prewarm(ctx context.Context) error { return s.templates.warm(ctx) }

// DataState reports the template set's release and when it was downloaded (implements
// plugin.DataStater).
func (s nucleiScanner) DataState(ctx context.Context) []plugin.DataState {
	return sharedNucleiData.templates(ctx)
}

// authHeader renders the header line an auth block asks for, resolving the credential from the
// environment at the moment of the scan.
//
// Authenticating declares no additional effect, which is deliberate rather than an omission.
// Writing `tokenEnv` into a descriptor is already an explicit, per-endpoint opt-in, committed and
// reviewable. The consent an effect would ask for has been given by the act of configuring it.
// Effects are also a property of a scanner rather than of a job, so declaring one here would
// demand `allowEffects` from every dast run including the anonymous ones, which teaches people to
// accept without reading. What the scan did is recorded in provenance instead.
//
// The value is read here and nowhere earlier on purpose: it must not reach the descriptor, a
// cache key, a report, or a log. Everything upstream carries the variable's name instead.
//
// The endpoint and the variable are both written in the descriptor, so a change to it could send
// any of the job's secrets to any host. The variable has to be one $DRAUGR_TOKEN_ENVS lists, which
// the pipeline sets.
//
// Plain http is accepted, unlike for a publisher's token. The endpoint is a declared target, often
// a service on the CI network with no certificate, and what TLS would protect against there is
// somebody reading that network rather than somebody editing the descriptor.
func authHeader(a *plugin.HostAuth) (string, error) {
	if a == nil {
		return "", nil
	}
	name, token, err := credential.Token(a.TokenEnv, "")
	if err != nil {
		return "", fmt.Errorf("nuclei: auth.%w", err)
	}
	if token == "" {
		// Loudly, because the alternative is the failure this feature exists to remove: a scan
		// that quietly falls back to anonymous, probes the login page, and reports a pass about
		// the application behind it.
		return "", fmt.Errorf("nuclei: $%s is empty, so this scan would run unauthenticated and "+
			"report on the login page rather than the application behind it", name)
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
//		nuclei -u <url> -jsonl -silent -nc -duc -etags headers,intrusive [options]
//
//	  - -jsonl writes one finding per line to stdout (parsed by nucleiToResults);
//	  - -silent -nc suppress the banner/progress and ANSI colors so stdout is clean JSONL;
//	  - -duc disables the update-check network call, keeping runs deterministic;
//	  - options are nucleiOptionArgs, which always begin with the -etags exclusions.
func nucleiArgv(url, headerFile string, options []string) []string {
	return nucleiTargetArgv([]string{"-u", url}, headerFile, options)
}

// nucleiSpecArgv fuzzes the operations a rewritten OpenAPI document declares, rather than the paths
// Nuclei's templates name under one URL. Neither path follows a link.
//
// -dast is passed rather than left implied. Nuclei 3.11.1 turns it on for every input mode other
// than list (internal/runner/runner.go), and then loads only the templates that fuzz a request, so
// this run sends payloads and runs none of the default set. Named here, the command line says what
// the run does, and a Nuclei that stopped implying it would not quietly turn the run into a few GETs.
//
// -sfv is not optional and not silent. Without it Nuclei refuses a specification whose required
// parameters it cannot fill. Which is most of them, and scans nothing at all. With it, those
// requests are skipped quietly, so Draugr counts them while rewriting the document and the run
// reports how much of the API went unexercised.
func nucleiSpecArgv(specPath, headerFile string, options []string) []string {
	return nucleiTargetArgv([]string{"-l", specPath, "-im", "openapi", "-sfv", "-dast"}, headerFile, options)
}

func nucleiTargetArgv(target []string, headerFile string, options []string) []string {
	argv := append([]string{"nuclei"}, target...)
	argv = append(argv, "-jsonl", "-silent", "-nc", "-duc")
	argv = append(argv, options...)
	// A path, never the header itself. -H accepts either, and only one of them keeps the
	// credential out of the process list.
	if headerFile != "" {
		argv = append(argv, "-H", headerFile)
	}
	return argv
}

// Scan runs Nuclei against the host target and returns its findings as a SARIF report.
func (s nucleiScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("nuclei: unsupported target %T (want host)", target)
	}
	if host.URL == "" {
		return sarif.Report{}, errors.New("nuclei: host target has no url")
	}
	// Before anything else, so a block Nuclei would run differently from what it says stops the
	// scan before a request is sent.
	options, err := nucleiOptionArgs(cfg)
	if err != nil {
		return sarif.Report{}, err
	}
	// If the template set could not be obtained, say that rather than letting Nuclei report the
	// symptom. Its own message, "no templates provided for scan". Reads like a mistake in the
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
	// After the credential is resolved, so a scan that cannot authenticate sends nothing at all, and
	// with it, so a scan that can sends no anonymous request either.
	if s.reach != nil {
		if err := s.reach(ctx, host.URL, header); err != nil {
			return sarif.Report{}, fmt.Errorf("nuclei: %s did not answer, so nothing was scanned: %w", host.URL, err)
		}
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

	// The scan tests the URL and nothing past it, unless the descriptor names its own templates.
	var leftOut []string
	if s.templates != nil && !nucleiNamesTemplates(cfg) {
		leftOut, err = s.templates.reaching(ctx)
		if err != nil {
			return sarif.Report{}, fmt.Errorf("nuclei: could not read the template set to leave out what reaches "+
				"past the URL, so nothing was scanned; `nuclei -update-templates` fetches it again: %w", err)
		}
		if len(leftOut) > 0 {
			options = append(options, "-eid", strings.Join(leftOut, ","))
		}
	}
	var resolverField *sarif.Field
	if s.resolvConf != "" {
		args, field, cleanup, err := nucleiResolverFile(ctx, s.resolvConf)
		if err != nil {
			return sarif.Report{}, err
		}
		defer cleanup()
		options, resolverField = append(options, args...), field
	}

	// The default templates at the URL, and for a host with spec a second run that fuzzes the
	// operations the document declares. The fuzzing run loads only templates that fuzz a request, so
	// without the first the spec would narrow the scan it was declared to widen.
	argvs := [][]string{nucleiArgv(host.URL, headerFile, options)}
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
		argvs = append(argvs, nucleiSpecArgv(spec.Path, headerFile, options))
	}

	// A spec scan's two runs select templates differently, the first those that do not fuzz and the
	// second those that do, and a set the descriptor narrowed, by naming templates or tags, can hold
	// none for one of them. Nuclei then exits 1 with "no templates provided for scan". That run is
	// recorded as having had nothing to run, and only a scan where neither run had any fails.
	var results []sarif.Result
	ran := make([]bool, len(argvs))
	for i, argv := range argvs {
		out, err := s.run(ctx, argv)
		if err != nil {
			if len(argvs) > 1 && nucleiHadNoTemplates(err) {
				continue
			}
			return sarif.Report{}, fmt.Errorf("run nuclei: %w", err)
		}
		found, err := nucleiToResults(out)
		if err != nil {
			return sarif.Report{}, err
		}
		results = append(results, found...)
		ran[i] = true
	}
	if !slices.Contains(ran, true) {
		return sarif.Report{}, errors.New("nuclei: the templates this scan may use hold none that run at the " +
			"endpoint and none that fuzz the spec's operations, so nothing was scanned")
	}
	report := sarif.Report{Tool: s.info.Name, Results: results}
	// Recorded so a reader can tell which of two very different scans produced this. An
	// authenticated run reaches the application; an anonymous one reaches the login page, and
	// their findings are not comparable.
	prov := nucleiProvenance(host, spec, ran)
	prov.Fields = append(prov.Fields, nucleiOptionFields(cfg)...)
	if !nucleiNamesTemplates(cfg) {
		prov.Fields = append(prov.Fields, nucleiLeftOut(leftOut))
	}
	if resolverField != nil {
		prov.Fields = append(prov.Fields, *resolverField)
	}
	report.Provenance = append(report.Provenance, prov)
	return report, nil
}

// nucleiProvenance says whether the scan authenticated, and as what, by naming the variable, never
// its value.
//
// The endpoint is the URL alone rather than the target's identity. The identity appends the spec
// and auth markers so two jobs against one URL key apart, and the same facts are fields of their
// own here, so the identity as a value would print each of them twice.
//
// For a host with spec, ran says which of its two runs had templates to run, the default templates
// at the endpoint and then the fuzzing of the spec's operations.
func nucleiProvenance(host plugin.HostTarget, spec preparedSpec, ran []bool) sarif.Provenance {
	fields := []sarif.Field{{Key: "endpoint", Value: plugin.SourceURL(host.URL)}}
	if host.Spec != nil {
		fields = append(fields,
			sarif.Field{Key: "runs", Value: nucleiRuns(ran)},
			sarif.Field{Key: "spec", Value: host.Spec.Path},
			sarif.Field{Key: "methods", Value: strings.Join(plugin.NormalizeMethods(host.Spec.Methods), ", ")},
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

// nucleiRuns says which of a spec scan's two runs had templates to run. Short, because the measured-against
// line it sits in is cut at a fixed length, and the operations a scan left out come after it.
func nucleiRuns(ran []bool) string {
	switch {
	case len(ran) == 2 && ran[0] && !ran[1]:
		return "default templates only; no template fuzzes"
	case len(ran) == 2 && !ran[0] && ran[1]:
		return "fuzzing only; no template runs at the endpoint"
	}
	return "default templates, then fuzzing"
}

// nucleiHadNoTemplates reports whether err is Nuclei's exit over a run whose template selection
// left nothing to run. toolexec puts the line Nuclei ended on, at FTL, after the exit status.
func nucleiHadNoTemplates(err error) bool {
	return strings.Contains(err.Error(), "no templates provided for scan")
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
//
// A line that does not parse is an error, not a line to skip. With `-jsonl -silent` every line on
// stdout is a finding, so one that cannot be read is a finding that would be dropped, and output
// none of whose lines parse, from a changed flag or format, would otherwise read as an application
// with nothing wrong.
func nucleiToResults(out []byte) ([]sarif.Result, error) {
	var results []sarif.Result
	for n, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f nucleiFinding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			return nil, fmt.Errorf("nuclei: line %d of its output is not a finding: %s", n+1, truncateLine(line, 120))
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
	return results, nil
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
	// reach holds the templates of the set that reach past the URL.
	reach nucleiReachScan
}

// warm brings the template set up to date at most once, and checks that there is one.
//
// No -duc here, though the scan invocation uses it and should. On a scan it disables the update
// check, which is what keeps a run deterministic. On `-update-templates` it disables the update
// itself: the command exits 0, downloads nothing, and leaves the directory as it found it. The
// result was a control that could never run. Nuclei is a template engine, and with no templates it
// fails with "no templates provided for scan", which reads like a descriptor mistake.
//
// The exit code is checked and then disbelieved. Nuclei exits 0 whether or not it fetched
// anything, so the only honest confirmation is to ask afterwards what it has.
//
// A failed update over a set that is already on disk is a warning and not an error, which is the
// rule Draugr already applies to an exploitability feed: a fetch that fails where there is a usable
// copy on disk uses the copy and says so, and only an empty hand is fatal. The template set is
// republished daily from a host a scan does not control, and refusing to run over yesterday's
// copy of it means an egress allowlist, a rate limit or an outage stops a gate that had everything
// it needed. Said out loud rather than swallowed, because a scan run against a set of unknown age
// is a different claim from one run against today's.
func (w *nucleiTemplateWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		onDisk := w.version(ctx)
		if _, err := w.run(ctx, []string{"nuclei", "-update-templates"}); err != nil {
			if onDisk != "" {
				slog.WarnContext(ctx, "nuclei templates not updated, scanning with the set on disk",
					"templates", onDisk, "error", err)
				return
			}
			w.err = fmt.Errorf("download nuclei templates: %w", err)
			return
		}
		out, err := w.run(ctx, []string{"nuclei", "-templates-version"})
		if err != nil {
			if onDisk != "" {
				slog.WarnContext(ctx, "nuclei templates could not be checked after updating, "+
					"scanning with the set on disk", "templates", onDisk, "error", err)
				return
			}
			w.err = fmt.Errorf("check nuclei templates: %w", err)
			return
		}
		// Asked of the directory as well as the version, because a failed download exits 0 and a
		// set restored without Nuclei's own config reports a blank version over templates it
		// loads and runs. Only an empty directory is fatal.
		switch set := tools.NucleiTemplates(out); {
		case !set.Present:
			w.err = fmt.Errorf("nuclei has no templates in %s after -update-templates, and dast "+
				"cannot run without them; try `nuclei -update-templates` by hand to see why", set.Dir)
		case set.Version == "":
			slog.WarnContext(ctx, "nuclei templates are on disk and their version could not be read, "+
				"scanning with the set on disk", "templates", set.Dir)
		}
	})
	return w.err
}

// version is the template set already installed, or "" where there is none.
//
// Asked before the update, so a failure afterwards can be told apart from an empty machine. Every
// error here reads as "no templates", which is the conservative direction: it costs a warning that
// could have been avoided and never claims a set that is not there.
func (w *nucleiTemplateWarmer) version(ctx context.Context) string {
	out, err := w.run(ctx, []string{"nuclei", "-templates-version"})
	if err != nil {
		return ""
	}
	ok, describe := tools.NucleiTemplatesOK(out)
	if !ok {
		return ""
	}
	return describe
}

// templatesErr returns the reason the template set is unavailable, if it is.
func (w *nucleiTemplateWarmer) templatesErr() error { return w.err }

// sharedNucleiTemplates warms the template set once per process for the Nuclei scanner.
// Combined output, not stdout: `nuclei -templates-version` prints its answer entirely to
// stderr, so reading stdout alone reports no templates however many are installed.
var sharedNucleiTemplates = &nucleiTemplateWarmer{run: execArgvCombined}

// truncateLine keeps the first n runes of line, which is enough to recognize what printed it.
func truncateLine(line string, n int) string {
	if r := []rune(line); len(r) > n {
		return string(r[:n]) + "…"
	}
	return line
}
