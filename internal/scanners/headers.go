package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// draugrHeadersScanner is a native (no external tool) scanner that fetches a running endpoint
// and evaluates its HTTP security response headers against the OWASP Secure Headers guidance.
// It serves the "headers" control. The header set is tuned by the host's type: browser hosts
// get the full browser suite; API hosts skip browser-only headers and get API-specific checks.
type draugrHeadersScanner struct {
	info  plugin.ScannerInfo
	fetch func(ctx context.Context, url string, browser bool) (response, error)
}

// response is what a fetch of the host returned: the headers, and for a browser host the page
// itself, so the policy can be compared with what it governs.
type response struct {
	header http.Header
	body   []byte   // HTML only, and only for a browser host; empty otherwise
	url    *url.URL // where the redirects ended, which is what relative references resolve against
}

// maxPage bounds how much of a page is read. A page larger than this is compared on what arrived,
// which holds the <head> and everything a policy is most often wrong about.
const maxPage = 2 << 20

// NewHTTPHeaders returns the native HTTP security-header scanner.
func NewHTTPHeaders() plugin.Scanner {
	return draugrHeadersScanner{
		info: plugin.ScannerInfo{
			Name:         "draugr-headers",
			Origin:       plugin.OriginDraugr,
			Controls:     []string{"headers"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetHost},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		fetch: httpFetchHeaders,
	}
}

// Info describes the scanner.
func (s draugrHeadersScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion ties cached results to this binary (implements plugin.CacheVersioner).
//
// A native scanner has no external tool to ask, and the header checklist and the CSP grading live
// in this binary, so a Draugr upgrade is what changes the answer. Adding a CSP rule must not leave
// every cached header result standing.
func (s draugrHeadersScanner) CacheVersion(context.Context) string { return draugrCacheVersion() }

// Scan fetches the host and evaluates its security headers, emitting one SARIF result per
// missing or misconfigured header.
func (s draugrHeadersScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("draugr-headers: unsupported target %T (want host)", target)
	}
	if host.URL == "" {
		return sarif.Report{}, errors.New("draugr-headers: host target has no url")
	}
	browser := !strings.EqualFold(host.Type, "api")
	resp, err := s.fetch(ctx, host.URL, browser)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("draugr-headers: fetch %s: %w", host.URL, err)
	}
	results := evaluateHeaders(host.URL, host.Type, resp.header)
	if browser && len(resp.body) > 0 && resp.url != nil {
		results = evaluateAgainstPage(host.URL, resp, results)
	}
	return sarif.Report{Tool: s.info.Name, Results: results}, nil
}

// evaluateAgainstPage compares the policy with the page it was served with: what the policy
// blocks, and what on the page depends on 'unsafe-inline' where the policy allows it.
//
// An enforced policy is judged first. A Report-Only one is judged only when nothing is enforced,
// because that is the case where somebody is testing a policy before switching it on and the
// question is what switching it on would break.
func evaluateAgainstPage(target string, resp response, results []sarif.Result) []sarif.Result {
	pc := readPage(resp.url, resp.body)
	policy, reportOnly := resp.header.Get("Content-Security-Policy"), false
	if policy == "" {
		policy, reportOnly = resp.header.Get("Content-Security-Policy-Report-Only"), true
	}
	if policy == "" {
		return results
	}
	for i := range results {
		if results[i].RuleID == "headers/csp-unsafe-inline" {
			results[i].Message += inlineEvidence(pc)
		}
	}
	evaluatePage(policy, reportOnly, pc, func(ruleID, message string, level sarif.Level) {
		results = append(results, sarif.Result{
			Tool: "draugr-headers", RuleID: ruleID, Level: level, Message: message,
			Location: sarif.Location{URI: target},
		})
	})
	return results
}

// evaluateHeaders applies the security-header checklist. Rules are grouped into universal
// (any endpoint), browser-only, and API-only, selected by hostType ("api" → API rules;
// anything else, including "browser" and empty, → browser rules).
func evaluateHeaders(url, hostType string, h http.Header) []sarif.Result {
	https := strings.HasPrefix(strings.ToLower(url), "https://")
	isAPI := strings.EqualFold(hostType, "api")

	var out []sarif.Result
	add := func(ruleID, message string, level sarif.Level) {
		out = append(out, sarif.Result{
			Tool:     "draugr-headers",
			RuleID:   ruleID,
			Level:    level,
			Message:  message,
			Location: sarif.Location{URI: url},
		})
	}

	// --- Universal (browser and API) ---
	if https && h.Get("Strict-Transport-Security") == "" {
		add("headers/hsts-missing",
			"Missing Strict-Transport-Security: add HSTS (e.g. 'max-age=31536000; includeSubDomains') to force HTTPS.",
			sarif.LevelWarning)
	}
	switch xcto := strings.TrimSpace(h.Get("X-Content-Type-Options")); {
	case xcto == "":
		add("headers/x-content-type-options-missing",
			"Missing X-Content-Type-Options: add 'nosniff' to stop MIME-type sniffing.",
			sarif.LevelWarning)
	case !strings.EqualFold(xcto, "nosniff"):
		add("headers/x-content-type-options-invalid",
			fmt.Sprintf("X-Content-Type-Options is %q; it should be 'nosniff'.", xcto),
			sarif.LevelWarning)
	}
	if v := h.Get("Server"); v != "" {
		add("headers/server-disclosure",
			fmt.Sprintf("Server header discloses %q; remove or obfuscate it to reduce fingerprinting.", v),
			sarif.LevelNote)
	}
	if v := h.Get("X-Powered-By"); v != "" {
		add("headers/x-powered-by-disclosure",
			fmt.Sprintf("X-Powered-By discloses %q; remove it to reduce fingerprinting.", v),
			sarif.LevelNote)
	}

	if isAPI {
		// --- API-only ---
		if h.Get("Access-Control-Allow-Origin") == "*" {
			if strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true") {
				add("headers/cors-wildcard-with-credentials",
					"Access-Control-Allow-Origin '*' combined with Allow-Credentials 'true' is invalid and unsafe; echo an explicit allowed origin instead.",
					sarif.LevelError)
			} else {
				add("headers/cors-wildcard",
					"Access-Control-Allow-Origin '*' allows any origin; restrict it to the origins that need access.",
					sarif.LevelWarning)
			}
		}
		if h.Get("Cache-Control") == "" {
			add("headers/cache-control-missing",
				"No Cache-Control: add 'no-store' on responses that return sensitive data so they aren't cached.",
				sarif.LevelNote)
		}
		return out
	}

	// --- Browser-only ---
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		add("headers/csp-missing",
			"Missing Content-Security-Policy: add a CSP to mitigate XSS and content-injection.",
			sarif.LevelWarning)
	} else {
		// Present is not the same as effective. A policy can name every directive and still
		// allow an injected script to run, so the content gets judged too.
		evaluateCSP(csp, add)
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		add("headers/x-frame-options-missing",
			"Missing X-Frame-Options: add 'DENY' (or a CSP 'frame-ancestors' directive) to prevent clickjacking.",
			sarif.LevelWarning)
	}
	if h.Get("Referrer-Policy") == "" {
		add("headers/referrer-policy-missing",
			"Missing Referrer-Policy: add one (e.g. 'strict-origin-when-cross-origin') to limit referrer leakage.",
			sarif.LevelNote)
	}
	if h.Get("Permissions-Policy") == "" {
		add("headers/permissions-policy-missing",
			"Missing Permissions-Policy: add one to restrict powerful browser features (camera, geolocation, …).",
			sarif.LevelNote)
	}
	return out
}

// httpFetchHeaders performs a GET and returns the response headers, and for a browser host the
// page. It follows redirects so the headers evaluated are those actually served to a client.
//
// A browser host is asked for HTML the way a browser asks. Some servers and proxies vary the page
// on Accept, and a CDN can inject a script only into responses a browser would render, so a page
// fetched with a bare Accept is not the page a visitor's browser holds the policy against.
func httpFetchHeaders(ctx context.Context, target string, browser bool) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil) //nolint:gosec // host URL is operator-provided in the Saga
	if err != nil {
		return response{}, err
	}
	if browser {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	out := response{header: resp.Header, url: resp.Request.URL}
	if browser && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		// A body that fails partway is compared on what arrived; the headers are already in hand.
		out.body, _ = io.ReadAll(io.LimitReader(resp.Body, maxPage))
	}
	return out, nil
}
