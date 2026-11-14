package scanners

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	// fetchUnverified is fetch reading the declared host without verifying its certificate, every
	// other host a redirect reaches still verified. Nil never reads past a certificate.
	fetchUnverified func(ctx context.Context, url string, browser bool) (response, error)
}

// response is what a fetch of the host returned, including the page for a browser host so the
// policy can be compared with what it governs.
type response struct {
	header     http.Header
	statusCode int
	body       []byte   // HTML only, and only for a browser host; empty otherwise
	url        *url.URL // where the redirects ended, which is what relative references resolve against
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
			Effects: []plugin.Effect{{
				Kind:   plugin.EffectNetwork,
				Detail: "sends an HTTP GET to the endpoint and follows its redirects",
			}},
		},
		fetch:           httpFetchHeaders,
		fetchUnverified: httpFetchHeadersUnverified,
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
	if err != nil && s.readsPastCertificate(host, err) {
		resp, err = s.fetchUnverified(ctx, host.URL, browser)
	}
	if err != nil {
		return sarif.Report{}, fmt.Errorf("draugr-headers: fetch %s: %w", host.URL, err)
	}
	results := evaluateHeaders(host.URL, host.Type, resp.header)
	if browser && len(resp.body) > 0 && resp.url != nil {
		results = evaluateAgainstPage(host.URL, resp, results)
	}
	report := sarif.Report{Tool: s.info.Name, Results: results}
	if resp.statusCode < http.StatusOK || resp.statusCode >= http.StatusMultipleChoices {
		report.Unchecked = []sarif.Unchecked{{
			Scanner:    s.info.Name,
			Check:      "response-headers",
			Group:      host.URL,
			Reason:     fmt.Sprintf("findings describe the HTTP %d response", resp.statusCode),
			PartlyRead: true,
		}}
	}
	return report, nil
}

// readsPastCertificate reports whether a fetch that failed on the host's certificate is repeated
// without verifying it.
//
// Only where the run reports that certificate itself (the tls control has a job on the same URL in
// the same component), so the failure is a finding with its fix rather than nowhere, and the headers
// are still answered instead of the control ending in an error about the same fact. The request
// sends no credential: a target carrying auth, or a URL carrying a user and password, which the
// client would send as a header, is never read this way, so no credential goes to a server that
// failed the check.
func (s draugrHeadersScanner) readsPastCertificate(host plugin.HostTarget, err error) bool {
	u, parseErr := url.Parse(host.URL)
	return s.fetchUnverified != nil && host.CertificateReported && host.Auth == nil &&
		parseErr == nil && u.User == nil && certificateRejected(err)
}

// certificateRejected reports whether a request failed because the server's certificate did not
// verify: expired or not yet valid, from an authority the system does not trust, or for another
// name. A refused handshake or an unsupported protocol is not this, and stays an error.
func certificateRejected(err error) bool {
	var (
		verification *tls.CertificateVerificationError
		invalid      x509.CertificateInvalidError
		unknown      x509.UnknownAuthorityError
		hostname     x509.HostnameError
	)
	return errors.As(err, &verification) || errors.As(err, &invalid) ||
		errors.As(err, &unknown) || errors.As(err, &hostname)
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
	return fetchHeadersWith(ctx, &http.Client{Timeout: headersTimeout}, target, browser)
}

// headersTimeout bounds one fetch, redirects included.
const headersTimeout = 15 * time.Second

// httpFetchHeadersUnverified is httpFetchHeaders accepting the target endpoint's certificate without
// verifying it. Only that endpoint, its host and port: a redirect to any other is verified as usual,
// since nothing in the run reports that one's certificate.
func httpFetchHeadersUnverified(ctx context.Context, target string, browser bool) (response, error) {
	u, err := url.Parse(target)
	if err != nil {
		return response{}, err
	}
	unverified := unverifiedTransport()
	client := &http.Client{Timeout: headersTimeout, Transport: endpointTrust{
		endpoint: endpointOf(u), unverified: unverified, verified: http.DefaultTransport,
	}}
	return fetchHeadersWith(ctx, client, target, browser)
}

// unverifiedTransport is the transport the declared endpoint is read through when its certificate
// failed: the default one, without verifying the certificate and without a proxy.
func unverifiedTransport() *http.Transport {
	unverified := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if def, ok := http.DefaultTransport.(*http.Transport); ok {
		unverified = def.Clone()
	}
	// Straight to the host, as the tls control dials it. Through a proxy that inspects TLS, the
	// certificate this fetch rejected would be the proxy's, which the tls control never sees.
	unverified.Proxy = nil
	// Used for the declared endpoint only, whose certificate the tls control verifies and reports in
	// the same run; endpointTrust sends every other one through the default, verifying transport.
	// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification
	unverified.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 -- the declared endpoint only; see above
	}
	return unverified
}

// endpointTrust sends a request to one endpoint through a transport that does not verify its
// certificate, and every other request, a redirect's included, through one that does.
type endpointTrust struct {
	endpoint             string
	unverified, verified http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (e endpointTrust) RoundTrip(r *http.Request) (*http.Response, error) {
	if endpointOf(r.URL) == e.endpoint {
		return e.unverified.RoundTrip(r)
	}
	return e.verified.RoundTrip(r)
}

// endpointOf is a URL's scheme, host and port, the port its scheme's default where none is written,
// so https://example.com and https://EXAMPLE.com:443 are one endpoint.
func endpointOf(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

// fetchHeadersWith is the GET both fetches make, through client.
func fetchHeadersWith(ctx context.Context, client *http.Client, target string, browser bool) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return response{}, err
	}
	if browser {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	out := response{header: resp.Header, statusCode: resp.StatusCode, url: resp.Request.URL}
	if browser && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		// A body that fails partway is compared on what arrived; the headers are already in hand.
		out.body, _ = io.ReadAll(io.LimitReader(resp.Body, maxPage))
	}
	return out, nil
}
