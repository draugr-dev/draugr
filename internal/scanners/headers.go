package scanners

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// httpHeadersScanner is a native (no external tool) scanner that fetches a running endpoint
// and evaluates its HTTP security response headers against the OWASP Secure Headers guidance.
// It serves the "headers" control. The header set is tuned by the host's type: browser hosts
// get the full browser suite; API hosts skip browser-only headers and get API-specific checks.
type httpHeadersScanner struct {
	info  plugin.ScannerInfo
	fetch func(ctx context.Context, url string) (http.Header, error)
}

// NewHTTPHeaders returns the native HTTP security-header scanner.
func NewHTTPHeaders() plugin.Scanner {
	return httpHeadersScanner{
		info: plugin.ScannerInfo{
			Name:        "http-headers",
			Controls:    []string{"headers"},
			TargetKinds: []plugin.TargetKind{plugin.TargetHost},
		},
		fetch: httpFetchHeaders,
	}
}

// Info describes the scanner.
func (s httpHeadersScanner) Info() plugin.ScannerInfo { return s.info }

// Scan fetches the host and evaluates its security headers, emitting one SARIF result per
// missing or misconfigured header.
func (s httpHeadersScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("http-headers: unsupported target %T (want host)", target)
	}
	if host.URL == "" {
		return sarif.Report{}, errors.New("http-headers: host target has no url")
	}
	header, err := s.fetch(ctx, host.URL)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("http-headers: fetch %s: %w", host.URL, err)
	}
	return sarif.Report{Tool: s.info.Name, Results: evaluateHeaders(host.URL, host.Type, header)}, nil
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
			Tool:     "http-headers",
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

// httpFetchHeaders performs a GET and returns the response headers. It follows redirects so
// the headers evaluated are those actually served to a client.
func httpFetchHeaders(ctx context.Context, url string) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // host URL is operator-provided in the Saga
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header, nil
}
