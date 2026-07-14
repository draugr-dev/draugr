# Scanner: `http-headers` (HTTP security headers)

- **Control:** [`headers`](../controllers/headers.md)
- **Tool:** **native** — no external tool. A Go HTTP client fetches each host and evaluates
  its response headers against the OWASP Secure Headers guidance.
- **Status:** ✅ implemented
- **Target:** a running endpoint (`HostTarget`) — a component's `hosts:`
- **License / terms:** native Draugr code (Apache-2.0). [OWASP Secure Headers
  Project](https://owasp.org/www-project-secure-headers/) is a **reference only** — no code or
  data is bundled.

## What it does

Performs a `GET` on each host (following redirects, so it evaluates what a client actually
receives) and emits one SARIF result per missing or misconfigured security header. The
checklist is **tuned by the host's `type`** so browser-only headers aren't flagged on APIs:

| Group | Applies to | Checks |
|-------|-----------|--------|
| Universal | all | `Strict-Transport-Security` (HTTPS), `X-Content-Type-Options: nosniff`, `Server` / `X-Powered-By` disclosure |
| Browser | `type: browser` (default) | `Content-Security-Policy`, `X-Frame-Options` (or CSP `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy` |
| API | `type: api` | wildcard CORS (`Access-Control-Allow-Origin: *`, escalated with `Allow-Credentials: true`), missing `Cache-Control` |

Severities: missing hardening headers → `warning`; softer recommendations and
information-disclosure → `note`; wildcard CORS with credentials → `error`. See the
[HTTP security headers glossary entry](../../docs/glossary.md#http-security-headers).

## Links

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

## Notes

- Being native, it needs **no external tool** — `doctor` requires nothing for the `headers`
  control (only network reachability to the hosts).
- The control talks to a scanner by name, so a tool-backed alternative (e.g. OWASP ZAP passive
  rules, Mozilla HTTP Observatory) could serve the same control later without changing callers.
- Making the ruleset **org-configurable** (required headers, per-header severity, exemptions,
  expected values) is a follow-up that will consume the `draugr.config.yaml`
  `controllers.headers` layer ([#129](https://github.com/draugr-dev/draugr/issues/129)).
