# Scanner: `draugr-headers` (HTTP security headers)

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
[HTTP security headers glossary entry](../../docs/reference/glossary.md#http-security-headers).

### Grading the Content-Security-Policy

A CSP can be present and stop almost nothing — `default-src *; script-src 'unsafe-inline'
'unsafe-eval'` satisfies a presence check while permitting exactly what a CSP exists to prevent.
So when the header is there, its **content** is judged too.

| Rule | Level | What it means |
|------|-------|---------------|
| `csp-unsafe-inline` | error | an injected `<script>` or event handler runs |
| `csp-unsafe-eval` | error | `eval()` and string-to-code are allowed |
| `csp-script-src-broad` | error | `*`, `https:`, `data:` or `blob:` — the payload can be hosted anywhere |
| `csp-script-src-missing` | error | no `script-src` and no `default-src`: script is ungoverned |
| `csp-object-src-broad` | warning | `<object>`/`<embed>` unrestricted — a route `script-src` does not cover |
| `csp-base-uri-missing` | warning | an injected `<base>` can repoint every relative script URL |
| `csp-object-src-not-none` | note | objects restricted but not disabled |
| `csp-default-src-missing` | note | resource types the policy does not name are unrestricted |
| `csp-unsafe-inline-legacy-fallback` | note | `'unsafe-inline'` present but inert |
| `csp-no-reporting` | note | no `report-uri`/`report-to`, so violations are invisible |

**Two CSP3 rules decide whether a weakness is real**, and a checker that ignores them produces
findings against the policies people were right to write:

- a **nonce or hash** in `script-src` makes `'unsafe-inline'` inert — browsers ignore it, and it
  is there for ones too old to understand the rest;
- **`'strict-dynamic'`** makes host and scheme sources inert, so a policy carrying `https:`
  alongside it is being compatible rather than permissive.

Both are reported as notes saying the value is doing nothing, rather than as flaws.

`base-uri` and `frame-ancestors` **do not** inherit from `default-src`. That is the subtlety that
most often leaves a policy weaker than its author believes, so a missing `base-uri` is reported
even when `default-src` is tight.

The heuristics follow the same public guidance as Google's
[CSP Evaluator](https://csp-evaluator.withgoogle.com/), implemented natively: it is a TypeScript
library rather than an exec-able binary, and Draugr executes tools rather than linking them.

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
