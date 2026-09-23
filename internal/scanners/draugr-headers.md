---
title: "draugr-headers"
description: "Evaluates a response's security headers against OWASP guidance, tuned by host type. Native, no external tool."
section: Scanners
order: 10
---

# Scanner: `draugr-headers` (HTTP security headers)

- **Control:** [`headers`](../controllers/headers.md)
- **Tool:** **native**, no external tool. A Go HTTP client fetches each host and evaluates
  its response headers against the OWASP Secure Headers guidance.
- **Status:** ✅ implemented
- **Target:** a running endpoint (`HostTarget`), a component's `hosts:`
- **License / terms:** native Draugr code (Apache-2.0). [OWASP Secure Headers
  Project](https://owasp.org/www-project-secure-headers/) is a **reference only**, no code or
  data is bundled.

## What it does

Performs a `GET` on each host (following redirects, so it evaluates what a client actually
receives) and emits one SARIF result per missing or misconfigured security header. A browser host
is asked for HTML the way a browser asks, and the page it returns is read too, up to 2 MiB, so the
policy can be [checked against the page](#checking-the-policy-against-the-page). The
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

A CSP can be present and stop almost nothing, `default-src *; script-src 'unsafe-inline'
'unsafe-eval'` satisfies a presence check while permitting exactly what a CSP exists to prevent.
So when the header is there, its **content** is judged too.

| Rule | Level | What it means |
|------|-------|---------------|
| `csp-unsafe-inline` | error | an injected `<script>` or event handler runs |
| `csp-unsafe-eval` | error | `eval()` and string-to-code are allowed |
| `csp-script-src-broad` | error | `*`, `https:`, `data:` or `blob:`. The payload can be hosted anywhere |
| `csp-script-src-missing` | error | no `script-src` and no `default-src`: script is ungoverned |
| `csp-object-src-broad` | warning | `<object>`/`<embed>` unrestricted. A route `script-src` does not cover |
| `csp-base-uri-missing` | warning | an injected `<base>` can repoint every relative script URL |
| `csp-object-src-not-none` | note | objects restricted but not disabled |
| `csp-default-src-missing` | note | resource types the policy does not name are unrestricted |
| `csp-unsafe-inline-legacy-fallback` | note | `'unsafe-inline'` present but inert |
| `csp-no-reporting` | note | no `report-uri`/`report-to`, so violations are invisible |

**Two CSP3 rules decide whether a weakness is real**, and a checker that ignores them produces
findings against the policies people were right to write:

- a **nonce or hash** in `script-src` makes `'unsafe-inline'` inert, browsers ignore it, and it
  is there for ones too old to understand the rest;
- **`'strict-dynamic'`** makes host and scheme sources inert, so a policy carrying `https:`
  alongside it is being compatible rather than permissive.

Both are reported as notes saying the value is doing nothing, rather than as flaws.

`base-uri` and `frame-ancestors` **do not** inherit from `default-src`. That is the subtlety that
most often leaves a policy weaker than its author believes, so a missing `base-uri` is reported
even when `default-src` is tight.

### Checking the policy against the page

A policy is written for a page, and a strict one can refuse part of the page it protects. An inline
event handler under a `script-src` with no `'unsafe-inline'`, or a script from a CDN the list does
not name, is refused by the browser, and the site's owner sees no error. The page check reads
the HTML a browser host returns and applies the policy to what it finds.

| Rule | Level | What the policy refuses |
|------|-------|-------------------------|
| `csp-blocks-inline-script` | note | inline `<script>` blocks with no nonce or hash the policy lists |
| `csp-blocks-inline-handler` | note | `on*=` attributes and `javascript:` links |
| `csp-blocks-inline-style` | note | `<style>` blocks and `style=` attributes |
| `csp-blocks-script-origin` | note | `<script src>`, and preloads of script |
| `csp-blocks-stylesheet-origin` | note | `<link rel=stylesheet>`, and preloads of style |
| `csp-blocks-image-origin` | note | `<img src>`, `srcset` candidates, and preloads of images |
| `csp-blocks-font-origin` | note | preloaded fonts |

Each origin rule is one finding per kind of resource, naming every origin refused and the directive
to add it to. That directive is the one governing the resource, so a policy with only `default-src`
is told to edit `default-src`.

These are notes because a policy refusing its own page is a fault in the page or in the policy, and
neither exposes anybody. They never fail a security gate.

A policy sent as `Content-Security-Policy-Report-Only` is checked when no enforced policy is present.
Nothing is refused yet, so each message says what enforcing the policy would refuse.

Where `csp-unsafe-inline` is reported, the page supplies its evidence. The message lists the inline
scripts and handlers that depend on `'unsafe-inline'`, or states that the page has none, in which
case removing `'unsafe-inline'` changes nothing the page runs.

Matching follows CSP3, including the rules a good policy relies on: a nonce or hash makes
`'unsafe-inline'` inert, `'strict-dynamic'` admits a markup script only by nonce or listed integrity
hash, an attribute matches a hash only with `'unsafe-hashes'`, `'self'` and `http:` allow the
upgrade to HTTPS, and `*` matches network schemes and not `data:` or `blob:`.

The check reads the markup the server sends. Content a script adds after the page loads, such as a
tag manager's payload or a request `connect-src` governs, is not in that markup and is not checked.

The heuristics follow the same public guidance as Google's
[CSP Evaluator](https://csp-evaluator.withgoogle.com/), implemented natively: it is a TypeScript
library rather than an exec-able binary, and Draugr executes tools rather than linking them.

## Links

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers

## Notes

- Being native, it needs **no external tool**, `doctor` requires nothing for the `headers`
  control (only network reachability to the hosts).
- The control talks to a scanner by name, so a tool-backed alternative (e.g. OWASP ZAP passive
  rules, Mozilla HTTP Observatory) could serve the same control later without changing callers.
- The ruleset is OWASP's and is not configurable per organization. A header you have decided not
  to set is accepted the way any other finding is, with [`config.exclude`](../../docs/reference/saga-schema.md#configexclude)
  and a reason.

## Data

Nothing. The checks are Draugr's own and travel in the binary, so a run behind an egress
allowlist needs nothing permitted for this scanner beyond reaching the host it is testing.
