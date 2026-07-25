# Scanner: `tls-probe` (native TLS configuration probe)

- **Control:** [`tls`](../controllers/tls.md)
- **Tool:** none — implemented natively in Go (`crypto/tls`, `crypto/x509`)
- **Target:** host (`hosts:` entries with an `https://` URL)
- **Status:** ✅ implemented

## What it does

Opens TLS handshakes against the endpoint and reports what it finds. No external tool, no
provisioning, and it finishes in seconds:

| Rule | Level | What it means |
|------|-------|---------------|
| `tls-cert-expired` | error (9.0) | The certificate has expired (or isn't yet valid) — clients will refuse to connect. |
| `tls-cert-expiring` | error (7.0) / warning (4.0) | Expires within 14 days / within 30 days. |
| `tls-cert-untrusted` | error (8.0) | Self-signed, or an incomplete chain to a trusted CA. |
| `tls-cert-hostname-mismatch` | error (8.0) | The certificate isn't valid for the hostname requested. |
| `tls-cert-invalid` | error (8.0) | Otherwise rejected during verification. |
| `tls-weak-cert-signature` | error (7.5) | Signed with a broken hash (MD2/MD5/SHA-1). |
| `tls-weak-key` | error (7.0) | RSA below 2048 bits, or an ECDSA curve below P-256. |
| `tls-modern-unsupported` | error (8.5) | The endpoint refuses TLS 1.2+ and only accepts deprecated versions. |
| `tls-deprecated-protocol` | error (7.0 / 6.5) | TLS 1.0 or TLS 1.1 is still accepted (deprecated by RFC 8996). |
| `tls-no-tls13` | note (2.0) | TLS 1.3 isn't offered — a nudge, not a failure. |

## License & terms

Native code — no third-party tool is executed or bundled, so the scanner carries only Draugr's
own license. It uses the Go standard library's `crypto/tls` and `crypto/x509`.

## Why native rather than testssl.sh

[testssl.sh](https://testssl.sh) is the reference tool for deep TLS auditing, and
[#56](https://github.com/draugr-dev/draugr/issues/56) originally proposed it. It's a poor fit as
the *default* engine:

- it's a **bash script plus a data directory**, not a single binary, so it doesn't fit Draugr's
  tool provisioning (which downloads and verifies one binary per tool);
- it needs `bash` and `openssl` on the runner;
- a thorough run takes **minutes per host**, which is heavy for a CI gate; and
- it's **GPL-2.0** — fine to exec, but it can never be bundled into a batteries-included image.

So the default is this native probe (fast, always present, zero setup), following the same
pattern as `semgrep` + opt-in `gosec` and `nuclei` + future opt-in ZAP. testssl.sh remains a
sensible **opt-in deeper engine** for the depth Go's stdlib can't reach.

## Limitations

Go's `crypto/tls` can't attempt protocols it doesn't implement, so this scanner **cannot** detect
SSLv2/SSLv3 or export/NULL cipher suites being enabled, and it doesn't test protocol-level
vulnerabilities (ROBOT, CRIME, Heartbleed, …) or enumerate the full cipher suite list. Those are
exactly what the opt-in testssl.sh engine would add.

## Integration notes

- The host must be reachable from wherever the scan runs (CI runners often can't see internal
  endpoints).
- `http://` hosts are rejected with an error — there's no TLS to assess.
- A URL without a port defaults to **443**; a bare hostname is treated as `https://`.
- Certificate verification is left **on**: a verification failure is classified into a finding
  rather than skipped, which is the point of the check.
