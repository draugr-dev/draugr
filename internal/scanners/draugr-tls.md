---
title: "draugr-tls"
description: "Probes an endpoint's certificate, protocol versions and key strength. Native, seconds per host, nothing to install."
section: Scanners
order: 30
---

# Scanner: `draugr-tls` (native TLS configuration probe)

- **Control:** [`tls`](../controllers/tls.md)
- **Tool:** none, implemented natively in Go (`crypto/tls`, `crypto/x509`)
- **Target:** host (`hosts:` entries with an `https://` URL)
- **Effects:** `network` (opens TLS connections to the endpoint, one handshake per protocol version tested, plus one offering insecure cipher suites if the endpoint refuses the current ones)
- **Status:** ✅ implemented

## What it does

Opens TLS handshakes against the endpoint and reports what it finds. No external tool, no
provisioning, and it finishes in seconds.

The handshakes do not verify the certificate, so a certificate that fails does not stop the
protocol versions being tested. The first chain the endpoint sends is judged on its own: verified
against the machine's trusted roots, matched to the host name, and read for each certificate's
signature, key and order, whether or not it verifies. A SHA-1 intermediate is reported as a weak
signature on that intermediate rather than only as an untrusted chain, and a certificate whose key
Go refuses to use is reported as a weak key rather than as a failed connection.

| Rule | Level | What it means |
|------|-------|---------------|
| `tls-cert-expired` | error (9.0) | The certificate has expired (or isn't yet valid). Clients will refuse to connect. |
| `tls-cert-expiring` | error (7.0) / warning (4.0) | Expires within 14 days / within 30 days. |
| `tls-cert-untrusted` | error (8.0) | Self-signed, or an incomplete chain to a trusted CA. |
| `tls-cert-hostname-mismatch` | error (8.0) | The certificate isn't valid for the hostname requested. Reported beside `tls-cert-untrusted` when both hold, since each has its own fix. |
| `tls-cert-no-san` | error (7.0) | The certificate names its host only in the Common Name, with no Subject Alternative Name. Current clients ignore the Common Name and reject it. |
| `tls-cert-chain-order` | warning (4.0) | The chain is sent out of order: a certificate is not issued by the one after it. Browsers reorder it; other clients may fail. |
| `tls-cert-invalid` | error (8.0) | Otherwise rejected during verification. |
| `tls-weak-cert-signature` | error (7.5 / 7.0) | The leaf (7.5) or an intermediate (7.0) is signed with a broken hash (MD2/MD5/SHA-1). A root's signature on itself is not checked. |
| `tls-weak-key` | error (7.0) | RSA below 2048 bits, or an ECDSA curve below P-256. |
| `tls-modern-unsupported` | error (8.5) | The endpoint refuses a TLS 1.2+ handshake from a current client and accepts a deprecated version. |
| `tls-legacy-cipher-only` | error (8.0 / 7.5 / 7.0 / 6.5) | The endpoint accepts none of the cipher suites a current client offers. The message names the suite it chose from the older ones offered and the problem with it: RC4, 3DES, CBC with a SHA-256 MAC, or RSA key exchange. |
| `tls-no-shared-cipher` | error (7.0) | The endpoint refuses every cipher suite Draugr can offer, insecure ones included. It likely accepts only others, such as finite-field Diffie-Hellman (DHE), NULL or export suites, or only SSL 3.0. |
| `tls-deprecated-protocol` | error (7.0 / 6.5) | TLS 1.0 or TLS 1.1 is still accepted (deprecated by RFC 8996). |
| `tls-no-tls13` | note (2.0) | TLS 1.3 isn't offered, a nudge, not a failure. |

## Configuration

Certificate-expiry windows are tunable under `config.controls.tls.draugrTls`:

| Option | Default | Meaning |
|--------|---------|---------|
| `expiryErrorDays` | `14` | Report an **error** when the certificate expires within this many days. |
| `expiryWarnDays` | `30` | Report a **warning** when it expires within this many days. |

```yaml
config:
  controls:
    tls:
      enabled: true
      draugrTls:
        expiryWarnDays: 10     # endpoint renews automatically, only shout if renewal failed
        expiryErrorDays: 5
```

Endpoints with **automated renewal** (Let's Encrypt, Cloudflare) legitimately sit inside a wide
default window during normal rotation, which would fail a `--fail-on warning` gate for a
non-problem. Tighten the windows so the gate fires only when renewal has actually failed.
Options are schema-validated, so a mistyped key or a non-integer value is rejected before the
scan runs.

## License & terms

Native code. No third-party tool is executed or bundled, so the scanner carries only Draugr's own
license. It uses the Go standard library's `crypto/tls` and `crypto/x509`.

## Why native rather than testssl.sh

[testssl.sh](https://testssl.sh) is the reference tool for deep TLS auditing, and a poor fit as
the *default* engine:

- it's a **bash script plus a data directory**, not a single binary, so it doesn't fit Draugr's
  tool provisioning (which downloads and verifies one binary per tool);
- it needs `bash` and `openssl` on the runner;
- a thorough run takes **minutes per host**, which is heavy for a CI gate; and
- it's **GPL-2.0**, fine to exec, but it can never be bundled into a batteries-included image.

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
- `http://` hosts are rejected with an error, there's no TLS to assess.
- A URL without a port defaults to **443**; a bare hostname is treated as `https://`.
- Certificate verification is left **on**: a verification failure is classified into a finding
  rather than skipped, which is the point of the check.

## Data

Nothing. The checks are Draugr's own and travel in the binary. The scan reaches the endpoint
under test, which is the point of the control rather than a fetch.
