---
title: Verifying releases
description: Verify Draugr's signed releases with cosign, SLSA provenance, and SBOMs.
section: Trust & operations
order: 10
---

# Verifying releases

A security tool should hold itself to what it checks. Every Draugr release is signed and
attested, so you can prove an archive came from Draugr's release workflow before you install
it.

## What ships with a release

- **Signed checksums** — the release archives' `checksums.txt` is **keyless-signed with
  cosign** (Sigstore) into a `checksums.txt.sigstore.json` bundle.
- **SLSA build provenance** — each release publishes SLSA build-provenance attestations you can
  check with `gh attestation verify`.
- **SBOMs** — a Syft **SBOM** is published for every release archive.

## Verify a download

Fetch the archive alongside the signed checksums, verify the signature came from Draugr's
release workflow, then confirm your archive matches (needs [cosign](https://docs.sigstore.dev/)
— `draugr tools install cosign` installs it):

```bash
gh release download --repo draugr-dev/draugr \
  -p 'draugr_*_linux_amd64.tar.gz' \
  -p 'checksums.txt' -p 'checksums.txt.sigstore.json'

# verify the signature came from Draugr's release workflow
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/draugr-dev/draugr/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# verify your archive matches the (signed) checksums
sha256sum --ignore-missing -c checksums.txt
```

The GitHub Action verifies this for you on every run (`verify: true`, the default); the archive
checksum is always verified regardless.

## Verify the tools Draugr installs

`draugr tools install` fetches scanners pinned by **SHA-256** (the mandatory integrity floor)
and, where the upstream signs its checksums (e.g. Trivy), also verifies the **cosign**
signature — checking the signing certificate identity and OIDC issuer. Without `cosign`, or for
tools the upstream doesn't sign (e.g. gitleaks), it degrades to SHA-256-only and says so. See
[updating](updating.md) for the install and self-update commands.

## We scan ourselves

On every change, CI runs the latest released Draugr against this repository (see
[`.draugr/self.saga.yaml`](../../.draugr/self.saga.yaml)) for `sca`, `secrets`, `sast`, and
`iac`, publishing the results to the repo's **code scanning**. We track our supply-chain
posture with the **OpenSSF Scorecard** and hold an **OpenSSF Best Practices** badge.

To **report a vulnerability**, see [SECURITY.md](../../SECURITY.md) — please don't open a public
issue for a security bug.
