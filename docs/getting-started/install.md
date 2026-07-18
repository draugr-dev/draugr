---
title: Install
description: Install Draugr and the scanners its controls need, and verify the download.
section: Getting started
order: 10
---

# Install

Draugr is a single binary that orchestrates external scanners. Install Draugr itself, then the
scanners for the controls you use. Once you're set up, head to the
[quickstart](quickstart.md) for your first scan.

## Requirements

Draugr execs external scanners; install the ones for the controls you use:

- [Trivy](https://github.com/aquasecurity/trivy) — `images`, `sca`, and `iac` controls.
- [Gitleaks](https://github.com/gitleaks/gitleaks) — `secrets` control.
- [Semgrep](https://semgrep.dev) — `sast` control (default; opt-in [gosec](https://github.com/securego/gosec) for Go).
- `git` — needed for any repository scan (`sca`, `secrets`, `sast`).
- Go 1.26+ — only needed if you build from source.

The fastest way to get the scanners is to let Draugr fetch pinned, verified copies into
`~/.draugr/bin` (added to your `PATH` automatically):

```bash
draugr tools install     # trivy, gitleaks, gosec, cosign — pinned + verified
draugr tools list        # what's pinned, which controls it backs, and what's installed
```

Prefer your own install (Homebrew, package manager, an existing copy)? That works too — run
`draugr doctor` to confirm everything's found.

## From a release (recommended)

The repo is public, so plain `curl` works; the GitHub CLI (`gh`) works too. Omit the tag to
get the **latest** release, or pass a `vX.Y.Z` to pin:

```bash
gh release download --repo draugr-dev/draugr -p 'draugr_*_linux_amd64.tar.gz'
tar -xzf draugr_*_linux_amd64.tar.gz draugr
sudo mv draugr /usr/local/bin/       # or anywhere on your PATH
draugr version
```

Already have a draugr binary? Update it in place with `draugr self-update`.

Swap `linux_amd64` for `darwin_arm64`, `darwin_amd64`, `linux_arm64`, or `windows_amd64`.

**Verify the download (recommended).** Releases ship a cosign-signed `checksums.txt` and
per-archive SBOMs:

```bash
gh release download --repo draugr-dev/draugr \
  -p 'checksums.txt' -p 'checksums.txt.sigstore.json'
# verify the signature came from Draugr's release workflow (needs cosign)
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/draugr-dev/draugr/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
# verify your archive matches
sha256sum --ignore-missing -c checksums.txt
```

For the full verification story (cosign, SLSA provenance, SBOMs) see
[verifying releases](../trust-and-operations/verifying-releases.md).

## From a release — curl

Plain `curl` works (public repo). Pick a version from the
[releases page](https://github.com/draugr-dev/draugr/releases):

```bash
VERSION=v0.18.0
base="https://github.com/draugr-dev/draugr/releases/download/${VERSION}"
curl -fsSL -o draugr.tar.gz "${base}/draugr_${VERSION#v}_linux_amd64.tar.gz"
tar -xzf draugr.tar.gz draugr
sudo mv draugr /usr/local/bin/
draugr version
```

(`-f` makes `curl` fail loudly on an HTTP error instead of silently saving the error page.)

## From source

```bash
git clone https://github.com/draugr-dev/draugr.git
cd draugr
make build             # produces ./bin/draugr
./bin/draugr version
make install-latest    # or: download + SHA-256-verify + install the latest release into ~/.local/bin (needs curl)
```

## With Go

```bash
go install github.com/draugr-dev/draugr/cmd/draugr@latest
```
