---
title: Install
description: Install Draugr and the scanners its controls need, and verify the download.
section: Getting started
order: 10
---

# Install

Draugr is a single binary that orchestrates external scanners. **Install Draugr first** (below),
then let it fetch the scanners its controls need — see [Scanners](#scanners--the-tools-draugr-runs).
Once you're set up, head to the [quickstart](quickstart.md) for your first scan.

## From a release (recommended)

`curl` is everywhere, so this is the shortest path from nothing to a working `draugr`. It grabs
the **latest** release — no version to look up or keep updated:

```bash
tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
  https://github.com/draugr-dev/draugr/releases/latest | sed 's#.*/tag/##')
curl -fsSL "https://github.com/draugr-dev/draugr/releases/download/${tag}/draugr_${tag#v}_linux_amd64.tar.gz" \
  | tar -xz draugr
sudo mv draugr /usr/local/bin/       # or anywhere on your PATH
draugr version
```

Swap `linux_amd64` for `darwin_arm64`, `darwin_amd64`, `linux_arm64`, or `windows_amd64`.

To **pin** a release instead of tracking the latest, set `tag=vX.Y.Z` yourself (pick one from the
[releases page](https://github.com/draugr-dev/draugr/releases)) and drop the first command.

Already have a draugr binary? Update it in place with `draugr self-update`.

## From a release — GitHub CLI

If you already have [`gh`](https://cli.github.com), it handles the download and the platform
suffix for you. Omit the tag to get the latest release, or pass a `vX.Y.Z` to pin:

```bash
gh release download --repo draugr-dev/draugr -p 'draugr_*_linux_amd64.tar.gz'
tar -xzf draugr_*_linux_amd64.tar.gz draugr
sudo mv draugr /usr/local/bin/
draugr version
```

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

## From source

Requires Go 1.26+.

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

## Scanners — the tools Draugr runs

With Draugr installed, add the scanners for the controls you use. The fastest way is to let
Draugr fetch pinned, verified copies into `~/.draugr/bin` (added to your `PATH` automatically):

```bash
draugr tools install     # trivy, gitleaks, gosec, cosign — pinned + verified
draugr tools list        # what's pinned, which controls it backs, and what's installed
```

Prefer your own install (Homebrew, package manager, an existing copy)? That works too — then run
`draugr doctor` to confirm everything's found:

- [Trivy](https://github.com/aquasecurity/trivy) — `images`, `sca`, and `iac` controls.
- [Gitleaks](https://github.com/gitleaks/gitleaks) — `secrets` control.
- [Semgrep](https://semgrep.dev) — `sast` control (default; opt-in [gosec](https://github.com/securego/gosec) for Go).
- `git` — needed for any repository scan (`sca`, `secrets`, `sast`).
