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

## Install script (recommended)

One line, latest release, Linux and macOS:

```bash
curl -fsSL https://draugr.dev/install.sh | sh
```

It detects your OS and architecture, installs to `~/.local/bin`, and tells you if that isn't on
your `PATH`.

**It verifies before it installs, and says which checks ran.** The archive's SHA-256 is always
checked against the release's `checksums.txt`. If [cosign](https://docs.sigstore.dev/cosign/) is
on your `PATH`, it also verifies that `checksums.txt` was signed by Draugr's release workflow —
which is the check that carries weight, because a host able to serve you a bad archive could
serve a matching checksums file too. Nothing is installed if a check fails.

Piping a script into a shell means trusting the host that served it. If you'd rather not, the
script is [readable in the repo](https://github.com/draugr-dev/draugr/blob/main/install.sh) and
the [manual steps](#from-a-release-by-hand) below do the same work.

Three knobs, all optional. **They go on `sh`, not on `curl`** — in a pipeline each side gets
its own environment, so `DRAUGR_INSTALL_DIR=~/bin curl … | sh` sets the variable on the download
and the script never sees it:

```bash
curl -fsSL https://draugr.dev/install.sh | DRAUGR_INSTALL_DIR=~/bin sh
```

| Variable | Effect |
| --- | --- |
| `DRAUGR_VERSION` | Pin a release (`vX.Y.Z`) instead of tracking the latest |
| `DRAUGR_INSTALL_DIR` | Install somewhere other than `~/.local/bin` |
| `DRAUGR_REQUIRE_SIGNATURE` | Set to `1` to refuse to install unless the signature verifies |

Pick a version to pin from the [releases page](https://github.com/draugr-dev/draugr/releases).
In CI, pin the version **and** require the signature — a build runner shouldn't install anything
it can't prove the origin of:

```bash
curl -fsSL https://draugr.dev/install.sh \
  | DRAUGR_VERSION=vX.Y.Z DRAUGR_REQUIRE_SIGNATURE=1 sh
```

Already have a draugr binary? Update it in place with `draugr self-update`.

## From a release, by hand

The same thing without the script. Grabs the **latest** release — no version to look up:

```bash
tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
  https://github.com/draugr-dev/draugr/releases/latest | sed 's#.*/tag/##')
curl -fsSL "https://github.com/draugr-dev/draugr/releases/download/${tag}/draugr_${tag#v}_linux_amd64.tar.gz" \
  | tar -xz draugr
sudo mv draugr /usr/local/bin/       # or anywhere on your PATH
draugr version
```

Swap `linux_amd64` for `darwin_arm64`, `darwin_amd64`, `linux_arm64`, or `windows_amd64`.

To **pin** a release, set `tag=vX.Y.Z` yourself (pick one from the
[releases page](https://github.com/draugr-dev/draugr/releases)) and drop the first command.

This path doesn't verify anything on its own — see
[verifying releases](../trust-and-operations/verifying-releases.md) for the checksum and
signature steps.

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
make build
./bin/draugr version
```

`make build` produces `./bin/draugr`. To install a verified release into `~/.local/bin` instead
of building, from the same checkout:

```bash
make install-latest
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
