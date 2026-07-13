# Quickstart

This guide takes you from zero to a security verdict, then shows how discovery can write
the descriptor for you.

**Contents:** [Install](#1-install) · [Describe your app](#2-describe-your-app) ·
[Scan](#3-scan) · [Focus: what to fix first](#focus-what-to-fix-first) ·
[Discovery — the Ravens](#4-let-discovery-write-the-descriptor-the-ravens) ·
[Run it in CI](#5-run-it-in-ci) · [Troubleshooting](#troubleshooting)

## 1. Install

**Requirements** — Draugr execs external scanners; install the ones for the controls you use:
- [Trivy](https://github.com/aquasecurity/trivy) — `images` and `sca` controls.
- [Gitleaks](https://github.com/gitleaks/gitleaks) — `secrets` control.
- `git` — needed for any repository scan (`sca`, `secrets`).
- Go 1.26+ — only needed if you build from source.

> **Pre-launch note.** While `draugr-dev/draugr` is **private**, plain `curl` to a release
> asset returns `404` — private downloads require authentication. Use the **GitHub CLI**
> method below until the repo is public.

### From a release (recommended) — GitHub CLI

Works while the repo is private (`gh` is authenticated). Omit the tag to get the **latest**
release, or pass a `vX.Y.Z` to pin:

```bash
gh release download --repo draugr-dev/draugr -p 'draugr_*_linux_amd64.tar.gz'
tar -xzf draugr_*_linux_amd64.tar.gz draugr
sudo mv draugr /usr/local/bin/       # or anywhere on your PATH
draugr version
```

Swap `linux_amd64` for `darwin_arm64`, `darwin_amd64`, `linux_arm64`, or `windows_amd64`.

**Verify the download (recommended).** Releases ship a cosign-signed `checksums.txt` and
per-archive SBOMs:

```bash
gh release download --repo draugr-dev/draugr \
  -p 'checksums.txt' -p 'checksums.txt.sig' -p 'checksums.txt.pem'
# verify the signature came from Draugr's release workflow (needs cosign)
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/draugr-dev/draugr/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt
# verify your archive matches
sha256sum --ignore-missing -c checksums.txt
```

### From a release — curl (once public)

After launch, plain `curl` works. Pick a version from the
[releases page](https://github.com/draugr-dev/draugr/releases):

```bash
VERSION=v0.2.0
base="https://github.com/draugr-dev/draugr/releases/download/${VERSION}"
curl -fsSL -o draugr.tar.gz "${base}/draugr_${VERSION#v}_linux_amd64.tar.gz"
tar -xzf draugr.tar.gz draugr
sudo mv draugr /usr/local/bin/
draugr version
```

(`-f` makes `curl` fail loudly on an HTTP error instead of silently saving the error page.)

### From source

```bash
git clone https://github.com/draugr-dev/draugr.git
cd draugr
make build             # produces ./bin/draugr
./bin/draugr version
make install-latest    # or: download & install the latest release into ~/.local/bin (needs gh)
```

### With Go

```bash
go install github.com/draugr-dev/draugr/cmd/draugr@v0.2.0   # once the module is public
```

## 2. Describe your app

Create `draugr.saga.yaml`. The **Saga** is the one artifact that maps your software to the
controls that must pass. A minimal, runnable example:

```yaml
release:
  name: my-app
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
```

A control only runs when it is **enabled** (globally under `config.controllers`, or on a
component). See the [Saga reference](saga-reference.md) for every field.

## 3. Scan

```bash
draugr scan draugr.saga.yaml
```

Draugr plans the work (controllers × components), runs the scanners concurrently, merges
and deduplicates results as SARIF, judges them against a policy, and prints a JSON verdict:

```json
{
  "release": { "name": "my-app", "version": "1.0" },
  "verdict": "pass",
  "controls": [
    { "name": "images", "verdict": "pass", "highest": "none",
      "threshold": "error", "errors": 0, "warnings": 0, "notes": 0, "total": 0 }
  ],
  "stats": { "jobs": 1, "scans": 1, "cacheHits": 0 }
}
```

The `verdict` and counts depend on what the scanners find — a real image like `alpine:3.19`
will typically report several vulnerabilities, so you'll see `fail` unless you use a minimal
image or raise `--fail-on`. The process **exits non-zero when the verdict is `fail`**, so it
gates a pipeline directly.

Useful flags:

```bash
draugr scan draugr.saga.yaml -o out/            # write out/report.json + out/results.sarif
draugr scan draugr.saga.yaml --fail-on warning  # stricter gate (default: error)
draugr scan draugr.saga.yaml --cache-dir .draugr-cache   # skip re-scanning unchanged targets
draugr scan draugr.saga.yaml --min-priority P2  # list only the findings worth acting on now
draugr scan draugr.saga.yaml --fail-on-priority P1  # also fail the gate on any P1 finding
```

## Focus: what to fix first

**Classify your components.** The fastest way to set up prioritization is the guided wizard —
it asks a few questions per component and writes `exposure` and `criticality` back into your
Saga (comments and formatting preserved):

```bash
draugr classify draugr.saga.yaml
```

```
Component: web
  Exposure — how reachable is it?
  Reachable from the public internet? [y/N] y
  Does it require authentication? [y/N] n
  Criticality — impact if it fails or is compromised?
    1) outage or data loss   2) degraded, no outage   3) limited impact
  Choose [1-3]: 1
  → web: exposure=public, criticality=critical
```

(Prefer to hand-edit? The fields are in the [Saga reference](saga-reference.md). And
`draugr survey` on a k8s namespace already *proposes* `exposure` for you.)

Once components declare `exposure` and `criticality`, Draugr ranks every finding into a
priority band — combining the finding's severity with how exposed and how business-critical
its component is. The report always includes a `priorities` count (P1–P4); `--min-priority`
adds a ranked `findings` list of just those at or above the band, so you can act on the short
list instead of the whole wall:

```json
{
  "priorities": { "p1": 2, "p2": 5, "p3": 3, "p4": 0 },
  "findings": [
    { "priority": "P1", "level": "error", "score": 9.1, "control": "sca",
      "ruleId": "CVE-2025-0001", "message": "…", "location": "go.mod" }
  ]
}
```

P1 = act now · P2 = this cycle · P3 = backlog · P4 = track. A component left unclassified is
treated as high-risk so nothing slips.

**Gate on priority.** `--fail-on-priority P1` fails the build when any finding reaches that
band — component-aware gating without a per-component config, since priority already folds in
exposure and criticality. It composes with the level gate (`--fail-on`): the run fails if
*either* trips. Each control also reports its `highestPriority` as evidence.

## 4. Let discovery write the descriptor (the Ravens)

Instead of hand-writing components, point a surveyor at your environment:

```bash
# Repositories in a GitHub org (token via --? no: GITHUB_TOKEN env or scope config)
GITHUB_TOKEN=*** draugr survey --github-org my-org -o draugr.saga.yaml

# Unique container images running in a Kubernetes namespace (uses your kubeconfig)
draugr survey --k8s-images --k8s-namespace prod --merge -o draugr.saga.yaml
```

`--merge` blends discovered components into an existing Saga instead of overwriting it.

## 5. Run it in CI

`scan`'s exit code is the gate. A minimal GitHub Actions step:

```yaml
- name: Draugr scan
  run: |
    draugr scan draugr.saga.yaml -o draugr-out
- name: Upload SARIF to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: draugr-out/results.sarif
```

## Troubleshooting

- **No findings / control didn't run** — ensure the control is `enabled` and the component
  has the relevant resources (e.g. `images` for the images control).
- **`trivy: executable file not found`** — install Trivy and ensure it's on `PATH`.
- **Verbose output** — add `--log-level debug` (optionally `--log-format text`).
