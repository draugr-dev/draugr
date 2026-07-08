# Quickstart

This guide takes you from zero to a security verdict, then shows how discovery can write
the descriptor for you.

## 1. Install

**Requirements**
- [Trivy](https://github.com/aquasecurity/trivy) on your `PATH` — used by the `images` control.
- Go 1.26+ — only needed to build from source.

**Build from source**

```bash
git clone https://github.com/draugr-dev/draugr.git
cd draugr
make build          # produces ./bin/draugr
./bin/draugr version
```

(Signed release binaries with SBOMs are produced by the release pipeline once a version is
tagged.)

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
```

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
