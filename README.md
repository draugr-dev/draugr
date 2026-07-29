# Draugr

> Developer-first, descriptor-driven security and compliance qualification.

[![CI](https://github.com/draugr-dev/draugr/actions/workflows/ci.yml/badge.svg)](https://github.com/draugr-dev/draugr/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draugr-dev/draugr/badge)](https://scorecard.dev/viewer/?uri=github.com/draugr-dev/draugr)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13631/badge)](https://www.bestpractices.dev/projects/13631)
[![Latest release](https://img.shields.io/github/v/release/draugr-dev/draugr?sort=semver)](https://github.com/draugr-dev/draugr/releases)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)

**Describe your app. Draugr figures out the rest.**

You declare what you *know* about your software — where the repos are, what container
images it builds, what endpoints it exposes, what infrastructure it runs on — in a single
descriptor (`draugr.saga.yaml`). Draugr infers which checks apply, runs the right tool for
each, and produces pass/fail evidence you can trust. Swap scanners freely — use the tools
you already pay for, or Draugr's open-source defaults. Every finding is normalized to
**SARIF**.

Both questions asked before a release ships, from the same descriptor and the same gate:
the **security** one — SAST, SCA, secrets, IaC, DAST, TLS, headers — and the **compliance**
one, starting with a Software Bill of Materials of everything you actually ship.

This is the open-source core engine.

## See it in action

![Draugr scanning a repository with zero config](contrib/demo/scan.gif)

`draugr scan .` on the demo sandbox — no descriptor, just a prioritized verdict:

```text
Draugr — FAIL   (draugr-demo 0.0.0)

Priorities:  P1 21   P2 22   P3 13   P4 0

Controls:
  secrets  FAIL   1 high
  iac      FAIL   4 high  5 medium  12 low
  sast     FAIL   7 high  9 medium
  sca      FAIL   3 critical  6 high  8 medium  1 low

Fix first:
  Priority  Severity  Score  Rule            Control  Scanner  Location
  P1        critical  9.8    CVE-2019-20477  sca      Trivy    app/requirements.txt:4
            PyYAML: command execution through python/object/apply constructor in FullLoader
  P1        critical  9.8    CVE-2020-14343  sca      Trivy    app/requirements.txt:4
            PyYAML: incomplete fix for CVE-2020-1747
  P1        high      8.0    DS-0002         iac      Trivy    app/Dockerfile:1
            Image user should not be 'root'
  P1        high      8.0    KSV-0014        iac      Trivy    deploy/pod.yaml:8
            Root file system is not read-only
  …

… and 46 more finding(s). Use --format json for the full report, or -o <dir> for report.json + results.sarif.
```

On a terminal the verdict, priorities, and severities are color-coded (disable with `NO_COLOR`).
Findings are ranked by **priority (P1–P4)** = severity × the component's exposure & criticality;
**severity** (critical/high/medium/low) comes from the CVSS score when a scanner provides one,
else from the finding's level. The gate and `--format json`/`sarif` still use SARIF levels.

**[draugr-dev/draugr-demo](https://github.com/draugr-dev/draugr-demo)** is an intentionally
vulnerable sample app wired to Draugr. Every control lights up, the findings are prioritized
P1–P4, and results land in the repo's **Security → Code scanning** tab — a safe sandbox to see
exactly what Draugr delivers before pointing it at your own code. The example PRs there also show
the **new-vs-fixed PR diff** and the sticky comment.

## Status

🚧 **Early, and moving fast.** Working today:

- **Controls:** `images` (Trivy), `sca` (Trivy fs), `secrets` (Gitleaks), `sast` (Semgrep,
  plus opt-in gosec for Go), `iac` (Trivy config), `headers` (native HTTP-header analyzer),
  `dast` (Nuclei), `tls` (native TLS/certificate probe).
  See the [integrations catalog](docs/reference/catalog.md).
- **Pipeline:** end-to-end `scan` (plan → scan → judge → report), content-hash caching,
  tunable parallelism (`-j`), results normalized to SARIF.
- **Prioritization:** declare a component's `exposure` and `criticality` and Draugr ranks
  every finding P1–P4 (`--min-priority` to focus, `--fail-on-priority` to gate);
  optional KEV/EPSS enrichment for real-world exploitability.
- **Discovery ("the Ravens"):** `survey` for Kubernetes images and GitHub org repositories.
- **Zero-config & scaffolding:** `scan .` scans the current repo with no descriptor
  (sca/secrets/sast/iac); `init` scaffolds a stack-detected `draugr.saga.yaml` to customize.
- **Preflight & tooling:** `validate` (schema-check a Saga), `doctor` (which scanner tools are
  present/missing), `tools install` (fetch pinned, checksum- and cosign-verified scanners —
  and cosign itself — into `~/.draugr/bin`), and `self-update` (update draugr itself, verified).

More controls (SBOM, infrastructure, threat intelligence) are on the roadmap. See
[controls & scanners](docs/concepts/controls-and-scanners.md) for what maps to what.

## Quickstart

**Requirements:** the external scanners for the controls you use —
[Trivy](https://github.com/aquasecurity/trivy) (`images`, `sca`, `iac`),
[Gitleaks](https://github.com/gitleaks/gitleaks) (`secrets`),
[Semgrep](https://semgrep.dev) (`sast`); `git` for repo scans. Or run
`draugr tools install` to fetch pinned, verified copies. Go 1.26+ only to build from source.

**Install (recommended):**

```bash
curl -fsSL https://draugr.dev/install.sh | sh
```

Detects your OS and architecture and installs to `~/.local/bin` — no `sudo`. It **verifies before
it installs and says which checks ran**: the archive's SHA-256 against the release's
`checksums.txt` always, plus the cosign signature on `checksums.txt` when
[cosign](https://docs.sigstore.dev/cosign/) is on your `PATH`. Nothing is installed if a check
fails.

Piping a script into a shell means trusting the host that served it. The script is
[readable in the repo](install.sh), and
[install & verifying downloads](docs/getting-started/install.md) has the manual steps, the
`DRAUGR_*` knobs, and Homebrew. Once installed, update in place with **`draugr self-update`**.

**Or build from source:**

```bash
git clone https://github.com/draugr-dev/draugr.git
cd draugr && make build      # produces ./bin/draugr
./bin/draugr version
```

**Fastest path — zero config.** Point Draugr at a repo and go; no descriptor needed:

```bash
draugr scan .        # scans the current repo: sca, secrets, sast, iac
draugr init          # or scaffold a draugr.saga.yaml (stack-detected) to customize
```

For full control, write a Saga — any `*.saga.yaml` file (see [`examples/`](examples/draugr.saga.yaml)):

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

Scan it:

```bash
draugr scan draugr.saga.yaml            # console summary; exits non-zero on fail
draugr scan draugr.saga.yaml -o out/    # also writes out/report.json + out/results.sarif
draugr scan draugr.saga.yaml --fail-on warning
draugr scan draugr.saga.yaml --format markdown   # or html, junit, json, sarif
```

**Your editor already knows this file.** Draugr's
[JSON Schema](https://draugr.dev/schema/draugr.saga.schema.json) is registered with
[SchemaStore](https://www.schemastore.org/), which VS Code's YAML extension and JetBrains IDEs
consult by default — so any `*.saga.yaml` gets completion, hover docs and typo warnings on open,
with nothing to configure. For an editor that doesn't use the catalog, `draugr init` also writes:

```yaml
# yaml-language-server: $schema=https://draugr.dev/schema/draugr.saga.schema.json
```

`draugr schema -o .saga.schema.json` writes the copy embedded in your binary instead, if you'd
rather validate offline or pin to exactly the version you run. See
[editor support](docs/reference/saga-schema.md#editor-support-autocomplete-hover-docs-validation).

Compare two scans to see what a change introduced (and gate a PR on *new* findings only):

```bash
draugr diff base/results.sarif head/results.sarif                     # new / fixed / unchanged
draugr diff base/results.sarif head/results.sarif --fail-on-new-priority P1
```

Let discovery write the descriptor for you (the Ravens):

```bash
draugr survey --github-org my-org -o draugr.saga.yaml
draugr survey --k8s-images --k8s-namespace prod --merge -o draugr.saga.yaml
```

Full walkthrough: [`docs/getting-started/quickstart.md`](docs/getting-started/quickstart.md).

## Use in CI (GitHub Actions)

Add Draugr to a repository's CI and code scanning with the first-party action. It downloads a
cosign-verified Draugr release, runs the scan, and hands the merged SARIF to GitHub code
scanning — one clean **Draugr** tool in the Security tab:

```yaml
permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning

steps:
  - uses: actions/checkout@v4
  - id: draugr
    uses: draugr-dev/draugr@v0     # latest v0.x; pin @vX.Y.Z for reproducible CI (installs Draugr for you)
    with:
      saga: draugr.saga.yaml
      tools: true                       # provision the scanners the controls need
      fail-on: warning                  # optional gate (default: error)
  - if: always()                        # publish findings even when the gate fails
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.draugr.outputs.sarif }}
```

With `tools: true` the action provisions the scanners each control needs (Trivy, Gitleaks,
Semgrep). See the [GitHub Action guide](docs/guides/github-action.md) for the full workflow and
all inputs.

## Use from an AI coding assistant

Ask an assistant to check a change for security problems and it will — by running whatever
scanner it can find, over a scope it chose for itself, and reading the raw output. That answer
has no relationship to the one your pipeline will give.

`draugr mcp` serves Draugr over the [Model Context Protocol](https://modelcontextprotocol.io),
so the assistant reads your **committed** Saga instead:

```bash
claude mcp add draugr -- draugr mcp
```

It can list the controls that exist, hand back the descriptor schema *your build* enforces,
validate a Saga before you write it, and rank an existing report by priority. Every
`*.saga.yaml` nearby is exposed as a resource, so the assistant reads the real scope rather than
guessing at one.

**Scanning is off by default** — it clones repositories and runs external tools. Turn it on with
`--scan=ask` to approve each call, or `--scan=always` for a sandbox. See
[use Draugr from an AI coding assistant](docs/guides/ai-agents-mcp.md).

## Documentation

**[Full documentation index →](docs/README.md)** (grouped by task, with a "building blocks"
glossary of Saga / Norn / Skald / the Ravens).

- [Quickstart](docs/getting-started/quickstart.md) — install, first scan, first survey, CI usage
- [Concepts](docs/concepts/saga.md) — Saga, controllers, scanners, surveyors, the pipeline, verdicts
- [Pipeline stages](docs/contributing/pipeline.md) — each stage in depth, incl. how the Norn (gate) works
- [Glossary](docs/reference/glossary.md) — security categories explained (SCA, SAST, DAST, SBOM, …)
- [Integrations catalog](docs/reference/catalog.md) — every controller/scanner/surveyor, with per-component docs + licenses
- [Changelog](CHANGELOG.md) — user-facing release notes
- [CLI reference](docs/reference/cli.md) — every command and flag
- [AI coding assistants](docs/guides/ai-agents-mcp.md) — the MCP server, its tools, and the consent model
- [Findings in your editor](docs/guides/findings-in-your-editor.md) — SARIF as inline diagnostics
- [Saga schema](docs/reference/saga-schema.md) — the descriptor, field by field
- [Architecture](docs/contributing/architecture.md) · [Plugin API](docs/contributing/plugin-api.md) · [Naming](docs/contributing/naming.md)

## What Draugr doesn't promise

A passing verdict means the controls you configured found nothing they were looking for. It is
not a statement that your software is secure — it's silent about anything your descriptor doesn't
declare, controls you didn't enable, and whatever the underlying scanners miss. Licence findings
are information, not legal advice. Draugr is provided under Apache-2.0 **without warranty**.

The details, including whose terms the bundled scanners carry and your responsibility for
authorisation when scanning live endpoints:
[scope and disclaimer](docs/trust-and-operations/disclaimer.md).

## Security & supply chain

A security tool should hold itself to what it checks. Draugr does:

- **Standard output** — every finding is normalized to **SARIF 2.1.0** (OASIS), so results flow
  into GitHub / GitLab / Azure DevOps code scanning and any SARIF-aware tool.
- **Signed releases + provenance** — release archives' `checksums.txt` is **keyless-signed with
  cosign** (Sigstore) into a `checksums.txt.sigstore.json` bundle, and each release publishes
  **SLSA build-provenance** attestations (`gh attestation verify …`); verify before installing
  ([recipe](docs/trust-and-operations/verifying-releases.md)).
- **SBOMs** — a Syft **SBOM** is published for every release archive.
- **Verified tooling** — `draugr tools install` fetches scanners pinned by **SHA-256** and, where
  the upstream signs them, verifies the **cosign** signature too — and cosign itself is
  installable, so verification is self-sufficient.
- **We scan ourselves** — Draugr runs on its own repo every PR (dogfood self-scan), and we track
  our supply-chain posture with the **[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/draugr-dev/draugr)**
  (badge above).
- **Report a vulnerability** — see [SECURITY.md](SECURITY.md).

## Development

Requires Go 1.26+.

```bash
make build   # build ./bin/draugr
make gate    # full local gate: fmt, vet, golangci-lint, race tests + coverage, govulncheck
make test    # run tests
```

### Observability

Draugr uses [Cobra](https://github.com/spf13/cobra) for the CLI, `log/slog` for
logging (human-readable and colorized by default; `--log-format json` for structured logs in
CI/observability pipelines), and [OpenTelemetry](https://opentelemetry.io)
for traces and metrics. Telemetry is opt-in via the standard `OTEL_*` environment variables
(e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`) — a no-op with zero overhead when unset. Logs and spans
never carry secrets.

## License

Draugr is licensed under the [Apache License 2.0](LICENSE).
