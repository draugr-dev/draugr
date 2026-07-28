---
title: Saga schema
description: Every field of draugr.saga.yaml — release, config, components, and references.
section: Reference
order: 20
---

# Saga reference

The **Saga** is Draugr's descriptor — a declarative account of an application's security surface
and the controls that must pass.

**Any `*.saga.yaml` file is a Saga.** `draugr init` writes `draugr.saga.yaml` by default, but the
name is yours: `draugr scan azure.saga.yaml`, `payments.saga.yaml`, a bare `.saga.yaml` — Draugr
loads whatever path you hand it, so a repo can hold several.

## Editor support (autocomplete, hover docs, validation)

Draugr publishes a [JSON Schema](https://draugr.dev/schema/draugr.saga.schema.json) for the Saga.
With it, your editor completes control and field names, shows the documentation for each one on
hover, offers the valid values for `exposure`, `criticality` and report formats, and flags typos
as you type instead of at scan time.

**In most editors, nothing to configure.** The Saga is registered with
[SchemaStore](https://www.schemastore.org/), the catalog that VS Code's
[YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) and
JetBrains IDEs consult by default. Any file named `*.saga.yaml`, `*.saga.yml` or `.saga.yaml` is
recognised the moment you open it — no modeline, no setting, nothing committed to the repo.

Editors cache that catalog and some ship a snapshot inside the extension, so a copy older than the
registration won't have it yet. Both routes below work regardless, and keep working if you'd
rather not depend on a third-party catalog at all.

**A modeline in the file.** `draugr init` writes one at the top:

```yaml
# yaml-language-server: $schema=https://draugr.dev/schema/draugr.saga.schema.json
```

Any editor running the YAML language server picks it up on open, catalog or not — VS Code,
JetBrains, Neovim. Paste that line at the top of an existing Saga to get the same.

**Or map it once, for every Saga in the project.** No modeline in the files. This is also the
route for filenames the catalog doesn't match, and for pinning a version across a repo.

**VS Code** — commit `.vscode/settings.json` so the whole team gets it automatically (requires the
[YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml)):

```json
{
  "yaml.schemas": {
    "https://draugr.dev/schema/draugr.saga.schema.json": ["*.saga.yaml", "*.saga.yml"]
  }
}
```

**JetBrains** (IntelliJ, GoLand, PyCharm) — *Settings → Languages & Frameworks → Schemas and DTDs
→ JSON Schema Mappings*. Add a mapping with the URL above and file-path pattern `*.saga.yaml`.

**Neovim** — `yamlls` may not have SchemaStore enabled depending on how you configure it, so
mapping it explicitly is the dependable route, via `nvim-lspconfig`:

```lua
require('lspconfig').yamlls.setup {
  settings = {
    yaml = {
      schemas = {
        ['https://draugr.dev/schema/draugr.saga.schema.json'] = '*.saga.{yaml,yml}',
      },
    },
  },
}
```

**Anything else** — any editor speaking the
[YAML language server](https://github.com/redhat-developer/yaml-language-server) supports both the
modeline and a schema mapping; point it at the same URL.

That covers *writing* the descriptor. For the scan's **findings** to appear inline on the lines
that caused them, see [findings in your editor](../guides/findings-in-your-editor.md).

### Matching the schema to your Draugr version

A schema newer than your binary will happily autocomplete fields it doesn't understand; an older
one will flag valid fields as errors. Three ways to control which you get, loosest to strictest:

| Reference | Behaviour | Use when |
|-----------|-----------|----------|
| `…/schema/draugr.saga.schema.json` | tracks the newest release | you keep Draugr current |
| `…/schema/v0.33.0/draugr.saga.schema.json` | that release, forever | you pin Draugr in CI |
| a local file from `draugr schema` | exactly your installed binary | offline, air-gapped, or strictest |

**`draugr init` pins by default** — it writes the URL for its own version, so a scaffolded Saga
is matched to the binary that created it. Change the line to the unversioned URL if you'd rather
track latest. Every release publishes its own immutable copy, so a pin keeps resolving after
newer versions ship.

**The strongest guarantee is the binary's own copy.** Draugr embeds the schema it enforces, so
this needs no network and cannot mismatch:

```bash
draugr schema -o .saga.schema.json
# then in your Saga:
# yaml-language-server: $schema=./.saga.schema.json
```

`draugr schema` with no `-o` prints to stdout, so you can diff two versions or pipe it anywhere.

## Top level

```yaml
release: { ... }              # required
config: { ... }               # optional — controllers, reports, and publishers
components: [ ... ]           # the app's parts
componentsMetaSources: [ ... ] # optional — load component defs from other repos (planned)
references: [ ... ]           # optional — links to manual/human controls
```

Any string value may reference an environment variable with `${{ VAR_NAME }}`; loading
fails fast if a referenced variable is unset.

## `release` (required)

| Field | Required | Description |
|-------|----------|-------------|
| `name` | — | Release/app name |
| `version` | ✅ | Release version |
| `stage` | — | Free-form stage label (e.g. `dev`) |

## `config.controllers`

A map of control name → free-form settings. A control runs only when **enabled**:

```yaml
config:
  controllers:
    images:
      enabled: true          # absent entry ⇒ disabled; entry without `enabled` ⇒ enabled
```

### Per-scanner config

A control can be served by more than one scanner, and each scanner is configured under its own
key in `controllers.<control>.<scanner>`. A scanner block holds an optional **`enabled`** flag
plus that scanner's options. Default scanners run unless turned off with `enabled: false`; a
non-default scanner runs only when it sets `enabled: true`. A component may override the project
config (component keys deep-merge over project keys). For `sast`:

```yaml
config:
  controllers:
    sast:
      enabled: true
      semgrep:
        config: p/owasp-top-ten   # ruleset: a registry ref or a path/URL (default: p/default)
      gosec:
        enabled: true             # opt-in scanner (Go-only) — off unless enabled here
```

Each scanner validates its options against a declared schema, so a mistyped key or wrong value
type is reported before the scan runs. Run `draugr controls` to see each control's scanners.

> Implemented today: **`images`** (Trivy), **`sca`** (Trivy fs), **`secrets`** (Gitleaks),
> **`sast`** (Semgrep; opt-in gosec), **`iac`** (Trivy config), **`headers`** (native
> HTTP-header checks), **`dast`** (Nuclei), and **`tls`** (native TLS/certificate probe).
> Other controls (`sbom`, `infrastructure`, `threats`) are on the roadmap. Run `draugr controls` for the current list and each control's
> scanners.

## `config.reports` and `config.publishers`

Declare which report **formats** a scan renders and **where** they're delivered. Reports are the
"what" (a [Reporter](../contributing/plugin-api.md#reporter)); publishers are the "where" (a Publisher). Every
rendered report is delivered to every publisher.

```yaml
config:
  reports:
    - format: sarif        # any scan --format: console, markdown, html, junit, json, sarif
    - format: markdown
    - format: html
    - format: template     # custom payload from a Go text/template
      templateFile: ./report.tmpl   # or inline `template: "..."` (set exactly one)
      filename: summary.txt         # optional; overrides the default output filename
  publishers:
    - kind: file           # write each report to a directory
      dir: ./out           # → ./out/results.sarif, ./out/report.md, ./out/report.html, ./out/summary.txt
```

The **`template`** format renders a [Go `text/template`](https://pkg.go.dev/text/template) against
a stable view of the scan — `.Release`, `.Verdict`, `.Pass`, `.Priorities.{P1..P4}`, `.Controls`,
and `.Findings` (each with `.Priority .Level .Score .Control .Tool .RuleID .Message .Location`).
Use it for a bespoke summary line, a Slack payload, or any custom text without writing code.

Reports are delivered regardless of the gate verdict, so you get evidence on a FAIL too. This is
independent of `scan --format` (stdout) and `scan -o` (which always writes `report.json` +
`results.sarif`) — use `config.publishers` when you want a declarative, multi-format,
multi-destination setup in the Saga itself.

Built-in publishers: **`file`** and **`github`** (uploads the `sarif` report to code scanning):

```yaml
config:
  reports:
    - format: sarif
  publishers:
    - kind: github         # repo/commit/ref default to the GitHub Actions env
      # repo: owner/name   # optional overrides ($GITHUB_REPOSITORY / $GITHUB_SHA / $GITHUB_REF)
      # ref: refs/heads/main
      # tokenEnv: GITHUB_TOKEN   # the token is read from this env var — never the Saga
```

The `github` publisher requires a `sarif` report in `config.reports`. It never stores a secret in
the descriptor — the token comes from an environment variable. Code scanning is free for public
repos; private repos need GitHub Advanced Security.

The **`github-pr-comment`** publisher posts the `markdown` report as a **sticky** pull-request
comment (updated in place on each push). It needs a `markdown` report in `config.reports`; `repo`
and the PR number default from the GitHub Actions environment; the token comes from `$GITHUB_TOKEN`
(or `tokenEnv`). It no-ops off a pull request. It's most useful with
[`draugr diff --publish`](cli.md#draugr-diff-basesarif-headsarif), which posts a PR **security
delta** (new / fixed findings) as that comment.

## SBOM generation

```yaml
config:
  sbom:
    enabled: true
    format: spdx-json      # defaults to spdx-json
```

Produces one [Software Bill of Materials](glossary.md#sbom--software-bill-of-materials) per
distinct repository and image in the Saga — an inventory of what each one contains. Requires
[Syft](https://github.com/anchore/syft) (`draugr tools install syft`).

**Choosing a format.** Both open specifications, each in both of its standard encodings — pick
whichever the thing consuming the document reads:

| `format` | Written as | Media type |
|----------|------------|------------|
| `spdx-json` (default) | `sbom-<component>-<target>.spdx.json` | `application/spdx+json` |
| `spdx-tag-value` | `sbom-<component>-<target>.spdx` | `text/spdx` |
| `cyclonedx-json` | `sbom-<component>-<target>.cdx.json` | `application/vnd.cyclonedx+json` |
| `cyclonedx-xml` | `sbom-<component>-<target>.cdx.xml` | `application/vnd.cyclonedx+xml` |

Syft can emit more — its own `syft-json`, GitHub's dependency-snapshot format, a bare PURL list
— but those are either vendor-specific or not an SBOM, so Draugr doesn't offer them. Every
document it produces is one a third party can read. An unsupported value is rejected when the
Saga loads, naming the four, rather than failing after the scan has run.

**It is not a control, and this is deliberate.** Every control checks something and returns a
verdict the gate acts on. An SBOM finds nothing, so it has no verdict to give; a control row
that always reads "pass" without having looked is exactly the meaningless green Draugr exists
to remove. So SBOMs are evidence: they never appear in the `Controls:` table and never affect
pass or fail. The console reports them on their own line:

```
Controls:
  secrets  FAIL   1 high

SBOM: 2 documents (spdx-json)
```

**Where the documents go.** `-o <dir>` writes them beside `report.json` and `results.sarif`,
and any configured publisher delivers them alongside your reports — including with no
`config.reports` at all, if the inventory is the only output you want. Filenames are
`sbom-<component>-<target>` plus the suffix for the format, with the target slugged so two
images in one component can't collide.

There is no `--format sbom`: a run produces one document per target, and a format that writes
several files has no meaning on stdout.

**If Syft is missing, the scan fails.** Generation errors are reported under `(sbom)` and make
the run incomplete, exactly as a missing scanner does — you asked for an inventory and didn't
get one, and silence would let you believe you had it. `--allow-scan-errors` accepts the
partial result if that's what you want; the error is still reported either way.

Deduplicated by target: several controls scan the same repository, and its inventory is one
document however many touched it. The same image referenced by two components is likewise one.

## `components`

Each component is one logical part of the app. All surface lists are optional; provide
what applies.

```yaml
components:
  - name: web                 # required, unique
    labels: { team: platform } # optional key/value metadata
    exposure: public          # optional — risk exposure
    criticality: critical     # optional — business criticality
    repositories:
      - url: https://github.com/acme/web.git   # required
        revision: main                          # optional
        paths: ["services/web/**"]              # optional
    images:
      - image: registry.example.com/acme/web:1.0  # required
        digest: sha256:…                          # optional — pin the immutable content digest
    hosts:
      - name: api
        url: https://api.example.com            # required
        type: api                               # browser | api (default browser); tunes header checks
    infrastructure:
      - kind: kubernetes                        # e.g. kubernetes
        ref: prod-cluster
    controllers:              # optional per-component overrides (same shape as config.controllers)
      images:
        enabled: true
```

**Control resolution:** a component-scoped control runs for a component when it is enabled
on the component, or (absent an override) enabled globally under `config.controllers`.

**Risk classification** (`exposure`, `criticality`) — optional, and the two axes of risk
prioritization: exposure is how reachable the component is (likelihood), criticality is the
business impact if it fails. Both are fixed ladders whose meaning an organization can
redefine (the levels stay stable). They feed finding prioritization as that ships; a
component may be left unclassified.

| `exposure` | meaning | | `criticality` | meaning |
|------------|---------|-|---------------|---------|
| `public` | internet-facing, no auth | | `critical` | failure causes outage / data loss |
| `authenticated` | internet-facing, behind auth | | `important` | degraded, no immediate outage |
| `internal` | reachable within the environment | | `supporting` | limited operational impact |
| `restricted` | namespace- / network-policy-scoped | | | |

## `componentsMetaSources` (planned)

Reference Saga fragments kept next to a component's source, to be cloned and merged:

```yaml
componentsMetaSources:
  - repoUrl: https://github.com/acme/web.git
    path: draugr.saga.yaml     # supports globs, e.g. **/draugr.saga.yaml
    revision: main
```

> Schema is accepted today; resolution/loading is tracked on the roadmap.

## `references`

Links to manual or human-performed controls (threat model, architecture diagram, …):

```yaml
references:
  - type: ThreatModel
    link: https://example.com/threat-model
```
