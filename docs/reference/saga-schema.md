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
> `threats` is on the roadmap; `sbom` ships as evidence under `config.sbom` rather than as a control. Run `draugr controls` for the current list and each control's
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

## Licence policy (`controllers.licenses`)

```yaml
config:
  controllers:
    licenses:
      enabled: true
      deny: ["AGPL-3.0-only", "GPL-3.0-only"]   # → error, whatever category Trivy assigned
      warn: ["MPL-2.0"]                          # → warning

components:
  - name: shipped-cli          # distributed to customers, so stricter
    controllers:
      licenses:
        deny: ["LGPL-3.0-only"]
```

Reports dependency licences that carry an obligation. Requires Trivy.

> **Not legal advice.** Licence interpretation depends on facts Draugr can't know — whether you
> distribute, how you link, which jurisdiction applies. Findings are a starting point for a
> conversation, not a determination. See
> [scope and disclaimer](../trust-and-operations/disclaimer.md).

**It reports problems, not inventory.** By default the level follows Trivy's own classification:

| Trivy category | Level | |
|---|---|---|
| `forbidden` | error | generally incompatible with shipping proprietary software |
| `restricted` | warning | copyleft — GPL, LGPL |
| `reciprocal` | note | file-level copyleft — MPL, EPL |
| `unknown` | note | Trivy couldn't identify it |
| `notice`, `permissive`, `unencumbered` | *not reported* | |

Permissive licences aren't findings, they're inventory — every dependency has one, and listing
them buries the few that matter under dozens that don't. On Draugr's own repository that's 77
licences, of which zero carry an obligation. The inventory question is what
[`config.sbom`](#sbom-generation) answers, with a licence per package.

`restricted` is a **warning** rather than an error because whether copyleft matters depends on
whether you distribute — which the Saga doesn't say. If you ship binaries to customers, raise it:
`deny: ["GPL-3.0-only"]`.

**`deny` and `warn` name SPDX ids and beat the category**, because whether a licence is acceptable
depends on what you do with your software. Trivy can't know that; you always do.

**Gate it separately from vulnerabilities** with [`config.gate`](#configgate) — licence policy is
usually owned by different people than security policy:

```yaml
config:
  gate:
    controls:
      licenses: error      # a denied licence fails the build…
  # …while --fail-on stays wherever you had it for everything else
```

### How project and component settings combine

This differs from every other controller, deliberately, and it's the one thing worth reading
twice.

Elsewhere, a component's block **deep-merges over** the project's and the component wins — so a
component setting a list *replaces* the project's list. For `deny` and `warn`, the two **union**
instead. A component can add restrictions; it cannot remove them:

```yaml
config:
  controllers:
    licenses:
      deny: ["GPL-3.0-only", "AGPL-3.0-only"]   # the organisation's policy

components:
  - name: web
    controllers:
      licenses:
        deny: ["Sleepycat"]      # web denies all three, not just Sleepycat
```

Under the usual rule, `web` would have silently dropped both organisation-wide denials — a
component opting out of company licence policy, invisible in review. That's the failure a licence
gate exists to prevent, so **components can only tighten**.

There is exactly one way to loosen, and it requires a reason:

```yaml
config:
  exclude:
    - rules: ["license/GPL-2.0-only/*"]
      reason: "Legal reviewed 2026-07; we link dynamically and don't distribute."
```

Which is the point — an exemption you have to justify, that stays in the report marked and
auditable, is a different thing from a list entry nobody has to explain.

### Rule ids

`license/<spdx-id>/<package>`, e.g. `license/GPL-3.0-only/github.com/somelib/thing`. Licence
first so the common exemption is `license/GPL-3.0-only/*`; the full id when you mean one
dependency. Package names contain slashes, which is why `rules` patterns match `*` across
separators.

Findings resolve onto the line where the dependency is declared, so they land on the right row in
your editor. `go.mod` and `requirements.txt` resolve cleanly; nested lockfiles may not, and a
finding whose line can't be determined still points at the file.

## `config.allowEffects`

Scanner effects this project accepts. A scanner that does more to a target than read it declares
an effect; the kinds that require consent (`mutate`, `privilege`) will not run unless listed here.

```yaml
config:
  allowEffects: [mutate]
```

In the descriptor rather than only a flag because it is a decision about what may be done to your
systems: reviewed in a pull request, and applied identically by every pipeline instead of
remembered by whoever wrote the workflow. `--allow-effects` does the same for a single run.

See [scanners that do more than read](cli.md#scanners-that-do-more-than-read).

## `config.gate`

```yaml
config:
  gate:
    controls:
      licenses: error      # this control fails the build on an error…
      sast: note           # …this one fails on anything at all
```

Per-control severity thresholds, overriding [`--fail-on`](cli.md#draugr-scan-saga) for the named
control only. Values are SARIF levels: `error`, `warning`, `note`.

One threshold can't serve every control. Licence policy is owned by legal and vulnerability
policy by security; *"fail the build on a forbidden licence but only warn on a medium CVE"* is a
reasonable position that a single global threshold makes unsayable.

It lives in the Saga rather than in a flag because it's **policy** — it should be reviewed in a
pull request and applied identically by every pipeline, not remembered by whoever wrote the
workflow. Resolution order is per-control setting → `--fail-on` → `error`.

## `config.exclude`

```yaml
config:
  exclude:
    - paths: ["test/integration/repo_scan_test.go"]
      rules: ["private-key"]
      reason: >-
        The integration test writes a throwaway key so the secrets control has something real
        to find. The material is fake and was never valid anywhere.
```

Every real repository has paths that aren't the application — fixtures, examples, generated
code, vendored trees — and rules that don't apply to them. Saying so in the Saga means one
syntax for every scanner, in the file that already describes your scope, rather than learning
each tool's own ignore format.

**A suppressed finding is reported, not deleted.** It stays in the SARIF marked with its
justification (`suppressions[].kind: external`), so GitHub code scanning files it as
closed-as-suppressed and an auditor can see exactly what was set aside and why. It stops
counting: no summary, no verdict, no fix-first row. The console says how many:

```
5 findings suppressed by config.exclude
```

That line is the point. An exclusion that left no trace would read exactly like a finding that
was never there.

| Field | Meaning |
|-------|---------|
| `paths` | Location patterns. A pattern ending in `/` matches everything beneath that directory; otherwise it's a glob against the whole location, so `*.md` and `test/fixture.go` both work. |
| `rules` | Rule ids. `*` matches any run of characters, **including `/`** — so `CVE-2019-*` and `license/GPL-3.0-only/*` both work. A pattern with no `*` matches exactly. |
| `reason` | **Required.** Why this exclusion exists. |

**`paths` and `rules` glob differently, on purpose.** In `paths`, `*` stops at a directory
separator, so `*.md` matches `README.md` but not `docs/README.md` — they really are paths. In
`rules` it doesn't, because a rule id is an opaque string and the compound ones are the ones
worth matching: a package name contains slashes, so a wildcard that stopped at `/` couldn't
express "this rule, whichever package".

A wide pattern is safe to use because it is **loud**. Nothing is deleted, so `rules: ["*"]`
reports `N findings suppressed by config.exclude` and every one of them sits in the SARIF with
your justification. An exclusion that swallowed more than you meant shows up in the count.

**When both `paths` and `rules` are set, a finding must match both.** That's the narrow reading —
"this rule, in this place" — and the safe one: the alternative would quietly widen *ignore the
fixture's fake key* into *ignore that rule everywhere*.

**A reason is required** because an exclusion without one is indistinguishable from an oversight
six months later, and a reviewer has nothing to judge. It's the cheapest guard against a scanner
being quietly defanged. An entry with neither `paths` nor `rules` is rejected too — it would
suppress every finding in the project.

Findings a scanner suppressed itself (a Semgrep `nosem` comment, say) keep their own reason and
aren't re-attributed to your Saga.

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
