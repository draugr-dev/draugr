---
title: Saga schema
description: Every field of draugr.saga.yaml — release, config, components, and references.
section: Reference
order: 20
---

# Saga reference

The **Saga** (`draugr.saga.yaml`) is Draugr's descriptor — a declarative account of an
application's security surface and the controls that must pass.

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

Some controls accept a **`scanners`** list to select which tools run for them (behavioral
config; a component may override the project default). For `sast`:

```yaml
config:
  controllers:
    sast:
      enabled: true
      scanners: [semgrep, gosec]   # default: [semgrep]. gosec is Go-only — enable it on Go components.
```

> Implemented today: **`images`** (Trivy), **`sca`** (Trivy fs), **`secrets`** (Gitleaks),
> **`sast`** (Semgrep; opt-in gosec), **`iac`** (Trivy config), and **`headers`** (native
> HTTP-header checks). Other controls (`dast`, `tls`, `infrastructure`, `threats`) are on the
> roadmap. Run `draugr controls` for the current list and each control's scanners.

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
