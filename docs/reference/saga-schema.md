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
fragments: [ ... ]            # optional — merge other Saga files into this one
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

**A control name Draugr does not provide is an error**, wherever it appears — here, in
`config.gate.controls`, or in a component's own `controllers`. A typo is otherwise invisible: the
descriptor claims a decision it is not making, and the run goes green either way.

```
$ draugr validate draugr.saga.yaml
draugr: config.gate.controls: "iaac" is not a control this build of Draugr provides — did you mean "iac"?
```

Checked against what **this build** can run, which is also what
[`draugr controls`](cli.md#draugr-controls) lists and what the
[JSON Schema](#editor-support-autocomplete-hover-docs-validation) offers for autocompletion — all
three come from one place and cannot disagree.

### Authenticating a dynamic scan

`dast` probes an endpoint anonymously unless a host says otherwise. Against an application that
requires a login that means it tests the login page, finds little, and passes — a verdict about the
least interesting part of the system.

```yaml
hosts:
  - url: https://api.example.com
    auth:
      type: bearer
      tokenEnv: DRAUGR_API_TOKEN
```

`type: bearer` sends `Authorization: Bearer <token>`; `type: header` with `header: X-API-Key` sends
that header instead.

**`tokenEnv` names a variable; there is no field for the credential.** A descriptor is committed,
so a token in one is a leaked token. The value is read at the moment of the scan, written to a
`0600` file for the scanner to read, and removed afterwards — never placed on a command line,
where a process list would show it, and never in a cache key or a report.

**An unset variable fails the scan** rather than falling back to anonymous, because a quiet
fallback produces the pass this feature exists to prevent. The report records *that* the scan
authenticated and which variable it read, so an authenticated run is never mistaken for an
anonymous one — and the cache key carries the same marker, so adding credentials invalidates
results gathered without them.

### Per-scanner config

A control can be served by more than one scanner, and each scanner is configured under its own
key in `controllers.<control>.<scanner>`. **The key is camelCase**, like every field in a Saga —
so a scanner whose name is hyphenated is configured under the camelCase form of it
(`kube-bench-job` → `kubeBenchJob`, `draugr-tls` → `draugrTls`). A hyphenated key is rejected at
load: it would otherwise match no scanner and quietly run one fewer than asked for. A scanner block holds an optional **`enabled`** flag
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
    threats:
      enabled: true
      virustotal:
        enabled: true             # opt-in: a second feed is a second party told about your hosts
        requestsPerMinute: 1000   # only if your key is a paid one; defaults to the free tier's 4
```

**Every scanner declares the options it accepts**, and anything else under its block is rejected
before the scan runs, naming the key it could not honour. That includes the scanners that accept
nothing: an option a scanner does not read is an error, not a setting that quietly does nothing.

**Which scanners take options, and which take only `enabled`:**

| Scanner | Options |
|---|---|
| `mend-sca` | `productToken` (required), `project`, `resultTimeout`, `settings` |
| `mend-licenses` | the `mend-sca` options, plus `deny` and `warn` |
| `kube-bench-job` | `targets`, `benchmark`, `namespace`, `image`, `nodeSelector`, `timeout`, `context` |
| `kube-bench` | `targets`, `benchmark`, `version`, `context`, `configDir` |
| `trivy-license` | `deny`, `warn` — SPDX identifiers |
| `draugr-tls` | `expiryErrorDays`, `expiryWarnDays` |
| `gosec` | `include`, `exclude` — rule IDs; `tags` — Go build tags |
| `trivy`, `trivy-fs` | `pkgTypes` (`os`, `library`), `dbRepository` — an internal mirror |
| `grype`, `grype-fs` | `byCve` — report under the CVE rather than the advisory ID, on by default |
| `trivy-config` | `checks` — paths to your own Rego; `namespaces` — the namespaces they declare |
| `semgrep` | `config` — a registry ref, path or URL |
| `gitleaks` | `config` — a rules file shared across repositories; `history` — scan commit history too |
| `virustotal` | `requestsPerMinute` |
| `nuclei`, `draugr-headers`, `draugr-k8s-policies`, `urlhaus` | `enabled` only |

```bash
draugr controls --options   # the authoritative list, read from the same schemas the gate enforces
```

**Your editor knows these too.** The published schema names each control's scanners and the
options each accepts, so completion and hover docs work inside a control block, and a scanner or
option that does not exist is flagged as you type. It is generated from the same registry the gate
consults, so the three answers cannot disagree.

**No scanner option filters findings**, and that is a rule rather than an omission. Trivy's
`--severity` and `--ignorefile`, gosec's `-severity` and `-confidence` — each drops findings inside
the tool, where Draugr never sees them. A finding Draugr never saw cannot be reported as
suppressed, cannot carry the reason someone gave for accepting it, and cannot be told apart from
one that was never made. Use [`config.exclude`](#configexclude) for a finding you have judged, which keeps
it in the report marked suppressed, and the gate thresholds for what should fail a build. Scanner
options decide **what gets looked at**; the gate decides what the answer means.

Paths in options — `gitleaks.config`, `trivyConfig.checks` — resolve relative to **where Draugr
runs**, not to the repository being scanned. Repository scanners work in a temporary clone, and a
path resolving inside it would point at somewhere your file is not.

Scanners in the last row run with the arguments Draugr chooses. Where a control has more than one
scanner, the choice you make is **which one serves it** — and that choice is the one that
matters most, because it is what lets a descriptor outlive any particular tool.

> Implemented today: **`images`** (Trivy), **`sca`** (Trivy fs), **`licenses`** (Trivy),
> **`secrets`** (Gitleaks), **`sast`** (Semgrep; opt-in gosec), **`iac`** (Trivy config),
> **`infrastructure`** (native CIS checks; opt-in kube-bench), **`headers`** (native HTTP-header
> checks, including a graded CSP), **`dast`** (Nuclei), **`tls`** (native TLS/certificate
> probe), and **`threats`** (abuse.ch URLhaus reputation — needs a free key, and discloses your
> hostnames to a third party). `sbom` ships as evidence under `config.sbom` rather than as a
> control.
>
> **`draugr controls` is the authoritative list** — it asks the same registry the validator and the
> JSON Schema do, so it cannot be out of date with the binary you are running. This one is prose,
> and prose drifts.

## `config.reports` and `config.publishers`

Declare which report **formats** a scan renders and **where** they're delivered. Reports are the
"what" (a [Reporter](../contributing/plugin-api.md#reporter)); publishers are the "where" (a Publisher). Every
rendered report is delivered to every publisher.

```yaml
config:
  reports:
    - format: sarif        # any scan --format: console, markdown, html, junit, json, sarif
      minPriority: P1      # optional — narrow this report, leaving the others complete
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

**`minPriority`** narrows one report to findings at or above a priority band (`P1`–`P4`), leaving
every other report complete. It exists for the SARIF that becomes review comments: a reviewer shown
every finding in the repository reads none of them, while the JSON beside it is evidence and
evidence is not something to trim.

Narrowing an artifact is otherwise refused, and for a good reason — a file that claims to be the
scan and is not misleads whatever reads it, most sharply `draugr diff`, which reads a missing
finding as a fixed one. What makes this different is that it is **declared**: written in the
descriptor, and recorded inside the artifact it produced, so a consumer can tell a narrowed file
from a whole one. `--min-priority` on the command line still trims only what is printed;
`--artifact-min-priority` is the flag that narrows a file, and it says so in the file.

The `github` publisher requires a `sarif` report in `config.reports`. It never stores a secret in
the descriptor — the token comes from an environment variable. Code scanning is free for public
repos; private repos need GitHub Advanced Security.

The **`github-pr-comment`** publisher posts the `markdown` report as a **sticky** pull-request
comment (updated in place on each push). It needs a `markdown` report in `config.reports`; `repo`
and the PR number default from the GitHub Actions environment; the token comes from `$GITHUB_TOKEN`
(or `tokenEnv`). It no-ops off a pull request. It's most useful with
[`draugr diff --publish`](cli.md#draugr-diff-basesarif-headsarif), which posts a PR **security
delta** (new / fixed findings) as that comment.

The **`azure-pr-comment`** publisher is its Azure DevOps counterpart, with the same sticky
behaviour. `org`, `project`, `repo` and the PR number default from the Azure Pipelines
environment, so `kind: azure-pr-comment` on its own is usually the whole configuration. The token
comes from `$SYSTEM_ACCESSTOKEN` (or `tokenEnv`), which a pipeline must map into the step
explicitly — see [reports & publishers](../guides/reports-and-publishers.md#azure-devops) for
that and for the repository permission the build identity needs.

The **`gitlab-mr-comment`** publisher is the GitLab counterpart, with the same sticky behaviour.
The project and the merge-request IID default from the GitLab CI environment, so
`kind: gitlab-mr-comment` on its own is usually the whole configuration; `repo` accepts a numeric
project id or a full path, groups included. The token comes from `$GITLAB_TOKEN` (or `tokenEnv`)
and must carry **`api`** scope — `CI_JOB_TOKEN` is read-only on the notes API and cannot post,
which is worth knowing before reaching for the variable GitLab already provides. See
[reports & publishers](../guides/reports-and-publishers.md#gitlab).

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

| Kind | |
|---|---|
| `mutate` | creates or changes something that outlives the scan — **needs consent** |
| `privilege` | needs access beyond what reading the target requires — **needs consent** |
| `network` | sends traffic to the target rather than reading an artifact |
| `disclosure` | sends information about the target to a third party |

`network` and `disclosure` are recorded but not gated. The controls that do them exist to do
them, and a prompt for the thing the control is *for* becomes a keystroke people learn to skip.
Both carry an obligation stated rather than enforced: that you are entitled to probe the host, and
that you are content for the third party to know what was sent. What was sent is in the effect's
detail line, because "a hostname" and "your source code" are not the same decision.

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

Per-control severity thresholds, overriding [`--fail-on`](cli.md#draugr-scan-sagayaml--dir) for the named
control only. Values are SARIF levels: `error`, `warning`, `note`.

One threshold can't serve every control. Licence policy is owned by legal and vulnerability
policy by security; *"fail the build on a forbidden licence but only warn on a medium CVE"* is a
reasonable position that a single global threshold makes unsayable.

It lives in the Saga rather than in a flag because it's **policy** — it should be reviewed in a
pull request and applied identically by every pipeline, not remembered by whoever wrote the
workflow. Resolution order is per-control setting → `--fail-on` → `error`.


## Where a repository comes from: URLs and paths

`url` accepts either a **remote URL** or a **local path**. The field is named for the common case;
anything git can clone is valid.

```yaml
repositories:
  - url: https://github.com/acme/web.git   # remote — cloned over the network
  - url: git@github.com:acme/web.git       # remote — uses your SSH agent
  - url: ../web                            # local — relative to the descriptor's directory
  - url: /srv/checkouts/web                # local — absolute
```

A relative path resolves against **the directory holding the Saga**, not the current working
directory, so a descriptor committed beside its code means the same thing wherever it is run
from. `draugr scan .` with no descriptor synthesises one pointing at the directory you named, so
the zero-config path lands here too.

**Both kinds are cloned.** A local path is not read in place: Draugr clones it into a temporary
directory the same way it clones a URL, applies [`paths` and `ignore`](#scoping-a-repository) as
a sparse checkout, and runs the scanners over that. Three things follow, and they are the reason
this section exists.

**The scan sees the committed revision, not your working tree.** Uncommitted work — edited,
staged, or untracked — is simply absent. A change that introduces a finding passes until it is
committed, and a fix appears not to have worked. This is deliberate: a report has to name a
revision that someone else can check out and reproduce, and "whatever was on one machine at one
moment" is not that.

**So the report names it**, along with what it left out:

```
Scanned: https://github.com/acme/web.git at 3f9a1c2b (3 uncommitted files not included)
```

**A repository is named by the repository, not by how you reached it.** Two details follow, and
both exist so that one repository reads as one thing however it was scanned.

*A local checkout is reported as the repository it was cloned from.* Point a descriptor at `.` or
`/srv/web` and the report names its git remote, because the path is where the code sits on one
machine rather than which repository it is. That is what lets a scan on a laptop and a scan in a
pipeline recognise each other: same repository, same revision, same identity — so they share a
cache entry, and `draugr diff` can compare them. A checkout with **no** remote keeps its path,
which is then the only name it has and the one you can act on.

*Credentials and usernames are dropped.* `https://oauth2:TOKEN@github.com/acme/web.git` is
reported, cached and named as `https://github.com/acme/web.git`, and Azure DevOps URLs stop
carrying the organisation as a username as well as in the path. The URL used to **clone** keeps
everything it had — fetching is the one thing credentials are for.

That line is in the console report, the Markdown and HTML ones, and the JSON under
`repositories`. It is per repository and per revision rather than per control: several controls
scanning one checkout is one fact. If two controls somehow read different commits — possible on a
branch that moves mid-scan, since each scanner checks out independently — both are listed, because
a single revision would be an assumption rather than a record.

For the loop of fixing something, `draugr scan --working-tree` reads the checkout as it is —
uncommitted work included, from a copy, and marked in the report as not reproducible. See
[the CLI reference](cli.md#--working-tree-for-the-loop-of-fixing-something).

**`revision` still applies.** A local path with `revision: main` scans `main`, whatever branch
the working copy happens to be on. Left unset, the scan follows the checkout's current `HEAD` —
which is usually what you want locally and worth pinning in CI.

**The clone is a copy.** Nothing a scanner does can modify your checkout, and the temporary
directory is removed when the scan ends.

Use a local path for iterating on a descriptor, for scanning something not pushed anywhere, and
for a monorepo where several components share one checkout. Use a URL in CI, where the path is
the runner's and means nothing to anyone reading the report later.

### What this means for `draugr diff`

`diff` compares two `results.sarif` files, so it inherits this: both sides describe committed
revisions. In CI that is exactly right — the base is a merge-base commit and the head is the PR's
head commit, both pushed, both reproducible — and it is why the [GitHub Action](../guides/github-action.md)
needs `fetch-depth: 0` to reach the base.

Locally it is the part that surprises people. This does nothing:

```bash
draugr scan . -o base/
vim app/handler.py          # introduce something
draugr scan . -o head/
draugr diff base/results.sarif head/results.sarif   # → no change
```

Both scans cloned the same `HEAD`, so both SARIF files are identical. Commit between them, and
the diff is real:

```bash
draugr scan . -o base/
git commit -am "add the endpoint"
draugr scan . -o head/
draugr diff base/results.sarif head/results.sarif
```

Or scan two revisions explicitly by pointing `revision` at each in turn, which is closer to what
CI does and does not disturb your branch.

## Scoping a repository

A monorepo holds more than one component, and a component is rarely the whole tree. `paths` and
`ignore` narrow what a scan looks at.

```yaml
repositories:
  - url: https://github.com/acme/monorepo.git
    revision: main
    paths:
      - services/web        # only this subtree…
    ignore:
      - "**/testdata/**"    # …minus the fixtures inside it
      - vendor/
```

**`paths` selects directories.** `services/web` and `services/web/**` mean the same thing; a
trailing `/**` is accepted because it reads naturally. Draugr checks out only those directories,
so a large repository is also cheaper to scan — the rest is never fetched.

**Files at the repository root are always included**, whatever `paths` says. `go.mod`,
`package.json`, `Dockerfile`, `.trivyignore`, `.semgrepignore` and their kin live there, and they
are how a scanner knows what it is looking at. A tool that cannot find the manifest does not
fail — it reports fewer findings against a tree it did not understand, and that is
indistinguishable from a clean scan.

**`ignore` removes paths, and runs last** — so it can carve out of a subtree `paths` selected.
The patterns are gitignore-shaped: a trailing `/` matches a directory and everything beneath it,
`*` matches within one path segment, `**` matches across segments. A bare name like `vendor`
means the directory and its contents.

Both are relative to the repository root; an absolute path or one containing `..` is rejected
when the descriptor loads.

**Scope is part of a target's identity.** Two components pointing at different subtrees of the
same repository are two different scans, cached separately, and their findings stay apart.

> `ignore` here is not the same tool as `config.exclude`, below. `ignore` narrows what is
> **scanned** — the files never reach the tool, and nothing is reported about them. `exclude`
> narrows what is **counted**: the finding is still made, still in the report, marked suppressed
> with the reason someone gave. Use `ignore` for code that is not yours to answer for, like a
> vendored tree. Use `exclude` for a finding you have looked at and accepted.

## `config.exclude`

```yaml
config:
  exclude:
    - paths: ["test/integration/repo_scan_test.go"]
      rules: ["private-key"]
      reason: >-
        The integration test writes a throwaway key so the secrets control has something real
        to find. The material is fake and was never valid anywhere.
      acceptedBy: "Wilson Santos <wilson@draugr.dev>"

    # A risk accepted for now rather than forever.
    - rules: ["CVE-2026-12345"]
      reason: "Upstream fix lands in v2.4. Reachable only from the offline importer."
      acceptedBy: "Wilson Santos <wilson@draugr.dev>"
      expires: 2026-08-14
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
| `acceptedBy` | Who decided this was acceptable. Optional; a suppression without one is reported as **unattributed**. |
| `expires` | The date it stops applying (`YYYY-MM-DD`). Past it the finding returns and the report says the exclusion lapsed. |
| `vex` | What this suppression claims about the product, for [`--report vex`](../guides/vex.md). Optional — see [below](#declaring-what-a-suppression-means-in-vex). |

**Who, why, and until when.** The question asked of a suppression is not whether the scanner ran
— it is who decided this was acceptable, and when. `reason` answers why; the other two answer the
rest, and they are separate fields rather than prose because a name buried in a sentence cannot
be reported on.

`acceptedBy` is optional so existing descriptors keep working, and the console says how many
suppressions have nobody attached:

```
5 findings suppressed by config.exclude (2 unattributed)
```

### Declaring what a suppression means in VEX

`reason` is prose for whoever reviews the descriptor. A [VEX](../guides/vex.md) status is a
machine-readable claim your customers' tooling acts on without reading it. They are different
statements, so `vex` is a separate field rather than something inferred from the other one:

```yaml
config:
  exclude:
    - rules: ["CVE-2018-18074"]
      reason: "The redirect path that leaks the header is never taken; we pin the host."
      acceptedBy: "Wilson Santos <wilson@draugr.dev>"
      vex:
        status: not_affected
        justification: vulnerable_code_not_in_execute_path
```

| Field | Meaning |
|-------|---------|
| `status` | `not_affected`, `affected`, or `fixed`. |
| `justification` | Why the product is not affected, from VEX's fixed vocabulary. Valid only with `not_affected`. |

The justifications are `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary` and
`inline_mitigations_already_exist`. A closed list, because the entire value of the field is that
a consumer can act on it without reading English. Omit it and the `reason` is published as VEX's
prose alternative instead, which is valid and simply less useful to a machine.

**Omitting `vex` entirely is fine.** The suppression is then published as `affected` carrying your
reason — true, since you did find it and did decide to accept it. Draugr will not read the reason
to work out whether you meant `not_affected`: that is a claim of safety made on your behalf,
inferred from prose, and published over your name.

`under_investigation` is not accepted here. It is what an untriaged finding already reports, and
claiming it for something you have suppressed says the matter is both open and settled.

**An expiry is enforced, not advisory.** On the day after `expires` the exclusion stops
suppressing and the finding comes back — with the report saying the exclusion lapsed, so a
finding that used to be accepted does not simply reappear unexplained:

```
1 exclusion expired and no longer suppressing:
  expired 2026-08-14, accepted by Wilson Santos — Upstream fix lands in v2.4…
```

An exclusion accepted "until the upstream fix lands" otherwise has nothing that brings the
finding back, which is how a suppression mechanism decays into a way of never seeing something
again. A date that cannot be parsed is rejected at load: it would suppress indefinitely while the
descriptor claims otherwise.

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

## `config.exploitability`

Raises a finding's severity by real-world exploitability before it is ranked, so priority reflects
what is being exploited rather than only what could be.

```yaml
config:
  exploitability:
    kev: cache          # path | cache | auto — omit to leave KEV off
    epss: cache
    epssThreshold: 0.5  # optional; default 0.5
    maxAge: 24h         # optional; default 24h
```

| Key | Meaning |
|-----|---------|
| `kev` | CISA's Known Exploited Vulnerabilities catalog. A CVE on it becomes **critical**, whatever it was. |
| `epss` | FIRST's EPSS scores. A CVE at or above `epssThreshold` is raised **one band**. |
| `epssThreshold` | The EPSS probability (0–1) that triggers the bump. Zero disables it while leaving KEV in force. |
| `maxAge` | How old a cached feed may be before `auto` refetches it and a scan warns. A Go duration. |

KEV wins where both apply: observed exploitation outranks a prediction about it. Either signal
works without the other — set one key and omit the other.

**Where the data comes from.** `kev` and `epss` each take three kinds of value:

| Value | Behaviour |
|-------|-----------|
| a path | that file. Touches neither the cache nor the network — the air-gapped route |
| `cache` | reads `~/.draugr/feeds`; **never** fetches. Errors if nothing is cached |
| `auto` | reads the cache, fetching when it is missing or older than `maxAge` |

Populate the cache with [`draugr feeds update`](cli.md#draugr-feeds). In CI, make that its own
step and use `cache`, so a feed outage fails where it happened rather than producing a scan that
ranked everything as though nothing were exploited.

**Flags override this block**, but only the ones you actually type: `--kev`, `--epss` and
`--epss-threshold`. Passing `--epss-threshold 0.5` beats a descriptor saying `0.1` even though
0.5 is also the flag's default; not passing it leaves the descriptor's value alone.

Raise `maxAge` on a runner deliberately pinned to a known copy of the data — reproducing last
quarter's verdict requires last quarter's feed.

See [prioritization](../concepts/prioritization.md#exploitability-kev-and-epss) for what the
signals mean and how to choose a threshold.

## VEX (`config.vex`)

Names the party making the claims in a generated [VEX document](../guides/vex.md)
(`--report vex`), and the product they are about.

```yaml
release:
  name: acme-api          # what you call this internally
  version: "2.4.0"

config:
  vex:
    author: "Acme Ltd <security@acme.example>"   # who is making the claim
    product: "pkg:oci/acme/api"                  # what a consumer will match on
```

| Field | The question it answers |
|-------|-------------------------|
| `author` | **Who is making this claim?** An organisation, ideally with a way to reach them. |
| `product` | **What will a consumer's tooling look this up by?** An IRI; a package URL is conventional. |

### `release` and `config.vex` are not the same thing

They describe the same product and rarely with the same string, which is the part worth being
careful about.

**`release` is what you call this internally.** It names what Draugr is qualifying, and it is
what appears at the top of your report.

**`config.vex` is how the outside world refers to it.** A VEX statement is matched by product
identifier: a consumer applies it when the identifier equals what *their* SBOM calls the thing
they are scanning. That is usually not your release name — it is an image reference, a package
URL, a digest.

Both fields are optional, and the defaults produce a valid document rather than a publishable
one:

| Unset | Falls back to | Why that is not enough |
|-------|---------------|------------------------|
| `author` | `release.name` | A project name is not a party. A consumer with a question about your claim needs somebody to ask. |
| `product` | `pkg:generic/<release.name>@<release.version>` | Synthesised from your descriptor. `pkg:generic/` says so plainly. Unless a consumer happens to call your product exactly that, nothing will match. |

**A document nothing matches fails silently.** A consumer cannot tell that a statement was meant
for it, so a wrong identifier does not error — it is read, understood, and applied to nothing.
This is the single field most worth checking against a consumer's SBOM before you publish.

### Versions track the release

A VEX statement is about a *version* of a product: `not_affected` in 2.3 says nothing about 2.4.

**Leave the version out of `product` and Draugr appends `release.version`.** This is the
recommended form, and it cannot go stale — the identifier moves when the release does.

```yaml
release:  { name: acme-api, version: "2.4.0" }
config:
  vex:
    product: "pkg:oci/acme/api"     # → pkg:oci/acme/api@2.4.0
```

A version you write yourself is kept exactly as given, because pinning is sometimes what you
want:

```yaml
    product: "pkg:oci/acme/api@sha256:0123…"   # a digest, left alone
```

That escape hatch has a cost worth stating: **a literal version does not follow the release.**
Write `pkg:oci/acme/api@2.4.0`, ship 2.5.0, and the document keeps claiming 2.4.0. Prefer the
version-less form unless you are pinning to something immutable.

Qualifiers and a subpath are preserved — the version is inserted where the package-URL
specification puts it (`pkg:type/name@version?qualifiers#subpath`). A `product` that is not a
package URL is left untouched, since VEX identifies a product by IRI and a purl is only the
convention.

## SBOM generation

```yaml
config:
  sbom:
    enabled: true
    format: cyclonedx-json   # defaults to cyclonedx-json
    scope: component         # component (default) | project | both
```

Produces one [Software Bill of Materials](glossary.md#sbom--software-bill-of-materials) per
distinct repository and image in the Saga — an inventory of what each one contains. Requires
[Syft](https://github.com/anchore/syft) (`draugr tools install syft`).

**Choosing a format.** Both open specifications, each in both of its standard encodings — pick
whichever the thing consuming the document reads:

| `format` | Written as | Media type |
|----------|------------|------------|
| `cyclonedx-json` (default) | `sbom-<component>-<target>.cdx.json` | `application/vnd.cyclonedx+json` |
| `cyclonedx-xml` | `sbom-<component>-<target>.cdx.xml` | `application/vnd.cyclonedx+xml` |
| `spdx-json` | `sbom-<component>-<target>.spdx.json` | `application/spdx+json` |
| `spdx-tag-value` | `sbom-<component>-<target>.spdx` | `text/spdx` |

**Why CycloneDX is the default.** Both are open standards and neither is going away, so the
default is decided by what a document is likely to be *used for* rather than by seniority.
CycloneDX (ECMA-424) composes: a document can carry nested components and state how complete it
is, so it answers "what is in this project" and not only "what is in this repository". It is
also what most security tooling reads first, and the format VEX is expressed in. SPDX (ISO/IEC
5962) is the name a procurement questionnaire or licence-compliance process is more likely to
ask for — set `format: spdx-json` when that is who the document is for.

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

SBOM: 2 documents (cyclonedx-json)
```

### One document per target, or one per product

`scope` decides what each document covers.

| `scope` | Produces |
|---------|----------|
| `component` (default) | one document per distinct repository and image |
| `project` | one document covering the whole release |
| `both` | the per-target documents **and** the assembled one |

**Why this exists.** An SBOM is asked for per *product*. A customer questionnaire, EO 14028 and
the CRA all want the bill of materials of the thing you shipped. Draugr scans per repository and
image — so a project with four repositories and three images produces **seven documents and no
answer to the question being asked**.

```yaml
config:
  sbom:
    enabled: true
    scope: project
```

```
SBOM: 1 project document (cyclonedx-json)
```

The assembled document is written as `sbom-project.cdx.json`. Its root component is the release,
with one node per Saga component beneath it, one per repository or image beneath that, and the
packages beneath those.

**This is assembly, not merging.** A generic merge tool has a pile of documents and has to guess
how they relate. Draugr is handed a release containing named components containing named targets
— the hierarchy is declared, so it does not have to be inferred.

That matters for the question a merge usually destroys. When `requests 2.19.1` appears in three
components, deduplicating to one entry answers *what do we ship* and loses *who ships it*, which
is what a triager needs the moment a CVE lands; keeping three entries answers the second and makes
any consumer counting packages report a meaningless number. So Draugr keeps **one entry per
package** and a **dependency graph** saying which targets contain it, and both questions are
answerable from the same document. Two versions of one library stay two packages.

`scope: project` replaces the per-target documents rather than adding to them — you asked for a
document covering the product. Use `both` when you want the parts as evidence for the whole.

**CycloneDX only.** `project` and `both` require `format: cyclonedx-json` and say so if it is
something else. SPDX expresses containment through relationships and could carry this, but
assembling it correctly is different work, and a half-right SPDX document would be worse than
declining because nothing about it would look wrong.

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
        paths: ["services/web"]                 # optional — scan only this subtree
        ignore: ["**/testdata/**"]              # optional — remove these from the scan
    images:
      - image: registry.example.com/acme/web:1.0  # required
        digest: sha256:…                          # optional — pin the immutable content digest
    hosts:
      - name: api
        url: https://api.example.com            # required
        type: api                               # browser | api (default browser); tunes header checks
        auth:                                   # optional — authenticates the dast scan
          type: bearer                          #   bearer | header
          header: X-API-Key                     #   required with type: header
          tokenEnv: DRAUGR_API_TOKEN            #   the variable holding it; there is no field
                                                #   for the credential itself, because a
                                                #   descriptor is committed
    infrastructure:
      - kind: kubernetes                        # e.g. kubernetes
        ref: prod-cluster
        namespaces: [team-a, team-a-jobs]       # optional — the namespaces this component owns
    controllers:              # optional per-component overrides (same shape as config.controllers)
      images:
        enabled: true
```

**Control resolution:** a component-scoped control runs for a component when it is enabled
on the component, or (absent an override) enabled globally under `config.controllers`.

**Several repositories on one component** is supported and worth knowing the shape of: Draugr plans
one job per repository and runs them concurrently, and paths in a finding are relative to the
repository it came from. Two repositories that share a path therefore produce findings that look
alike — so a finding records which repository it came from, that is part of what makes it a
distinct finding, and the report grows a `Repository` column when findings span more than one.
The same applies to repositories a [fragment](../guides/saga-fragments.md) contributes from another
project.

**Infrastructure namespaces:** `namespaces` narrows an infrastructure surface to the part of a
cluster the component owns; omit it and the audit covers the whole cluster. Not every scanner can
honour it. `kube-bench` runs checks written as cluster-wide `kubectl` queries, and `kube-bench-job`
reads a node's own filesystem, which has no namespace — so both always describe the whole cluster.
Neither is run against a component that sets `namespaces`. The alternative would be a report that
looks scoped and lists somebody else's namespaces against this component, so the scan is not
planned — and the report says so, under **Not measured**, naming the scanner and the component:

```
Not measured:
  infrastructure  kube-bench-job on team-a — audits the whole cluster and cannot be narrowed to namespace team-a
```

Nothing has to be turned off by hand. To get both — node-level checks over the whole cluster, and
API checks scoped to what you own — declare the cluster twice:

```yaml
components:
  - name: team-a
    infrastructure:
      - kind: kubernetes
        ref: prod-cluster
        namespaces: [team-a]     # draugr-k8s-policies narrows to this
  - name: prod-cluster           # the same cluster, claimed whole
    infrastructure:
      - kind: kubernetes
        ref: prod-cluster        # kube-bench and kubeBenchJob run here
```

**Risk classification** (`exposure`, `criticality`) — optional, and the two axes of risk
prioritization: exposure is how reachable the component is (likelihood), criticality is the
business impact if it fails. Both are fixed ladders whose meaning an organization can
redefine (the levels stay stable). They feed finding prioritization; a
component may be left unclassified.

| `exposure` | meaning | | `criticality` | meaning |
|------------|---------|-|---------------|---------|
| `public` | anyone on the internet, no sign-in | | `critical` | an outage or data loss for the business |
| `authenticated` | on the internet, behind a login | | `important` | degraded service, but no outage |
| `internal` | only from inside your network or VPN | | `supporting` | limited impact, easily worked around |
| `restricted` | inside your network and locked down further — an allowlist, a private link, its own segment | | | |

The wording names no platform on purpose: a Kubernetes network policy is one way to arrange
`restricted`, and Draugr classifies repositories and images as well as clusters. `draugr classify`
asks these same questions with the same words.

## `fragments`

Merge other files into this descriptor. See [split a Saga across
files](../guides/saga-fragments.md) for the monorepo shape.

```yaml
fragments:
  # Local: a path relative to the file that names it.
  - path: "**/draugr.saga-fragment.yaml"

  # Remote: the same shape as a repository, plus which files to read.
  - url: https://github.com/acme/platform.git
    revision: v2.4.0
    path: "components/**/draugr.saga-fragment.yaml"
```

| Field | Meaning |
|-------|---------|
| `path` | **Required.** Which files to read. Globs use the same dialect as `paths` and `ignore` — `*` within a segment, `**` across them. Relative to the file that names it, so `../shared/x.saga-fragment.yaml` works. |
| `url` | A git repository to read from. Omit for a local path. |
| `revision` | Branch, tag or commit. **Required with `url`**, and not defaulted — see below. |

**A fragment adds scope or adds attributed suppressions; it cannot change policy.** It may carry
`components`, `config.exclude`, and further `fragments` — nothing else. `release`, `config.gate`
and `config.controllers` are rejected, naming the rule. That is what makes a `fragments:` line
safe to review: pulling a file in can never quietly lower your gate or switch a control off, and
the worst it can do is add suppressions, which are individually attributed and counted in the
report.

**A pattern that matches nothing is an error.** Somebody wrote the line on purpose, so silence
from it is indistinguishable from a typo — and the result would be a descriptor scanning less
than it claims. If a product genuinely has no components on one cloud, do not list that pattern.

**A remote fragment must name a revision.** Defaulting to the repository's default branch would
make your gate change with no commit in your own repository. A tag is fine; the commit it
resolved to is recorded, so a tag that moves is visible afterwards.

Fragments are files named `*.saga-fragment.yaml` (or `.yml`), with [their own
schema](https://draugr.dev/schema/draugr.saga-fragment.schema.json) — a fragment has no
`release:`, so validating one against the Saga's schema would report every valid fragment as
broken. `draugr validate` checks a fragment on its own, and `draugr schema --fragment` prints the
schema this build enforces.

```bash
draugr validate azure.saga.yaml --resolved   # the merged descriptor, with sources
```

## `references`

Links to manual or human-performed controls (threat model, architecture diagram, …):

```yaml
references:
  - type: ThreatModel
    link: https://example.com/threat-model
```
