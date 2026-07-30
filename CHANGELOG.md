# Changelog

All notable, user-facing changes to Draugr. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

Each release's notes are written for **users first** (what you can do, what changed for
you), with technical detail linked from the commit history. Keep an `Unreleased` section
and move it under a version on release.

## [Unreleased]

### Added

- **The `infrastructure` control can now audit the rest of the CIS Benchmark**, by running
  kube-bench inside the cluster:

  ```yaml
  config:
    allowEffects: [mutate, privilege]
    controllers:
      infrastructure:
        enabled: true
        mode: job
  ```

  The default stays read-only and covers section 5 — RBAC, service accounts, Pod Security
  Standards — which is what can be answered through the Kubernetes API. Sections 1 to 4 read a
  node's own filesystem: API server manifests, kubelet configuration, etcd permissions. Those are
  **95 of the 130 checks in `cis-1.9`**, and the only way to reach them is from a pod on the node.

  So `mode: job` creates a short-lived Job, waits for it, reads its output, and deletes it —
  including when the scan fails or is cancelled. It needs `mutate` and `privilege` accepted
  first, and says exactly what it would do if they are not. Nothing is installed locally; the
  image carries the tool.

  The Job mounts host paths **read-only** and asks for no RBAC, because these checks read the
  filesystem rather than the API. It is still a privileged pod, and a namespace enforcing the
  restricted Pod Security Standard will reject it — which is that standard working as intended.

  On a managed cluster (GKE, EKS, AKS) the control plane is not yours and cannot be inspected by
  any tool, so `targets: node` is the useful setting there.

## [0.45.0] - 2026-07-30

### Added

- **Scanners declare what they do to a target beyond reading it, and Draugr acts on it.** Most
  read an artifact and nothing else. A few do more, and now say so — before a scan, during it,
  and in the report.

  `draugr controls` lists them:

  ```
  Scanners that do more than read:
    Scanner  Effect   What happens
    nuclei   network  sends probe traffic to the endpoint, which is lawful only against
                      systems you own or have written permission to test
  ```

  **An effect that changes a target, or needs elevated access, does not run until accepted:**

  ```yaml
  config:
    allowEffects: [mutate]
  ```

  or `--allow-effects` for a single run. A scanner whose effect has not been accepted stops the
  run *before* it does anything, and says what it would have done.

  **Sending traffic is declared, not gated.** A dynamic scanner exists to send traffic, and
  demanding consent per run for the thing the control is *for* teaches people to accept without
  reading. `dast` now states it instead — until now nothing in the tool mentioned that probing a
  host is lawful only against systems you are entitled to test; only the scope and disclaimer
  did, which nobody reads mid-scan.

  What a run actually did is recorded in the report, so the evidence describes what happened
  rather than what was configured. Only scans that really executed count — a cache hit means the
  traffic was not sent that time.

- **A new `infrastructure` control**, auditing a Kubernetes cluster against the
  [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) via
  [kube-bench](https://github.com/aquasecurity/kube-bench). A cluster is a component like any
  other — one with no code of its own:

  ```yaml
  components:
    - name: prod-cluster
      exposure: public
      criticality: critical
      infrastructure:
        - kind: kubernetes
          ref: prod-eu-west-1
  ```

  **It runs the benchmark's policies section** — RBAC, service accounts, Pod Security Standards,
  network policies, secrets usage: 35 of the 130 checks in `cis-1.9`, read-only, through the
  Kubernetes API. Those are the checks describing how a cluster is configured for the workloads
  on it, and they mean the same thing whether you run them from a laptop or from CI.

  The rest of the benchmark reads a node's own filesystem, so it needs kube-bench running inside
  the cluster. Draugr does not do that, and would rather cover a quarter of the benchmark
  honestly than report on files it never saw.

  A failing scored check is an error; a `WARN` is a warning, because in CIS terms it means
  "requires a manual check" rather than "this is broken". Passing checks are not reported —
  three hundred green rows bury the dozen that matter.

  **`ref` selects the cluster.** It is matched against a kubeconfig context, and both the version
  lookup and the `kubectl` calls kube-bench makes are pointed at it — so a report cannot name one
  cluster while describing whichever one your terminal happened to be pointed at. Set `context`
  where the kubeconfig's name for a cluster differs from yours. Omit `ref` and Draugr uses the
  current context, naming it in the findings so the report still says what it examined.

  **Draugr tells kube-bench which benchmark to use.** kube-bench picks one from the Kubernetes
  version, which it reads from the node it runs on — and from outside a node it cannot, so it
  quietly assumes 1.18 and audits against a benchmark for Kubernetes 1.16. On a v1.34 cluster
  that is 24 findings where the right benchmark reports 29. Draugr asks the cluster instead, and
  fails the scan rather than guessing if it cannot reach it.

  Needs `kube-bench` and `kubectl` on `PATH`. Point `configDir` at kube-bench's `cfg/` directory
  if it is not installed at `/etc/kube-bench/cfg`.

### Fixed

- **`draugr doctor` no longer says a scan will work when it will not.** A scanner needing a tool
  Draugr does not package was skipped silently, so enabling the `infrastructure` control and
  running `doctor` reported *"All required tools present"* against an empty table — from the one
  command whose job is answering "will a scan work?".

  It now checks every binary a registered scanner declares, packaged or not, and scanners can
  declare more than one. That second part matters for tools that shell out in turn: kube-bench's
  CIS checks invoke `kubectl`, so a machine with kube-bench and no kubectl used to fail at scan
  time, after a preflight that said everything was fine. Both now appear in `doctor` and
  `tools list`.

## [0.44.0] - 2026-07-30

### Added

- **The HTML report carries its own data, and you can search it.** Two download links —
  `results.sarif` (the complete report) and `findings.tsv` (every finding, ready for a
  spreadsheet) — so the file someone emailed you is enough to work from. Tab-separated rather
  than comma-separated: finding messages are full of commas, and TSV needs no escaping and opens
  on a double-click.

  A search box and per-priority, per-severity and per-control toggles narrow the table as you
  type. Both are **progressive enhancement**: with JavaScript disabled the page still renders the
  complete table and both downloads, and the toolbar stays hidden rather than showing controls
  that do nothing.

  Findings now show their message on its own line beneath the row, so it has room to be read
  instead of being squeezed into an eighth column. Suppressed findings get their own section with
  the reason each was set aside, and the footer records when the scan ran, which version produced
  it, and the run's statistics.

  Instead of a job count, the footer reports how long the run took and a per-control breakdown of
  where the time went — worst first, with shares of total work rather than of the wall clock,
  since controls run in parallel.

### Fixed

- **A failed scanner now says what it said.** A control whose tool exited badly reported
  `run nuclei: exit status 1`, which tells you nothing you can act on — and that line is what
  reaches the terminal, the HTML report and the pull-request comment. The tool's own first line
  of output now travels with it:
  `run nuclei: exit status 1: [FTL] Could not run nuclei: no templates provided for scan`.
  `--log-level trace` still relays everything it printed.

- **The HTML and Markdown reports now say what the run couldn't do.** A control whose scanner
  failed was missing from both entirely — so a report you sent to someone listed the controls
  that worked and gave no sign the others had been asked for. They now carry an `ERROR` row and
  the reason, as the console already did.

  Both also report the suppression count and any SBOMs, and say when the finding list was
  narrowed by `--min-priority` — HTML filtered silently before, showing 21 of 56 findings beside
  priority counts that still read 56.

  While there: rule ids in the HTML report link to their documentation, dark mode is legible
  (the page asked the browser for it without styling for it), and there are print styles for
  saving to PDF.

- **`--min-priority` now works with `--format sarif`.** It was silently ignored: the output was
  byte-identical with and without the flag, so the machine consumer with the strongest reason to
  ask for "just the P1s" was the one it didn't serve — and the one least able to notice. On
  Draugr's demo repository, `--format sarif --compact --min-priority p1` is now **61% smaller**
  (11.7 KB against 30.1 KB), because the rules the omitted findings referenced leave with them.

  It narrows what a run **shows**, never what it **records**. `results.sarif` under `-o` and
  everything sent to a publisher stay complete, and a run that had to ignore the flag says so.
  The reason is one asymmetry worth knowing: GitHub code scanning resolves any alert missing
  from an upload as fixed, so a filtered report published there would quietly close real
  findings — and `results.sarif` is also what `draugr diff` compares against, where a
  short baseline makes the next delta wrong.

- **The same scan now produces the same report, byte for byte.** Controls were listed in whatever
  order Go's map iteration happened to yield, so two runs of an unchanged repository printed the
  `Controls:` block differently and wrote different `report.json`, markdown and HTML — enough to
  make the artifacts diff against each other when nothing had changed. They are now always
  alphabetical.

- **Findings read properly in your editor and on pull requests.** Trivy writes its finding
  message as a field dump whose first line is a filename, and a SARIF viewer shows the first
  line — so a Kubernetes manifest with fourteen misconfigurations produced fourteen rows in the
  Problems panel all reading `Artifact: deploy/pod.yaml`, with the one distinguishing fact five
  lines down.

  Messages are now normalized where a scanner's output is decoded rather than where the terminal
  renders it, so the advisory title (`Image user should not be 'root'`) reaches every consumer:
  the SARIF you open in VS Code or JetBrains, GitHub code-scanning annotations, and MCP clients.
  On the demo repository that is 39 of 56 findings. The scanner's full detail is unchanged and
  still travels on the rule, which is what a viewer shows beside a selected finding.

  Terminal output is unaffected — it already showed the title.

## [0.43.0] - 2026-07-28

### Added

- **Dependency licence compliance.** A new `licenses` control reports the licences in your
  dependency tree that carry an obligation:

  ```yaml
  config:
    controllers:
      licenses:
        enabled: true
        deny: ["AGPL-3.0-only", "GPL-3.0-only"]   # → error, whatever Trivy called it
        warn: ["MPL-2.0"]
  ```

  **It reports problems, not an inventory.** Copyleft, forbidden and unidentified licences are
  findings; permissive ones aren't. On Draugr's own repository that's the difference between 77
  rows saying "MIT is fine" and none at all. The inventory question is what `config.sbom`
  answers, with a licence per package.

  Findings land on the line where the dependency is declared, so they show up on the right row in
  your editor rather than at the top of `go.mod`. Each one explains the obligation — when
  copyleft actually bites, and when it doesn't — rather than only naming the licence.

  A separate control from `sca` on purpose: licence risk isn't a vulnerability, and
  `config.gate.controls` can now hold it to its own threshold. Fail the build on a forbidden
  licence while medium CVEs stay a warning.

  Project and component `deny`/`warn` lists **union** rather than override, so a component can
  tighten the organisation's policy but never silently drop it. Loosening goes through
  `config.exclude`, which requires a reason.

- **Per-control gate thresholds.** One threshold never served every control — licence policy is
  owned by legal and vulnerability policy by security, and *"fail on a forbidden licence but only
  warn on a medium CVE"* was unsayable:

  ```yaml
  config:
    gate:
      controls:
        licenses: error
        sast: note
  ```

  Overrides `--fail-on` for the named control only. In the Saga rather than a flag because it's
  policy: reviewed in a pull request, and applied identically by every pipeline instead of
  remembered by whoever wrote the workflow.

- **`config.exclude` rules accept wildcards.** `rules: ["CVE-2019-*"]` suppresses a family of
  findings without listing each one. `*` matches any run of characters including `/`, so
  compound rule ids work too; a pattern with no `*` still matches exactly, as before.

  Safe because it is loud: a suppressed finding is not deleted, so a pattern that matched more
  than you meant shows up in the `N findings suppressed by config.exclude` count, with every one
  of them in the SARIF carrying your reason.

- **A scope and disclaimer page**, under Trust & operations. What a `PASS` is silent about, why
  licence findings are information rather than legal advice, that evidence is a record and not a
  certification, that the tools Draugr runs carry their own terms, and that probing a host is
  your authorisation to obtain. Worth reading once if you are relying on a verdict in front of an
  auditor or a customer.

### Changed

- **Draugr's own scan now uses `config.exclude` instead of scanner-specific ignore files.** Its
  `.semgrepignore` and `.gitleaks.toml` are gone; both exclusions live in its Saga, with reasons.
  Nothing changes for your scans — this is us using what we shipped.

## [0.42.0] - 2026-07-28

### Added

- **Exclude findings in the Saga, with a reason.** One syntax for every scanner, in the file that
  already describes your scope:

  ```yaml
  config:
    exclude:
      - paths: ["test/integration/repo_scan_test.go"]
        rules: ["private-key"]
        reason: "Deliberate test fixture; the key material is fake."
  ```

  **The finding is suppressed, not deleted.** It stays in the SARIF marked with your
  justification, so GitHub code scanning files it as closed-as-suppressed and anyone auditing can
  see what was set aside and why. It stops counting toward the summary, the verdict and the
  fix-first list, and the console reports how many were suppressed — because an exclusion that
  left no trace would read exactly like a finding that was never there.

  A `reason` is required. When both `paths` and `rules` are given, a finding has to match both,
  so "ignore this rule in the fixture" can't quietly become "ignore this rule everywhere".

### Fixed

- **Dependency findings say what the vulnerability is.** A `sca` row used to read
  `Package: Flask Installed Version: 0.12.2 Vulnerability CVE-…` — every field of which Draugr
  already shows in its own column, and long enough that the line was cut off before reaching the
  part that explains anything. It now shows the advisory title:
  `PyYAML: command execution through python/object/apply constructor in FullLoader`. Findings
  from scanners that already write a sentence are untouched.

- **Long rule ids no longer look corrupted.** A shortened id cut mid-word
  (`…ction-tag.github-actions-mutable-action-tag`), which reads like something went wrong. It
  now cuts on a separator: `…github-actions-mutable-action-tag`.

- **The GitHub Action now writes its artifacts on pull requests.** On a PR the action runs in
  diff mode, and diff mode wrote both scans to a temporary directory that vanished with the
  runner — so `output` was ignored, an uploaded `draugr-out/` artifact was always empty, and the
  `sarif` and `report` step outputs named files that had never been written. The head scan (the
  one describing the code under review) now goes where `output` says, on every event. Only the
  base scan stays throwaway.

## [0.41.0] - 2026-07-28

### Added

- **Software Bills of Materials, via [Syft](https://github.com/anchore/syft).** Turn it on with
  `config.sbom` in your Saga and every scan also produces an inventory of each repository and
  image:

  ```yaml
  config:
    sbom:
      enabled: true
      format: spdx-json      # defaults to spdx-json
  ```

  Four formats, both open specifications in both of their standard encodings — `spdx-json`,
  `spdx-tag-value`, `cyclonedx-json`, `cyclonedx-xml` — so you can hand the document to whatever
  reads it. An unsupported value is rejected when the Saga loads, not after the scan has run.

  The documents land beside your other artifacts with `-o`, and go to any publisher you have
  configured. `draugr tools install syft` fetches the tool.

  **An SBOM is not a control, and won't appear as one.** Every row in the `Controls:` table
  means "we checked this, and here is the verdict". An SBOM finds nothing — it's an inventory —
  so a row there would always read "pass" without ever having looked. It's reported on its own
  line instead, and never affects whether your scan passes.

  What it *will* do is fail the scan if it was asked for and couldn't run, the same as a missing
  scanner: you asked for an inventory and didn't get one, and silence would let you believe you
  had it. `--allow-scan-errors` accepts the partial result.

## [0.40.1] - 2026-07-28

### Changed

- **Draugr's own dogfood scan now gates its CI.** It ran on every pull request before, but as a
  non-blocking step — so the check stayed green whatever the scan found. It now fails the build
  on a P1. Nothing changes for your scans; this is us holding ourselves to what we ask of you.

### Fixed

- **Updated gRPC to 1.82.1**, picking up the fix for
  [GO-2026-6061](https://pkg.go.dev/vuln/GO-2026-6061) — vulnerabilities in gRPC's xDS RBAC
  authorization engine and HTTP/2 transport server. It reached Draugr as an indirect dependency
  of the OpenTelemetry exporter, and the vulnerable code was reachable from telemetry startup.

### Added

- **Saga files now validate in your editor with no setup.** The Saga schema is registered with
  [SchemaStore](https://www.schemastore.org/), which VS Code's YAML extension and JetBrains IDEs
  consult by default — open any `*.saga.yaml` and you get completion, hover docs and typo
  warnings without a modeline or a settings entry. The modeline `draugr init` writes still works,
  and still matters for editors that don't use the catalog.

## [0.40.0] - 2026-07-27

### Added

- **The MCP server now carries Draugr's icon.** Clients that show an icon beside a connected
  server will display the mark instead of a placeholder. It travels three ways so it shows up
  however you installed: in the protocol handshake, in the registry listing, and inside the
  `.mcpb` bundle itself — the bundled copy means the icon still works on an offline install.

## [0.39.0] - 2026-07-27

### Added

- **Releases now carry an MCP Bundle (`.mcpb`).** A one-step install of Draugr's MCP server for
  clients that support bundles, and the packaging the MCP Registry requires for a tool
  distributed as a native binary. It's assembled from the release's own published archives, so
  the binaries inside are bit-for-bit the ones covered by `checksums.txt`, and it carries its own
  SHA-256. One bundle covers macOS (universal), Linux amd64 and Windows amd64.

- **`check_tools` over MCP.** An assistant can now ask which external scanners are present and,
  when one is missing, gets the exact command that fixes it — narrowed to what your descriptor
  actually needs. This matters more since a control that can't run stopped reporting a pass: an
  assistant that hits a missing scanner should be able to say what's wrong rather than guess.

  **There is deliberately no install tool.** Installing binaries is a write to your machine, and
  your client already has a permission model for running commands that is stronger than anything
  this server could offer. Draugr reports the command; you approve it where you approve
  everything else.

## [0.38.0] - 2026-07-26

### Changed

- **A control that couldn't run no longer passes the gate.** If a scanner binary is missing, a
  tool exits badly, or a control can't be planned, `draugr scan` now fails and names it:

  ```
  Controls:
    sca  ERROR  did not run
         trivy-fs: exec: "trivy": executable file not found in $PATH

  draugr: scan incomplete: sca could not run (use --allow-scan-errors to accept partial results)
  ```

  Previously this logged a warning and reported `PASS` with exit 0 — a green build from a check
  that never ran, which is exactly what happens in CI when scanner provisioning fails and the
  warning scrolls past unread. An empty report from a scanner that didn't run isn't evidence of
  anything, and the gate now says so.

  **This can newly fail pipelines that were silently passing.** That's the point, but if you
  want best-effort scanning, `--allow-scan-errors` restores the old exit code. The errored
  control is reported either way — the flag buys a passing exit code, not silence.

### Fixed

- **Controls that error are no longer missing from the report.** A control whose scan failed was
  absent from the `Controls:` block entirely, so the output got *shorter* precisely when
  something had gone wrong. It now appears as `ERROR`, with the reason underneath — including
  when it produced some findings before failing, where the results are partial rather than
  complete.

## [0.37.0] - 2026-07-26

### Added

- **An install script that verifies before it installs.**

  ```bash
  curl -fsSL https://draugr.dev/install.sh | sh
  ```

  It detects your OS and architecture, installs to `~/.local/bin` without `sudo`, and tells you
  if that isn't on your `PATH`. It always checks the archive's SHA-256 against the release's
  `checksums.txt`, and when cosign is available it verifies that `checksums.txt` was signed by
  Draugr's release workflow — then says which of the two checks actually ran, rather than
  implying more than it did. Nothing is installed if a check fails. `DRAUGR_VERSION` pins a
  release, `DRAUGR_INSTALL_DIR` changes where it lands, and `DRAUGR_REQUIRE_SIGNATURE=1` refuses
  to install without a verified signature — worth setting in CI.

### Changed

- **The MCP guide shows what an assistant actually gets back.** It listed the five tools and
  never showed a result — now it carries a real session against Draugr's own scan, which also
  makes the division of labour visible: priorities and scores come from the scan, while the
  assistant contributes the grouping and the judgement about which findings need a human.

## [0.36.1] - 2026-07-26

### Fixed

- **Image findings name the image you scanned.** They were reported at `library/python` line 1
  — the registry path with the tag dropped, and a line number that means nothing for a
  container image — which the console rendered as `library/python:1`, and which made two images
  in one component impossible to tell apart. They now read `python:3.8-slim`. The stray path
  also made SARIF consumers treat an image reference as a file in your workspace; that stops too.

## [0.36.0] - 2026-07-26

### Added

- **`draugr mcp` — Draugr for AI coding assistants.** Serves Draugr over the Model Context
  Protocol, so an assistant asked "is this safe to ship?" answers from your Saga instead of
  improvising a scan over a scope it invented. It can list the controls that exist, hand back
  the descriptor schema *this build* enforces, validate a Saga before you write it, and rank an
  existing report by priority. **Scanning is off by default** — it clones repositories, runs
  external scanners and uses the network, so it's offered only when you say so: `--scan=ask`
  prompts for your approval on each call, `--scan=always` skips the prompt for sandboxes and CI.
  Draugr also exposes every `*.saga.yaml` it finds nearby as an MCP resource, so an assistant
  reads your committed scope instead of inventing one. Register it with
  `claude mcp add draugr -- draugr mcp`, or the equivalent for your client. New guide:
  **Use Draugr from an AI coding assistant**.

## [0.35.0] - 2026-07-26

### Added

- **`--compact` for machine-readable output.** `draugr scan --format sarif --compact` (and
  `--format json`) strips indentation and the rule documentation Draugr relays from each
  scanner, while staying valid SARIF: 17,355 → 5,831 bytes on Draugr's own repository, for the
  same findings. Rule prose is roughly 60% of a report and a consumer that can follow a link
  doesn't need it inlined, so `helpUri` survives and the paragraphs don't. It's for something
  that *acts* on the report — a script, a policy engine, an agent paying for context. Leave it
  off for your editor and for GitHub code scanning, which both display the fields it removes.

- **See your findings in your editor.** A scan's `results.sarif` now opens as inline
  diagnostics — squiggles on the offending lines, a Problems list, click-to-line — in VS Code
  (via Microsoft's SARIF Viewer) and JetBrains IDEs, with no Draugr-specific extension. Draugr
  now relays each rule's description, remediation help and documentation link from the scanner
  that published it, and declares its relative paths against `%SRCROOT%` so a viewer resolves
  them onto files in your open workspace instead of asking you to find each one. The same
  metadata is what GitHub code scanning shows beside an alert, so alerts get fuller too. New
  guide: **See findings in your editor**.

### Changed

- **Every command's output now looks like it came from the same tool.** `doctor`, `tools`,
  `controls` and `diff` share the scan report's palette and table layout: consistent Title Case
  headers, green for pass, red for fail, dimmed supporting detail, and columns that line up
  whether or not colour is on. Colour is still emitted only for an interactive terminal with
  `NO_COLOR` unset, and that decision is now made in exactly one place instead of three.
- **Rule ids in the "Fix first" table link to their documentation, and no longer wreck the
  table.** The id now links to wherever the scanner documents the rule — every scanner, not
  just `CVE-`/`GHSA-` ids — and long namespaced ids (Semgrep's run past a hundred characters,
  which pushed the location off the screen) are shortened from the front, keeping the specific
  tail. The full id is unchanged in the JSON and SARIF reports.
- **The "Fix first" table now explains each finding.** It identified findings only by their
  scanner's rule id — `DS-0002`, `KSV-0014` — which is precise and meaningless if you don't
  already know the scanner. Each row now carries the finding's own message beneath it, dimmed,
  and rule ids with a stable public home (CVE, GHSA) become clickable links to the advisory in
  terminals that support them, costing no width in ones that don't.

## [0.34.0] - 2026-07-26

### Added

- **You can finally see what Draugr is doing.** A scan used to emit essentially nothing — one
  line at `--log-level debug`. It now narrates the run: what was planned, the **exact command**
  handed to each scanner with its working directory, duration and exit code, cache hits, findings
  per control, and aggregation. And a new **`--log-level trace`** relays what the scanners
  themselves print — Draugr captures a tool's stderr and normally only summarises it, but that
  output is usually where the real explanation is.
- **A fuller example Saga, and the severity/level relationship documented.** `examples/draugr.saga.yaml`
  now shows what a real descriptor looks like — three components with different surfaces, risk
  classification, a pinned image digest, path-scoped repositories, a per-component control
  override, and references — since people copy an example rather than read a schema. The CLI
  reference now also explains the two scales that appear side by side: severity bands come from
  CVSS, `--fail-on` takes SARIF levels, and a table shows how they line up.
- **`draugr validate` now takes globs, or no arguments at all.** A repo can hold one Saga per
  service; validating them one command at a time didn't scale. `draugr validate` discovers every
  `*.saga.yaml` beneath the current directory, `draugr validate 'svc/*/*.saga.yaml'` expands a
  pattern, and every file is reported on its own line so one failure doesn't hide the rest. Exits
  non-zero if any file is invalid.

### Fixed

- **A misspelled tool name is now an error.** `draugr tools install trivvy` printed a plan with a
  row of dashes and then asked whether to continue; it now stops, lists what can be installed,
  and suggests the near-miss (`did you mean "trivy"?`). One bad name fails the whole command —
  half-installing after a typo is the surprising outcome.
- **`--min-priority` now works on every output, not just JSON.** It filtered the JSON report and
  was silently ignored by the console, Markdown, HTML and JUnit reporters — so on the default
  output the flag did nothing. The listing is filtered while the priority counts still describe
  the whole run, and the heading says what was hidden
  (`Fix first (P2 and above; 13 lower-priority finding(s) hidden):`) so a short list next to
  large counts isn't a puzzle.

## [0.33.0] - 2026-07-26

### Added

- **Your editor now understands a Saga.** Draugr publishes a
  [JSON Schema](https://draugr.dev/schema/draugr.saga.schema.json) for `*.saga.yaml`, so VS Code,
  JetBrains and Neovim complete control and field names, offer the valid `exposure`,
  `criticality` and report-format values, show what each field means on hover, and flag typos as
  you type instead of at scan time. `draugr init` writes the `# yaml-language-server: $schema=…`
  line for you; paste it into an existing Saga, or map `*.saga.yaml` once in your editor
  settings — see [editor support](https://draugr.dev/docs/latest/reference/saga-schema/).
- **Pin the schema to your Draugr version.** Every release publishes an immutable copy at
  `…/schema/vX.Y.Z/draugr.saga.schema.json`, and `draugr init` pins to its own version, so an
  editor validates against the same rules your installed binary applies. The unversioned URL
  still tracks the newest release.
- **`draugr schema`** prints the schema embedded in the binary (`-o` writes it to a file). It
  needs no network and cannot disagree with the build you're running — the option to reach for
  when you're offline, air-gapped, or want validation pinned exactly.

### Fixed

- **A typo in a Saga is now an error, not a shrug.** Unknown fields were silently ignored, so
  `repositores:` disabled a whole surface without a word — and your editor flagged it while the
  CLI accepted it, since the published schema was already strict. Both now agree:
  `unknown field "bogusField" in release`. Scanner options are unaffected:
  `controllers.<control>.<scanner>` stays free-form, validated against that scanner's own schema
  when the scan is planned.

### Changed

- **`tools install` skips tools that are already installed.** Re-running no longer re-downloads
  and re-verifies a tool that's already present at the pinned build — a repeat `install trivy`
  went from ~3s (162 MB re-download) to 0.08s, which adds up in CI where provisioning runs on
  every job. "Already present" means the exact bytes Draugr installed, compared by checksum, so
  a **modified binary is replaced rather than accepted**; a changed pin also reinstalls. Use
  `--force` to reinstall unconditionally.

## [0.32.0] - 2026-07-25

### Added

- **`draugr version --json`.** The same build metadata as a JSON object, so scripts and CI can
  read a field instead of regexing the prose line:
  `draugr version --json | jq -r .version`.

### Changed

- **Installing is simpler.** The install guide now leads with a four-line `curl` recipe that
  needs nothing but curl and resolves the latest release itself — previously it led with
  `gh release download`, which meant installing the GitHub CLI first. `gh` remains documented
  for those who have it.

## [0.31.1] - 2026-07-25

### Fixed

- **`draugr version` now prints to stdout** instead of stderr, so `v=$(draugr version)` captures
  it. It was using a Cobra helper that writes to stderr.

## [0.31.0] - 2026-07-25

### Added

- **New `tls` control — TLS and certificate assessment.** Point a component's `hosts:` at an
  endpoint and enable `tls` to catch the things that page you at 3am: a certificate that has
  expired or is about to (14/30-day warnings), one that isn't trusted or doesn't match the
  hostname, weak keys or SHA-1 signatures, and endpoints still accepting TLS 1.0/1.1 — or
  refusing TLS 1.2+ entirely. It's a **native probe**, so there's no tool to install and a scan
  takes seconds:

  ```yaml
  config:
    controllers:
      tls:
        enabled: true
  components:
    - name: web
      hosts:
        - url: https://api.example.com
  ```

  Certificate-expiry windows are tunable (`controllers.tls.tls-probe.expiryWarnDays` /
  `expiryErrorDays`) — useful for endpoints with automated renewal, where the default 30-day
  warning would otherwise trip a `--fail-on warning` gate during normal rotation.

  Deeper protocol auditing (SSLv2/v3, cipher enumeration, protocol vulns) via testssl.sh is
  planned as an opt-in engine.

### Fixed

- **`draugr controls` pointed at a removed setting.** Its footnote told you to enable an opt-in
  scanner via `controllers.<control>.scanners` — a list removed in 0.29.0. It now shows the
  current form, `controllers.<control>.<scanner>.enabled: true`.
- Config-validation errors no longer repeat the word "config"
  (`tls/web/tls-probe: config: unknown option "…"`).

## [0.30.0] - 2026-07-24

### Added

- **Pin the GitHub Action to `@v0`.** Releases now publish a moving major tag, so
  `uses: draugr-dev/draugr@v0` always gets the newest `v0.x` release — no more editing a pinned
  version to stay current. Pin an exact `@vX.Y.Z` when you want reproducible CI.
- **`scan --top N`.** Control how many findings the console "Fix first" table lists (default 10;
  `--top 0` shows all) — handy when you want the whole list in the terminal.
- **Contextual scan tips.** When a scan finds issues but no component sets `exposure`/`criticality`,
  Draugr now prints a one-line tip that priorities are using severity alone and suggests
  `draugr classify` to make P1–P4 risk-aware. Tips are advisory (never affect the verdict) and can
  be turned off with `--no-tips` or `DRAUGR_NO_TIPS`.

## [0.29.0] - 2026-07-24

### Added

- **Human-readable, colorized logs.** Draugr now logs in a compact, legible console format by
  default (`21:15:21 WARN  scan completed with issues error="…"`), with the level colorized when
  you're on a terminal. Piped or redirected output stays plain text, and `NO_COLOR` is honored.
  Structured logs are still one flag away — `--log-format json` — for CI and observability
  pipelines.
- **Clearer "Fix first" table.** The terminal scan summary now prints a column header and a
  **Scanner** column, so you can see at a glance which control *and* which scanner flagged each
  finding. The Markdown and HTML reports label that column **Scanner** too (previously "Tool"),
  for consistent vocabulary across every report.
- **Per-scanner config in the Saga.** You can now tune a scanner from
  `controllers.<control>.<scanner>`. The first option: point Semgrep at your own ruleset with
  `controllers.sast.semgrep.config` (a registry ref such as `p/owasp-top-ten`, or a path/URL to
  a rules file — defaults to `p/default`). Options are validated against each scanner's schema,
  so a mistyped key or wrong value type is reported before the scan runs, not silently ignored.

### Changed

- **SAST scanner selection moved to per-scanner blocks.** Enable a scanner under its own key
  with an `enabled` flag instead of listing names. Replace
  `sast: { scanners: [semgrep, gosec] }` with `sast: { gosec: { enabled: true } }` (Semgrep runs
  by default; add `semgrep: { enabled: false }` to turn it off). This unifies enablement and
  config in one place per scanner.
- **Removed** the `controllers.sast.scanners` list (superseded by per-scanner `enabled`). Sagas
  using it must migrate to the block form above.
- **Default log format is now `console`** (human-readable) instead of `json`. If you parse
  Draugr's logs in a pipeline, pass `--log-format json` to restore structured output.

## [0.28.0] - 2026-07-24

### Added

- **New `dast` control — dynamic application security testing.** Point a component's `hosts:`
  at a running (e.g. staging) endpoint and enable `dast` in your Saga to probe it for runtime
  issues static analysis can't see: exposures, misconfigurations, information disclosure,
  outdated libraries, default credentials. It's backed by [Nuclei](https://github.com/projectdiscovery/nuclei)
  — a single Go binary, so nothing to run in a container — and complements the `headers` control
  (which keeps ownership of HTTP security-header checks). Install it with
  `draugr tools install nuclei`; `dast` is opt-in, like every component control. It runs Nuclei's
  default (safe) template set — no active/attack scanning.

## [0.27.0] - 2026-07-20

### Added

- **Event-aware GitHub Action.** The first-party action has a new `mode` input (`auto` by
  default): on a **push** it runs a full scan and publishes to code scanning; on a **pull
  request** it scans the base and head and posts one **sticky new/fixed comment** — from a
  single workflow and a single Saga. Because code-scanning upload stays on push, PRs don't get a
  second, overlapping "GitHub Advanced Security" comment next to Draugr's own. New `fail-on-new`
  / `fail-on-new-priority` inputs gate a PR on the findings it introduces.
- **`draugr scan --no-publish`** runs a scan without triggering the Saga's configured
  publishers — it still writes `-o` artifacts and stdout. Used by the action's diff mode, and
  handy anywhere you want results without side effects (like a code-scanning upload).

## [0.26.1] - 2026-07-18

### Changed

- **Docs now use plain, standard terms.** The user docs describe the pass/fail step as
  **the gate** / **verdict** and the output step as **report** / **reporting**, instead of the
  internal code names — so the vocabulary reads clearly when you describe Draugr to others.
  No CLI, config, or file-format changes.

## [0.26.0] - 2026-07-18

### Changed

- **The human report now speaks severity bands (critical/high/medium/low), not SARIF levels.**
  The console/markdown/html per-control counts and the "fix first" list show severity — from the
  CVSS score when a scanner provides one, else derived from the finding's level. The gate
  (`--fail-on`) and machine formats (`json`/`sarif`) still use SARIF levels. See
  [Understanding the report](docs/concepts/verdict-and-gating.md#understanding-the-report).
- **Colored console output on a terminal.** The verdict, priorities, and severities are
  color-coded when stdout is a TTY; set `NO_COLOR` to disable. Piped/redirected output stays plain.

## [0.25.0] - 2026-07-17

### Added

- **Zero-config `draugr scan .`** — point `scan` at a directory (or omit the argument for the
  current one) and Draugr scans that repository with `sca`, `secrets`, `sast`, and `iac` — no Saga
  file required. The 60-second path from install to a verdict.
- **`draugr init`** — scaffold a `draugr.saga.yaml` for your project, detecting the stack (Go →
  gosec, a Dockerfile → an images stub, dependency manifests → SCA) so you start from a sensible,
  commented descriptor. `-o -` prints to stdout; `--force` overwrites.

## [0.24.1] - 2026-07-17

### Fixed

- **Finding messages are now repo-relative too**, not just locations. Some scanners (e.g. Gitleaks)
  embed the absolute checkout path in the message (`…detected secret for file /tmp/draugr-repo-…/x`).
  That leaked temp path is now stripped, so messages are clean and — because they no longer vary by
  the (per-scan) temp directory — `draugr diff` no longer reports an unchanged secret finding as
  both new and fixed (#197).

## [0.24.0] - 2026-07-17

### Added

- **The GitHub Action can provision the scanners itself** — set `tools: true` and the action runs
  `draugr tools install` (Trivy, Gitleaks, gosec) plus Semgrep via pipx before scanning, so a
  workflow needs no per-tool setup steps. Default `false` (unchanged for existing users). This
  makes the upcoming code-scanning **starter workflow** a simple checkout → Draugr → upload-sarif.

## [0.23.0] - 2026-07-17

### Added

- **`github-pr-comment` publisher + `draugr diff --publish`.** Post a security report — or a PR's
  **diff** (new / fixed findings) — as a **sticky pull-request comment** that updates in place on
  each push. `draugr diff base.sarif head.sarif --publish` renders the markdown delta and comments
  it on the PR; a Saga can also add `{ kind: github-pr-comment }` to `config.publishers`. Repo/PR
  come from the GitHub Actions environment and the token from `$GITHUB_TOKEN` (never the Saga); it
  no-ops off a pull request.

### Security

- Bumped `golang.org/x/net` (0.55.0 → 0.56.0) and `golang.org/x/text` (0.37.0 → 0.39.0) to clear
  CVE-2026-46600 and CVE-2026-56852 in transitive dependencies.

## [0.22.0] - 2026-07-17

### Added

- **The GitHub Action forwards `GITHUB_TOKEN` to the scan**, so a Saga's `github` publisher can
  upload SARIF to code scanning with no extra step (grant the job `security-events: write`). See
  `examples/github-actions-code-scanning.yml` and `examples/reporting.saga.yaml`.

### Changed

- **Code-scanning alerts now show which scanner found each issue.** Draugr's SARIF tags every
  rule with `scanner:<name>` (e.g. `scanner:semgrep`, `scanner:trivy`), so a GitHub code scanning
  alert surfaces the originating tool in its Tags — Draugr still reports as a single `Draugr` tool.
- **The `github` publisher no-ops outside GitHub Actions** (when no repo/commit/ref/token is
  resolvable) instead of erroring, so a Saga that publishes to code scanning in CI still runs
  cleanly on a developer's machine.

### Fixed

- **Repository-scan findings now use repo-relative paths.** `sast`/`secrets` findings previously
  carried absolute temp-checkout paths (`/tmp/draugr-repo-…/…`), which GitHub code scanning
  couldn't map to files (no PR annotations, unusable Security-tab entries). Paths are now rewritten
  to be repo-relative.

## [0.21.0] - 2026-07-17

### Added

- **`template` report format — custom payloads with no code.** `--format template` (or a
  `config.reports` entry) renders a [Go `text/template`](https://pkg.go.dev/text/template) against
  a stable view of the scan (`.Verdict`, `.Priorities`, `.Controls`, `.Findings`, …) — for a
  bespoke summary line, a Slack payload, or any custom text. Supply it inline (`--template` /
  `template:`) or from a file (`--template-file` / `templateFile:`).
- **Report publishers — declarative, multi-format, multi-destination output.** A Saga can now
  declare `config.reports` (which formats to render) and `config.publishers` (where to deliver
  them); a scan renders each report once and delivers all of them to every publisher. Reports are
  delivered even when the gate fails, so you always get evidence. Built-in publishers:
  - **`file`** — writes each report to a directory.
  - **`github`** — uploads the `sarif` report to GitHub **code scanning** (the Security tab).
    Repo/commit/ref default to the GitHub Actions environment; the token is read from
    `$GITHUB_TOKEN` (or a `tokenEnv` you name) and never stored in the Saga.

  This completes the pluggable reporting model (#58): pick any report formats and deliver them
  anywhere, no code required.

```yaml
config:
  reports:    [ { format: sarif }, { format: markdown }, { format: html } ]
  publishers: [ { kind: file, dir: ./out } ]
```

## [0.20.0] - 2026-07-17

### Added

- **`draugr diff <base.sarif> <head.sarif>`** — compare two scans and classify every finding as
  **new / fixed / unchanged**, with a delta by severity and priority. The headline use case is a
  PR's security impact vs its base branch. Adds a **differential gate** (`--fail-on-new` /
  `--fail-on-new-priority`) that fails a build only for findings the change *introduces*, not the
  pre-existing backlog — so gating stays adoptable. Renders as `console`, `markdown` (a ready-made
  MR comment), or `json`. Findings are matched line-insensitively, so carried-over findings that
  merely moved lines aren't reported as fixed + new.
- **Two more `draugr scan --format` outputs.** `html` renders a self-contained, browser-viewable
  report (inline CSS, no assets) you can publish as a build artifact; `junit` emits JUnit XML so
  CI systems (GitLab, Jenkins, Azure DevOps…) surface findings in their native test-results panel
  — one `<testsuite>` per control, one failing `<testcase>` per finding. Both plug into the same
  Reporter interface as `console`/`markdown`/`json`/`sarif`.

## [0.19.0] - 2026-07-16

### Added

- **Human-readable report formats, independent of GitHub/ADO.** `draugr scan --format` selects
  the stdout format: **`console`** (a grouped summary — verdict, P1–P4 counts, "fix first"),
  **`markdown`** (portable for GitLab/Bitbucket MR comments, wikis, Slack), plus `json` and
  `sarif`. Built on a new pluggable **Reporter** interface (first slice of #58).

### Changed

- **`draugr scan` now prints the console summary by default** instead of raw JSON — the common
  interactive/CI-log case is now readable at a glance. Use `--format json` (or `--output` for
  `report.json` + `results.sarif`) for machine consumption. `--output` is unchanged.

## [0.18.0] - 2026-07-16

### Added

- **`draugr controls`** — list the security controls Draugr can run: what each checks, its
  scope, and which scanner(s) implement it (default, plus opt-in alternatives like gosec marked
  `*`). Makes it easy to see what Draugr covers and how to enable each control.
- **`draugr tools list` now shows a CONTROLS column** — which control(s) each tool backs (e.g.
  `trivy` → `images,sca,iac`), so it's clear why a given scanner matters. `controls` maps
  control → scanners; `tools list` maps tool → controls.

## [0.17.0] - 2026-07-16

### Added

- **`draugr self-update`** — update the running binary in place to the latest release (or a
  pinned `--version`), verified against the release's SHA-256 checksums and, when the `cosign`
  CLI is present, its keyless signature. `--check` reports current vs latest without changing
  anything; `-y` skips the prompt. Because it replaces the binary you're actually running, it
  avoids the stale-copy/PATH confusion of having draugr installed in two places. (CI should
  still pin a release.)
- **`draugr doctor` now reports your Draugr version vs the latest available** (best-effort,
  short timeout), nudging `self-update` when you're behind. Opt out with `--offline` or
  `DRAUGR_NO_UPDATE_CHECK=1`; it never blocks or fails the command.
- **`draugr tools install` shows an install plan and confirms interactively.** It prints the
  plan first — tool, version, **category**, verification, destination — and asks for
  confirmation on a TTY (`-y` to skip, `--dry-run` to only preview); CI/pipes proceed
  automatically.
- **cosign is now installable** (`draugr tools install cosign`) — a pinned, SHA-256-verified
  utility. It's what Draugr uses to verify other tools' and its own releases' provenance, so
  making it installable lets signature verification "just work" without hunting for it. Optional:
  `doctor` reports it but never fails when absent.
- **`draugr tools list` gained a CATEGORY column** (scanner vs utility).

### Changed

- **`draugr self-update` now prompts only when interactive** (consistent with `tools install`):
  a TTY gets the prompt; CI/pipes proceed automatically. `-y` still skips it.

## [0.16.0] - 2026-07-16

### Added

- **`draugr scan -j/--jobs N`** — cap how many scan jobs run in parallel (`0` = auto, one per
  CPU; `1` = serial). Scanners like Trivy and Semgrep are themselves multi-threaded, so on a
  small or busy machine the default can oversubscribe and slow a run down — `-j` lets you dial
  it in (down on a laptop, up on a big CI runner). The run's JSON `stats` now also reports the
  effective **`concurrency`** and the **`deduped`** count (identical jobs collapsed in-run), so
  you can see the effect and tune from evidence.

## [0.15.0] - 2026-07-16

### Added

- **SLSA build provenance for releases.** Each release now publishes signed **build provenance
  attestations** for its archives and `checksums.txt` (GitHub `attest-build-provenance`), so you
  can verify *where and how* a binary was built:
  `gh attestation verify draugr_<ver>_<os>_<arch>.tar.gz --repo draugr-dev/draugr`. This is on
  top of the existing cosign-signed checksums and SBOMs.

## [0.14.0] - 2026-07-16

### Added

- **gosec as a second `sast` scanner.** The `sast` control can now run **gosec** — a
  Go-specialized static analyzer — alongside (or instead of) Semgrep. Select the scanner set
  with `controllers.sast.scanners: [semgrep, gosec]` (default `[semgrep]`); it works at the
  project level or as a per-component override, so you can enable gosec just on your Go
  components. `draugr tools install gosec` provisions a pinned, SHA-256-verified binary, and
  `draugr doctor` knows about it. gosec is Go-only (it errors on non-Go repos), which is why
  it's opt-in.

## [0.13.0] - 2026-07-15

### Changed

- **Releases now sign with the modern Sigstore bundle.** The release's `checksums.txt` is
  signed with keyless cosign into a single `checksums.txt.sigstore.json` bundle (via
  cosign-installer v4), replacing the separate `checksums.txt.sig` + `.pem` files. Verify with
  `cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp … …`.
  The self-scan, the GitHub Action, and the docs verify the new bundle; the install/quickstart
  recipes are updated accordingly.

### Added

- **`draugr tools install` now verifies upstream cosign signatures** (where the upstream
  publishes them), on top of the mandatory SHA-256 pin. For Trivy, Draugr verifies the keyless
  signature over the release's checksums file — checking the signing certificate identity and
  OIDC issuer via the `cosign` CLI, then confirming the downloaded archive is listed in the
  signed checksums — giving signed provenance, not just integrity. It degrades gracefully to
  SHA-256-only (with a note) when `cosign` isn't installed or the upstream isn't signed (e.g.
  gitleaks); if `cosign` is present but verification fails, the install aborts. Each installed
  tool reports what was verified.

## [0.12.1] - 2026-07-15

### Changed

- **Action metadata for the GitHub Marketplace.** Renamed the action to
  **Draugr Security Scan** (a Marketplace name must be unique across all actions/users/orgs)
  and shortened its description to meet the 125-character limit. No behavior or input change —
  `uses: draugr-dev/draugr@…` is unchanged.

## [0.12.0] - 2026-07-15

### Added

- **First-party GitHub Action.** Add Draugr to CI and GitHub code scanning with
  `uses: draugr-dev/draugr@vX.Y.Z` — it downloads a cosign-verified Draugr release for the
  runner, runs `draugr scan` against your Saga, and exposes the merged SARIF (`sarif` output)
  for `upload-sarif`, so findings land as one clean **Draugr** tool in the Security tab.
  Inputs cover `saga`, `version`, `fail-on`, `fail-on-priority`, `min-priority`, `cache-dir`,
  `output`, `working-directory`, and a raw-`args` escape hatch; the release signature is
  cosign-verified by default. Draugr's own self-scan now dogfoods this action.

## [0.11.0] - 2026-07-15

### Added

- **Content-addressed image caching.** A container image can now carry an immutable
  `digest:` alongside its `image:` tag in the Saga. With `--cache-dir`, results are keyed on
  the digest, so a rebuilt image pushed under the same tag re-scans immediately instead of
  serving the old result until the TTL. The `k8s-images` surveyor captures the running
  digest of each image automatically; you can also pin `digest:` by hand. When a digest is
  set, Draugr scans the digest-pinned reference (`repo:tag@sha256:…`) so the bytes scanned
  match what the result is cached under, while the readable tag is kept in the report.

### Changed

- **Faster high-volume scanning.** Before the concurrent scan fan-out, Draugr now pre-warms
  shared scanner state once — for Trivy, it downloads the vulnerability DB a single time
  (`trivy image --download-db-only`) instead of every parallel process cold-starting it. And
  identical jobs within a run (the same scanner + target + config, e.g. one image referenced by
  two components) are de-duplicated so the target is scanned once and the result shared. Run
  stats now report `deduped` alongside `scans` and `cacheHits`.

## [0.10.0] - 2026-07-15

### Changed

- **SARIF now reports as a single `Draugr` tool.** Draugr is an orchestrator that normalizes many
  scanners into one report, so its SARIF is emitted as one `Draugr` run instead of one run per
  underlying scanner — each finding keeps its originating scanner in `properties.tool`. In GitHub
  code scanning this shows a single "Draugr" analysis/check rather than separate "Trivy",
  "Semgrep OSS", … checks, with per-finding attribution preserved.
- **Result cache now invalidates when Trivy's vulnerability DB updates.** With `--cache-dir`,
  cached image/dependency/IaC results were keyed without the scanner or DB version, so a new
  Trivy DB (new CVEs) wouldn't trigger a re-scan until the TTL expired. The cache key now folds
  in the Trivy tool and vuln-DB version, so a DB refresh correctly invalidates stale results.
  The version is probed once per run and only when caching is enabled (no overhead otherwise).

## [0.9.0] - 2026-07-14

### Added

- **`headers` control** — a native HTTP security-header analyzer (no external tool) for a
  component's `hosts:`. Fetches each endpoint and checks it against the OWASP Secure Headers
  guidance — HSTS, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, wildcard CORS, and `Server`/`X-Powered-By`
  disclosure — normalized to SARIF like every other control. The checklist is tuned by each
  host's `type` (`browser` — the default — vs. `api`), so browser-only headers aren't flagged
  on APIs. The host `type` values are now **`browser` | `api`** (was `web` | `api`).

## [0.8.0] - 2026-07-14

### Added

- **`draugr tools install`** — fetch pinned, **checksum-verified** scanner binaries (`trivy`,
  `gitleaks`) into a Draugr-managed `~/.draugr/bin`, which Draugr adds to `PATH` automatically so
  `scan` and `doctor` use them with no shell config. Opt-in and explicit — nothing is ever
  downloaded during a scan, and every download is verified against a SHA-256 recorded in Draugr
  before it's placed on disk. Semgrep (a Python package) prints its pinned `pipx` command instead.
  `draugr tools list` shows what's pinned and what's installed.

## [0.7.0] - 2026-07-14

### Added

- **`draugr doctor`** — a preflight that reports which external scanner tools are present,
  missing, or of what version, with an install hint for each, so a missing tool is caught up
  front instead of failing mid-scan. Given a Saga it validates the descriptor and checks only
  the tools its enabled controls need (plus `git` for repo scans); `--json` for CI. Exits
  non-zero when the descriptor is invalid or a required tool is missing, so it gates a
  pipeline: `draugr doctor saga.yaml && draugr scan saga.yaml`. It only reports — it never
  downloads anything.
- **`draugr validate <saga.yaml>`** — check a Saga against the schema without running any
  scanners. Fast and dependency-free, for a pre-commit hook, CI lint step, or editor.
- **Exploitability enrichment** — `draugr scan --kev <file>` escalates any finding whose CVE
  is on the CISA Known Exploited Vulnerabilities catalog to critical, and `--epss <file>`
  (with `--epss-threshold`) bumps CVEs the FIRST EPSS model predicts are likely to be
  exploited. Both are optional and offline (bring your own downloaded feed), so priority
  reflects real-world exploitability, not just CVSS.
- The **`k8s-images` surveyor now proposes a component's `exposure`** from namespace topology
  when surveying a specific namespace — an Ingress or externally-reachable Service →
  `public`, a NetworkPolicy → `restricted`, otherwise `internal`. It's a suggestion to review
  (authentication can't be inferred; downgrade to `authenticated` where appropriate).

### Changed

- **Clearer descriptor errors.** When `scan`, `classify`, or `survey` hit an invalid Saga they
  now say which file is bad, list every problem at once, and point you at
  `draugr validate <file>` — instead of a bare, context-free validation message.

## [0.6.0] - 2026-07-13

### Added

- **`draugr classify`** — a guided wizard that asks a few questions about each component and
  writes its `exposure` and `criticality` back into the Saga (comments and formatting
  preserved). The easy way to set up prioritization without hand-editing the descriptor.

### Changed

- **Breaking:** component risk classification now uses readable labels instead of codes —
  `exposure: public | authenticated | internal | restricted` and
  `criticality: critical | important | supporting` (was `re1`–`re4` / `bc1`–`bc3`). They're
  self-documenting in the descriptor and reports. Pre-1.0 change — update any descriptors
  that used the old codes.

## [0.5.0] - 2026-07-13

### Added

- **Finding prioritization** — declare a component's `exposure` and `criticality` and Draugr
  ranks every finding into a priority band (P1–P4) by combining its severity with how exposed
  and how business-critical its component is. The report includes `priorities` counts, and
  `draugr scan --min-priority P2` lists just the findings worth acting on now. Unclassified
  components are treated as high-risk so nothing slips.
- **Priority gating** — `draugr scan --fail-on-priority P1` fails the gate on any finding at
  or above a priority band. Because priority already folds in a component's exposure and
  criticality, this gates per component without per-component config; it composes with
  `--fail-on` (the run fails if either trips).

### Changed

- Merged SARIF output now preserves each finding's numeric **`security-severity`** score
  (read from the scanner and re-emitted), so GitHub / GitLab / Azure DevOps rank Draugr's
  findings by their real CVSS-style severity instead of a coarse pass/fail level.

## [0.4.0] - 2026-07-12

### Added

- **IaC scanning** (`iac` control, via [Trivy](https://trivy.dev) config mode): scans a
  component's repositories for insecure Infrastructure as Code — Terraform, Kubernetes
  manifests, Dockerfiles, Helm, and more. Requires `trivy` on your `PATH`.

### Fixed

- In-source scanner suppressions are now honored: results a scanner marks as suppressed
  (e.g. Semgrep `// nosem` comments) are dropped instead of counted, so intentional,
  justified exceptions no longer fail the gate.

## [0.3.0] - 2026-07-11

### Added

- **Static analysis** (`sast` control, via [Semgrep](https://semgrep.dev)): scans a
  component's repositories for security bugs in your own source code (injection, unsafe APIs,
  and more). Requires `semgrep` on your `PATH`.

### Fixed

- SARIF results that omit a severity level now inherit it from the rule definition (per the
  SARIF spec), so Semgrep's error-level findings are correctly reported as errors and fail
  the gate — instead of all being downgraded to warnings.

## [0.2.0] - 2026-07-11

### Added

- **Secret detection** (`secrets` control, via [Gitleaks](https://github.com/gitleaks/gitleaks)):
  scans a component's repositories for leaked credentials — API keys, tokens, private keys.
  Any detected secret **fails the gate** regardless of how the scanner rated it. Requires
  `gitleaks` on your `PATH`.

### Changed

- The **self-scan** CI now dogfoods the **latest** Draugr release automatically (no pinned
  version), so new controls take effect as soon as they ship.

## [0.1.0] - 2026-07-11

First public preview of Draugr.

### Highlights

- **Describe your app, scan it, get a verdict.** Write a `draugr.saga.yaml`, run
  `draugr scan`, and get pass/fail evidence as JSON + SARIF.
- **Container image scanning** (`images`, via Trivy) and **dependency scanning / SCA**
  (`sca`, via Trivy) work out of the box.
- **Discovery — "the Ravens":** `draugr survey` writes the descriptor for you from a
  Kubernetes cluster or a GitHub organization.
- **Cheap at scale:** content-hash caching means unchanged components are never re-scanned.
- **CI-ready:** exits non-zero on a failing verdict, and results are SARIF, so they flow
  straight into GitHub / GitLab / Azure DevOps security dashboards.

### Added

- Commands: `draugr scan`, `draugr survey`, `draugr version`.
- Controls: `images`, `sca`. Scanners: `trivy`, `trivy-fs`. Surveyors: `k8s-images`,
  `github-org-repos`.
- Policy gate with `--fail-on`; JSON + merged SARIF reports (`--output`).
- Content-hash caching (`--cache-dir`); structured logs and opt-in OpenTelemetry.

### Notes

- **Early preview** — the CLI and the Saga schema may change before 1.0.
- Requires **Trivy** on your `PATH` (and `git` for repository scans).

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.45.0...HEAD
[0.45.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.45.0
[0.44.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.44.0
[0.43.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.43.0
[0.42.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.42.0
[0.41.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.41.0
[0.40.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.40.1
[0.40.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.40.0
[0.39.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.39.0
[0.38.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.38.0
[0.37.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.37.0
[0.36.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.36.1
[0.36.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.36.0
[0.35.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.35.0
[0.34.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.34.0
[0.33.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.33.0
[0.32.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.32.0
[0.31.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.31.1
[0.31.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.31.0
[0.30.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.30.0
[0.29.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.29.0
[0.28.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.28.0
[0.27.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.27.0
[0.26.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.26.1
[0.26.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.26.0
[0.25.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.25.0
[0.24.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.24.1
[0.24.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.24.0
[0.23.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.23.0
[0.22.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.22.0
[0.21.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.21.0
[0.20.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.20.0
[0.19.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.19.0
[0.18.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.18.0
[0.17.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.17.0
[0.16.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.16.0
[0.15.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.15.0
[0.14.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.14.0
[0.13.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.13.0
[0.12.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.12.1
[0.12.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.12.0
[0.11.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.11.0
[0.10.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.10.0
[0.9.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.9.0
[0.8.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.8.0
[0.7.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.7.0
[0.6.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.6.0
[0.5.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.5.0
[0.4.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.4.0
[0.3.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.3.0
[0.2.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.2.0
[0.1.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.1.0
