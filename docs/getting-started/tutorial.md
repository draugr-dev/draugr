---
title: Tutorial
description: From installing Draugr to gating pull requests, on the demo repository, with what each step prints.
section: Getting started
order: 30
---

# From install to gated pull requests

This tutorial runs Draugr on [draugr-demo](https://github.com/draugr-dev/draugr-demo), a deliberately
vulnerable shop, in four steps:

1. install Draugr and scan the demo with nothing declared;
2. declare what each part of the demo is, scan again, and compare the two runs;
3. open one finding in the HTML report;
4. see how the demo's CI gates a pull request and keeps issues open.

Every block of output comes from Draugr 0.182.0 on demo commit `bb729745`, run on 2026-11-20. A
newer release or commit prints different counts, and so can a later day, because the scanners read
advisory databases that change over time. A line reading `…` stands for lines cut from the output.

**Contents:** [Install and scan](#1-install-and-scan-with-nothing-declared) ·
[Declare the components](#2-declare-what-each-part-is) · [HTML report](#3-read-one-finding-in-the-html-report) ·
[Pull requests and issues](#4-gate-pull-requests-and-file-issues)

## 1. Install and scan with nothing declared

Install Draugr 0.182.0 into `~/.local/bin`, which [install](install.md) covers in full, and check
the version.

```console
$ curl -fsSL https://draugr.dev/install.sh | DRAUGR_VERSION=v0.182.0 sh
…
$ draugr version
draugr 0.182.0 (commit 56f18e91, built 2026-11-17T16:57:39Z, go1.27.4)
```

Clone the demo at the commit this page was written against.

```bash
git clone https://github.com/draugr-dev/draugr-demo
cd draugr-demo
git checkout bb729745becb4825ba9d3123c98ebb2ada5ce038
```

The demo carries a descriptor, `draugr.saga.yaml`, that says what each part of the shop is. Move it
aside to see what Draugr makes of a repository nobody has described, then install the scanners a
scan of it runs.

```bash
mv draugr.saga.yaml draugr.saga.yaml.aside
draugr tools install
```

`draugr tools install` prints the scanners it will fetch, then installs each into `~/.draugr/bin`,
pinned and checksum-verified. Two of them need a language runtime already on the machine, because
govulncheck is built with Go and retire.js runs on Node 18 or newer with npm. Without Go or Node,
the install leaves that scanner out and names what to install, and the scan runs without it. With no
govulncheck, SIGNALS has no reachability row, so nothing lowers the Go findings it would have found
unreachable. With no retire.js, nothing checks the copied jQuery files, and CAVEATS names the scanner
that could not run.

Now scan the demo.

```console
$ draugr scan .
…
DRAUGR  FAIL  draugr-demo  5.344s

 37 P1 28 P2 18 P3 0 P4
 No component declares exposure or criticality, so every one is read as public and critical.
 These bands rank severity alone. `draugr classify` makes them describe this application.

CONTROLS
  iac      FAIL   4 P1 5 P2 12 P3
  sast     FAIL   14 P1 6 P2 5 P3 · 2 files unread
  sca      FAIL   18 P1 17 P2 1 P3
  secrets  FAIL   1 P1
…
SIGNALS
  KEV           not read · --kev auto reads it
  EPSS          not read · --epss auto reads it
  floor         nothing raised
  reachability  govulncheck · 2 reachable, 3 unreachable
…
draugr: policy verdict: fail
```

Three parts of the output say how much the scan knew:

- **No component declares exposure or criticality.** Draugr reads every finding as if it sat on a
  public, critical service, so the P1 to P4 bands follow the scanners' severity alone.
- **`FOUND`**, cut above because its rows are wider than this page, lists each kind of file the
  scan read and the scanners it turned on for it, such as sca, gosec and govulncheck for
  `checkout/go.mod`. Its rows for the Dockerfile and the SARIF files end `images off` and
  `imports off`, which a descriptor could turn on, and `draugr init` writes all of it into one.
- **`KEV` and `EPSS` were not read.** KEV is CISA's catalog of flaws being exploited, and EPSS a daily
  estimate of how likely a flaw is to be exploited in the next 30 days. A scan reads them only when
  asked.

The last line is the verdict, and the command exits non-zero, so it fails a pipeline on its own. The
[quickstart](quickstart.md#2-scan) reads every section of this report.

## 2. Declare what each part is

Put the descriptor back. It turns on more controls than the tree alone suggests, so install what it
adds, cosign and Syft here, and fetch the exploitation data it ranks with.

```bash
mv draugr.saga.yaml.aside draugr.saga.yaml
draugr tools install
draugr feeds update
```

The descriptor sets `kev: cache` and `epss: cache`, which read the copy `draugr feeds update` keeps
in `~/.draugr/feeds`, and a scan with nothing cached stops and names that command.

The demo has four components. `api` and `storefront` are the shop's public services, `worker` is a
nightly job behind the firewall, and `platform` holds the Kubernetes manifests. The first three are
declared in `draugr.saga.yaml`, and `platform` in `.draugr/components/platform.saga-fragment.yaml`,
a fragment the platform team owns. Here are their declarations from both files, with every other
line cut.

```yaml
components:
  - name: api
    exposure: public
    criticality: important
  - name: storefront
    exposure: public
    criticality: important
  - name: worker
    exposure: internal
    criticality: supporting
  - name: platform
    exposure: internal
    criticality: supporting
```

`exposure` is how reachable the component is, and `criticality` is the business impact if it fails.
[Prioritization](../concepts/prioritization.md#matrices) crosses the two into a tier and the tier
with severity into the band.

### Scan without the declarations

To see what the declarations change, delete them and scan. `sed` keeps a copy of each file it edits,
ending `.bak`.

```bash
sed -i.bak -e '/^ *exposure:/d' -e '/^ *criticality:/d' \
  draugr.saga.yaml .draugr/components/platform.saga-fragment.yaml
```

```console
$ draugr scan --no-publish --report sarif -o before
…
DRAUGR  FAIL  draugr-demo 1.0  14.087s

 275 P1 712 P2 272 P3 0 P4
 No component declares exposure or criticality, so every one is read as public and critical.
 These bands rank severity alone. `draugr classify` makes them describe this application.
…
COMPONENTS
  api         ERROR  260 P1 702 P2 261 P3
  platform    FAIL   3 P1 7 P2 11 P3
  storefront  ERROR  8 P1 1 P2
  worker      FAIL   4 P1 2 P2
…
```

A scan reads the descriptor and its fragments from disk, so the edit counts without a commit.
`--no-publish` leaves out the demo's publishers, which write into `.draugr/out` and deliver to
GitHub, and `--report sarif -o before` writes the findings to `before/results.sarif`.

### Scan with them

Restore both files from the copies `sed` kept, and scan again.

```bash
mv draugr.saga.yaml.bak draugr.saga.yaml
mv .draugr/components/platform.saga-fragment.yaml.bak .draugr/components/platform.saga-fragment.yaml
```

```console
$ draugr scan --no-publish --report sarif -o after --top 1
…
DRAUGR  FAIL  draugr-demo 1.0  13.663s

 268 P1 704 P2 267 P3 20 P4
…
COMPONENTS
  api         ERROR  260 P1 702 P2 261 P3
  storefront  ERROR  8 P1 1 P2
  platform    pass   3 P3 18 P4
  worker      pass   1 P2 3 P3 2 P4

SIGNALS
  KEV           2 findings listed · 2 raised
  EPSS          3 findings raised
  malicious     nothing raised
  deprecated    12 findings raised
  floor         nothing raised
  reachability  govulncheck · 2 reachable, 3 unreachable
…
FIX FIRST  1 of 1259 findings, by priority
  P1  critical  CVE-2020-11023
      Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
      ↑ KEV · scanner trivy · jquery 1.8.3 → 3.5.0
      web/package-lock.json:12 · and 1 more · also found by retirejs
…
```

- **`COMPONENTS`** now gives `worker` and `platform` a pass, with nothing at P1. They hold the same
  findings as before, ranked lower because both are declared internal and supporting. `api` and
  `storefront` end in `ERROR` because the demo's descriptor fails the run when a scanner leaves a
  file unread ([`config.gate.failOnCaveats`](../reference/saga-schema.md#configgate)), and the
  CAVEATS section names those files.
- **`↑ KEV`** marks a finding raised to critical because it is on CISA's Known Exploited
  Vulnerabilities catalog. SIGNALS counts two such findings, the same jQuery 1.8.3 flaw in the
  storefront's lockfile, shown here, and in a copy the api serves.
  [Signals](../concepts/prioritization.md#signals) lists every mark.

`--top 1` keeps the list to its first row.

### Compare the two runs

`draugr diff` pairs the findings of two scans and reports what changed between them.

```console
$ draugr diff before/results.sarif after/results.sarif
DRAUGR DIFF  pass  27 reranked (27 lowered)  1234 unchanged

 reranked        0 P1 1 P2 6 P3 20 P4
 unchanged       268 P1 703 P2 261 P3 0 P4
 still accepted  2 P1 0 P2 0 P3 0 P4

Gate: fails on any P1 this change introduces.

Nothing is new or fixed. Only priorities changed.

RERANKED  27 · 27 lowered
  Priority  Severity  Rule                                                                                      Scanner      Component  Location
  P1 → P2   critical  CVE-2026-4800                                                                             trivy        worker     worker/package-lock.json:73
            Arbitrary code execution via untrusted input in template imports
  P1 → P3   high      CVE-2025-13465                                                                            trivy        worker     worker/package-lock.json:73
            prototype pollution in _.unset and _.omit functions
  P1 → P3   high      KSV-0014                                                                                  Trivy        platform   deploy/pod.yaml:8
            Root file system is not read-only
…
  P1 → P3   high      CVE-2021-23337                                                                            trivy        worker     worker/package-lock.json:73
            nodejs-lodash: command injection via template
  P1 → P3   high      javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret                        Semgrep OSS  worker     worker/reconcile.js:33
            A hard-coded credential was detected. It is not recommended to store credentials in source-code…
…
  P2 → P4   medium    CVE-2020-28500                                                                            trivy        worker     worker/package-lock.json:73
            nodejs-lodash: ReDoS via the toNumber, trim and trimEnd functions
  P2 → P4   medium    javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell                Semgrep OSS  worker     worker/reconcile.js:54
            Detected non-literal calls to spawn(). This could lead to a command injection vulnerability.
…
```

Every finding is in both runs, so the declarations moved bands and fixed nothing. The worker's
critical lodash flaw went from P1 to P2, its highs to P3 and its mediums to P4. The rows cut here are
the platform's Kubernetes findings, which moved the same way. Both runs read KEV and EPSS, so the
diff shows only what the declarations did. [Reranked
findings](../guides/pr-diff.md#reranked-findings) covers the table, and [classify
components](../guides/classify-components.md) helps you choose the two values for your own
application.

## 3. Read one finding in the HTML report

Write the report as one HTML file.

```console
$ draugr scan --no-publish --report html -o out
…
REPORTS
  out/report.html  every finding, searchable and filtered by component
…
```

Open `out/report.html` in a browser. It loads nothing from the network.
[Read a finding in the HTML report](../guides/reading-the-html-report.md) follows the KEV-raised
jQuery flaw through it, from where it ranks to what to change.

## 4. Gate pull requests and file issues

Nothing in this step runs on your machine. It reads what the demo's CI does on GitHub, in
`.github/workflows/draugr.yml`. Here it is with its comments cut, and `# …` where lines are cut.

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  # …
permissions:
  contents: read
  security-events: write
  issues: write
  pull-requests: write
jobs:
  draugr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      # … installs Go and govulncheck
      - name: Draugr
        id: draugr
        # …
        uses: draugr-dev/draugr@v0
        with:
          saga: draugr.saga.yaml
          version: latest
          tools: true
          feeds: true
          code-scanning: new
          # …
```

On a push to `main` the action scans the whole tree and uploads the findings to code scanning. On a
pull request it scans the pull request's base and its head, compares them as `draugr diff` did in
step 2, and posts the result as one comment, which it edits on each push. The descriptor's
`config.gate.failOnNew: P1` fails the check on a P1 the pull request adds, and the backlog it
inherits decides nothing. [Use in CI with the GitHub Action](../guides/github-action.md) lists every
input.

[Pull request 37](https://github.com/draugr-dev/draugr-demo/pull/37) fails that gate by design. It
adds urllib3 2.0.7 to `app/requirements.txt`, which brings six new P1 findings, and its comment lists
each one with the upgrade that clears it.

The same descriptor keeps an issue open while part of the gate fails on `main`. This entry covers the
storefront, the component labeled `team: web`.

```yaml
config:
  publishers:
    - kind: github-issue
      select:
        labels: { team: web }
      item:
        labels: ["team:web"]
```

A run on `main` opens the issue when the storefront fails, rewrites it when its findings change and
closes it when the storefront passes, and a pull-request run leaves it alone. The workflow grants
`issues: write` for it. [GitHub issues](../guides/reports-and-publishers.md#github-issues) covers
every field, and the same page has the GitLab and Azure DevOps equivalents.

## Next

- [Write your first Saga](first-saga.md) describes your own application.
- [Gate PRs on new findings](../guides/pr-diff.md) runs the comparison from step 2 in any CI system.
- [What to fix first](../concepts/what-to-fix-first.md) turns findings into a list of changes.
