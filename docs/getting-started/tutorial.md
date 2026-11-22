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
2. declare what each part of the demo is, and compare a scan with those declarations to one without;
3. open one finding in the HTML report;
4. see how a pull request is gated, and run the same gate on your machine.

Every block of output comes from Draugr 0.185.0 on demo commit `bb729745`, run on 2026-11-22. A
newer release or commit prints different counts, and so can a later day, because the scanners read
advisory databases that change over time. A line reading `…` stands for lines cut from the output.

**Contents:** [Scan with nothing declared](#1-scan-with-nothing-declared) ·
[Declare what each part is](#2-declare-what-each-part-is) · [Read a finding](#3-read-a-finding) ·
[Gate pull requests](#4-gate-pull-requests)

## 1. Scan with nothing declared

Install Draugr 0.185.0 into `~/.local/bin`, which [install](install.md) covers in full, and check
the version.

```console
$ curl -fsSL https://draugr.dev/install.sh | DRAUGR_VERSION=v0.185.0 sh
…
$ draugr version
draugr 0.185.0 (commit …)
```

Clone the demo at the commit this page was written against.

```bash
git clone https://github.com/draugr-dev/draugr-demo
cd draugr-demo
git checkout bb729745becb4825ba9d3123c98ebb2ada5ce038
```

The demo carries a descriptor, `draugr.saga.yaml`, that says what each part of the shop is. Move it
aside to see what Draugr makes of a repository nobody has described, and check that it moved.

```console
$ mv draugr.saga.yaml draugr.saga.yaml.aside
$ git status --short
 D draugr.saga.yaml
?? draugr.saga.yaml.aside
```

Install the scanners a scan of this tree runs. `--yes` installs them without asking first.

```bash
draugr tools install --yes
```

Two scanners need Go or Node.js on the machine. If either is missing, the install names what to add
and the scan runs without that scanner. Without cosign on the machine, trivy's line says it skipped
its signature check. The download is still checked against the SHA-256 digest this release of Draugr
pins, and step 2 installs cosign.

The demo is deliberately vulnerable, so this scan fails. That is the expected result.

```console
$ draugr scan .
…
DRAUGR  FAIL  draugr-demo  18.801s

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

Two parts of the output say how much the scan knew:

- **No component declares exposure or criticality.** Draugr reads every finding as if it sat on a
  public, critical service, so the P1 to P4 bands follow the scanners' severity alone. Step 2
  declares them.
- **`KEV` and `EPSS` were not read.** They are the [signals](../concepts/prioritization.md#signals)
  that raise a flaw being exploited, or likely to be, and a scan reads them only when asked.

The last line is the verdict, and the command exits non-zero, so it fails a pipeline on its own. The
[quickstart](quickstart.md#2-scan) reads every section of this report.

## 2. Declare what each part is

Declaring what each part of an application is changes how its findings rank, and fixes nothing.
This step scans the demo twice, once with those declarations removed and once with them, and
compares the runs.

Put the descriptor back. It turns on more controls than the tree alone suggests, so install what it
adds, cosign and Syft here, and fetch the exploitation data it ranks with.

```bash
mv draugr.saga.yaml.aside draugr.saga.yaml
draugr tools install --yes
draugr feeds update
```

The descriptor sets `kev: cache` and `epss: cache`, which read the copy `draugr feeds update` keeps
in `~/.draugr/feeds`, and a scan with nothing cached stops and names that command.

`api` and `storefront` are the shop's public services, `worker` is a nightly job behind the
firewall, and `platform` holds the Kubernetes manifests. The first three are declared in
`draugr.saga.yaml`, and `platform` in `.draugr/components/platform.saga-fragment.yaml`, a fragment
the platform team owns. Here are their declarations from both files, with every other line cut.

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

[Prioritization](../concepts/prioritization.md#matrices) says what each value means and how the two
combine with a finding's severity into its band.

### Without the declarations

Delete the declarations. `sed` keeps a copy of each file it edits, ending `.bak`, and `git status`
shows the two edits and the two copies.

```console
$ sed -i.bak -e '/^ *exposure:/d' -e '/^ *criticality:/d' \
    draugr.saga.yaml .draugr/components/platform.saga-fragment.yaml
$ git status --short
 M .draugr/components/platform.saga-fragment.yaml
 M draugr.saga.yaml
?? .draugr/components/platform.saga-fragment.yaml.bak
?? draugr.saga.yaml.bak
```

Every scan of the demo with its descriptor opens and closes with a line too wide for this page, so
the blocks below cut both. The first line is `config.gate.failOnNew is P1 and no --base names a scan
to compare against, so no finding was judged as new.`, and step 4 makes that comparison with
`draugr diff`. The last is `draugr: scan incomplete: 2 caveats fail it under
config.gate.failOnCaveats (use --allow-scan-errors to accept partial results)`, and the command exits
non-zero, because the demo's descriptor fails a run in which a scanner left files unread. The report
is still written.

```console
$ draugr scan --no-publish --report sarif -o before
…
DRAUGR  FAIL  draugr-demo 1.0  12.357s

 275 P1 712 P2 276 P3 0 P4
 No component declares exposure or criticality, so every one is read as public and critical.
 These bands rank severity alone. `draugr classify` makes them describe this application.
…
CAVEATS  2 fail the run · config.gate.failOnCaveats: unread-files
…
    uncommitted-files
      4 uncommitted files  not in commit bb729745 · --working-tree reads them

COMPONENTS
  api         ERROR  260 P1 702 P2 265 P3
  platform    FAIL   3 P1 7 P2 11 P3
  storefront  ERROR  8 P1 1 P2
  worker      FAIL   4 P1 2 P2
…
```

The uncommitted files are the ones `git status` listed, which the scanners did not read because they
read the repository at its commit. The edit counts all the same, because Draugr loads the descriptor
and its fragments from disk, apart from what the scanners read. `--no-publish` leaves out the demo's
publishers, which write into `.draugr/out` and deliver to GitHub. `--report sarif -o before` writes
the findings to `before/results.sarif`, in SARIF, a standard file format for scanner results.

### With them

Restore both files from the copies `sed` kept. `git status` then shows only the new `before/`
directory.

```console
$ mv draugr.saga.yaml.bak draugr.saga.yaml
$ mv .draugr/components/platform.saga-fragment.yaml.bak .draugr/components/platform.saga-fragment.yaml
$ git status --short
?? before/
```

Scan again.

```console
$ draugr scan --no-publish --report sarif -o after --top 1
…
DRAUGR  FAIL  draugr-demo 1.0  16.787s

 268 P1 704 P2 271 P3 20 P4
…
CAVEATS  2 fail the run · config.gate.failOnCaveats: unread-files
  ✗ unread-files · licenses · api
      app/requirements.txt  records no licenses for 4 packages
  ✗ unread-files · licenses · storefront
      web/package-lock.json  records no license for 1 package
…
COMPONENTS
  api         ERROR  260 P1 702 P2 265 P3
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
FIX FIRST  1 of 1263 findings, by priority
  P1  critical  CVE-2020-11023
      Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
      ↑ KEV · scanner trivy · jquery 1.8.3 → 3.5.0
      web/package-lock.json:12 · and 1 more · also found by retirejs
…
```

- **`COMPONENTS`** now gives `worker` and `platform` a pass, with nothing at P1. They hold the same
  findings as before, ranked lower because both are declared internal and supporting. `api` and
  `storefront` end in `ERROR` because a scanner left files unread, and CAVEATS lists them.
- **`↑ KEV`** marks a finding raised to critical because it is on CISA's Known Exploited
  Vulnerabilities catalog, here a jQuery 1.8.3 flaw in the storefront's lockfile.
  [Signals](../concepts/prioritization.md#signals) lists every mark.

`--top 1` keeps the list to its first row.

### Compare the two runs

`draugr diff` pairs the findings of two scans and reports what changed between them.

```console
$ draugr diff before/results.sarif after/results.sarif
DRAUGR DIFF  pass  27 reranked (27 lowered)  1238 unchanged

 reranked        0 P1 1 P2 6 P3 20 P4
 unchanged       268 P1 703 P2 265 P3 0 P4
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
critical lodash flaw went from P1 to P2, its highs to P3 and its mediums to P4. The rows cut here
are more worker and platform findings that moved the same way. The diff's unchanged count includes
the two findings the descriptor accepts, which the scan's `1 of 1263` leaves out. Both runs read KEV
and EPSS, so the diff shows only what the declarations did.
[Reranked findings](../guides/pr-diff.md#reranked-findings) covers the table, and
[classify components](../guides/classify-components.md) helps you choose the two values for your
own application.

## 3. Read a finding

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

## 4. Gate pull requests

The demo's CI, `.github/workflows/draugr.yml`, runs the
[GitHub Action](../guides/github-action.md). On a pull request it scans the base and the head,
compares them as step 2 did, and posts the result as a comment. The descriptor's
`config.gate.failOnNew: P1` fails the check on a P1 the pull request adds.
[Pull request 37](https://github.com/draugr-dev/draugr-demo/pull/37), kept open on the demo for
this, adds urllib3 2.0.7 to `app/requirements.txt` and fails its check.

The comment is the diff in Markdown. Render it from the two runs of step 2.

```console
$ draugr diff before/results.sarif after/results.sarif --format markdown
## Draugr diff

✅ **pass** · ↕️ 27 reranked (27 lowered) · 1238 unchanged

_reranked_ · 0 P1 · **1 P2** · **6 P3** · **20 P4**<br>
_unchanged_ · **268 P1** · **703 P2** · **265 P3** · 0 P4<br>
_still accepted_ · **2 P1** · 0 P2 · 0 P3 · 0 P4

_Gate: fails on any P1 this change introduces._

Nothing is new or fixed. Only priorities changed.
…
```

Run the gate itself, and read its exit code.

```console
$ draugr diff before/results.sarif after/results.sarif --fail-on-new P1 --view compact --top 1
DRAUGR DIFF  pass  27 reranked (27 lowered)  1238 unchanged

 reranked        0 P1 1 P2 6 P3 20 P4
 unchanged       268 P1 703 P2 265 P3 0 P4
 still accepted  2 P1 0 P2 0 P3 0 P4

Gate: fails on any P1 this change introduces.

Nothing is new or fixed. Only priorities changed.

RERANKED  top 1 of 27 · 27 lowered
  Priority  Severity  Rule           Scanner  Location
  P1 → P2   critical  CVE-2026-4800  trivy    worker/package-lock.json:73
…
$ echo $?
0
```

Both runs hold hundreds of P1 findings, and the gate passes, because it judges only what is new
between them. A pull request that adds a P1, as pull request 37 does, makes the same command exit
non-zero.
[Gate PRs on new findings](../guides/pr-diff.md) covers the comparison in any CI system.

The descriptor also keeps an issue open while part of the gate fails on `main`. This entry covers the
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

[GitHub issues](../guides/reports-and-publishers.md#github-issues) says when a run opens, rewrites
and closes the issue, and the same page has the GitLab and Azure DevOps equivalents.

## Next

- [Write your first Saga](first-saga.md) describes your own application.
- [What to fix first](../concepts/what-to-fix-first.md) turns findings into a list of changes.
