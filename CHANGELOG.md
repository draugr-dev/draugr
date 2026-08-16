# Changelog

All notable, user-facing changes to Draugr. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

Each release's notes are written for **users first** (what you can do, what changed for
you), with technical detail linked from the commit history. Keep an `Unreleased` section
and move it under a version on release.

## [Unreleased]

_Nothing yet._

## [0.97.0] - 2026-08-16

### Changed

- **The gate takes the severity words the report prints.** `--fail-on`, `--fail-on-new` and
  `config.gate.controls` now take `critical`, `high`, `medium` or `low` — the bands in the counts
  beside them — instead of the SARIF levels `error`, `warning` and `note`.

  ```bash
  draugr scan draugr.saga.yaml --fail-on critical   # newly expressible
  ```

  `critical` had no SARIF level of its own, so until now it could not be named: it travelled as
  `error`, together with everything high. The old words still work everywhere and mean `high`,
  `medium` and `low`, so pipelines and descriptors written against them keep working.

### Added

- **The report says what gate produced the verdict.** A verdict is only as meaningful as the
  policy behind it, and a gate can be narrowed or switched off from the command line without
  leaving a trace in the report:

  ```
  Draugr — PASS   (draugr-demo 1.0)

  Controls:
    secrets  pass   1 high

  Gate: fails on critical.
  ```

  A narrowed gate or `--no-gate` is stated in the default view, because a pass under a narrowed
  gate otherwise looks exactly like a pass under a full one — and `--no-gate` exits 0 on a verdict
  of FAIL, so anything reading the exit code is told the opposite of what the report says. A
  stricter gate says nothing until asked: it can only fail more, and the failure speaks for
  itself. `--evidence` and `--report evidence` state the gate whatever it is.

  Where the policy lives is unchanged. It stays in the descriptor beside the other gate settings,
  and configuration remains a default a Saga overrides rather than a floor it cannot lower — a
  floor is not something a CLI running on the reader's own machine can keep, and one that can be
  quietly lowered is worth less than no floor plus a visible record.

### Fixed

- **A finding the report calls `high` now fails a gate set to high.** The gate compared the SARIF
  level a scanner wrote, while the report shows the band a finding's CVSS score puts it in. Those
  are different ladders — a scanner can publish a 7.8 as `warning` — so a finding listed as `high`
  could pass a gate its reader believed was set to catch it.

  This can fail builds that previously passed, and that is the point: the findings it now catches
  were always in the report. It cuts the other way too — a finding a scanner marked `error` but
  scored as a medium is a medium, and no longer fails a gate set to `high`. The verdict and the
  report now describe the same finding the same way.

## [0.96.0] - 2026-08-16

### Added

- **`--group action` shows the fix list as things to do rather than things that are wrong.** One
  row per action, saying how many findings it clears and where:

  ```
  Fix first — 5 actions clear 19 findings:
    P1  Upgrade Jinja2 2.10  sca · 6 findings
        fixed in 2.10.1, 3.1.6, 3.1.5 and 3 other releases — take the latest
    P1  Remove the credential  secrets · 4 findings
        docs/example.yaml:65 · scripts/build.ps1:164 · test/app.yaml:75
  ```

  A library a year out of date carries a dozen findings and one upgrade; the same
  misconfiguration in three Dockerfiles is one habit. Listing those as a dozen and three rows
  makes the repetitive work crowd out the rest.

  Findings on infrastructure your provider operates are not in this list at all — they are
  reported and counted on their own line. Actions are ranked by the worst priority they clear,
  never by how many: an action clearing one P1 outranks one clearing forty P4s.

  **Opt-in for now**, with one finding per row remaining the default. Grouping is only right once
  a descriptor says which images you build and which infrastructure you operate — without that, an
  action row states a fix nobody can apply, where a finding row merely reports something true you
  can look up. The report files are unchanged either way.

- **A concepts page explaining the fix list** — how findings become actions, how they are ranked,
  and how `operatedBy` and `builtBy` change what Draugr recommends. `--group` points at it.

- **`draugr explain <rule>` says what a finding means and how to fix it**, from the scan's own
  report.

  ```
  kube-bench/cis/4.3.1
  Ensure that the kube-proxy metrics service is bound to localhost (Automated)

  How to fix
    Modify or remove any values which bind the metrics service to a non-localhost address.
    The default value is 127.0.0.1:10249.
  ```

  A rule id and a truncated line are enough to rank a finding and not enough to decide anything.
  Scanners publish remediation text and Draugr has been recording it all along — there was just
  nowhere to read it, so the identifier sent you to whatever a search engine offered, which for a
  benchmark is a registration form in front of a PDF.

  Takes the id in full or the part that is unambiguous: `4.3.1` finds `kube-bench/cis/4.3.1`.

- **`builtBy` says whether you build an image or only run it**, and the fix list stops telling you
  to do the impossible.

  ```yaml
  images:
    - image: registry.example.com/vendor/redis:8.2.2
      builtBy: upstream     # self (default), or upstream for one somebody else publishes
  ```

  Nobody can upgrade a library inside an image they do not build — the fix is a newer image, or a
  wait for whoever publishes it. Findings in an `upstream` image now group into one action per
  image instead of one per package:

  ```
  P1  Update istio/install-cni:1.30.0  images · 184 findings · upstream
      CVE-2026-8925 +183
  ```

  On a real cluster scan that turned 80-odd rows telling the reader to upgrade libraries they
  cannot reach into five rows naming five images they can. `self` remains the default, because a
  descriptor written by hand describes what a team builds; a hint points at the setting when a run
  finds image vulnerabilities and no image has said either way.
- **Configuration can hold how you like the report**, and has a guide of its own.

  ```yaml
  output:
    group: action
    evidence: false
    top: 20
  ```

  `draugr scan` has 27 flags and most of them answer the same question every time you run it on a
  given machine. Rendering preferences now live in `draugr.config.yaml` alongside `tools`,
  `cache` and `controllers` — a preference belongs to a person or a machine, not to an
  application, and putting one in a descriptor asserts it on everyone else who scans that
  application.

  Flags still win, including when what you typed is the zero value: `--top 0` means show
  everything, and a configured cap does not override an explicit instruction.

  The new [configuration guide](docs/guides/configuration.md) covers where the file is read from,
  the question that decides whether a setting belongs there or in a Saga, and a worked example of
  a platform team setting defaults for every repository in a runner image.

- **`--evidence` shows what stands behind the verdict, and `--report evidence` writes it down.**

  Tool provenance, the scanned revision, and what the run cost are no longer in the default view.
  Each is justified on its own, and together they were most of what came before the findings — a
  developer opening a terminal is asking what to fix, and answers to questions they have not asked
  push the answer to the one they have off the screen. An auditor is a real reader, just not the
  default one.

  Both deliveries render from the same code, so they cannot disagree about what a run did.

  What stays in the default view is whatever changes what the verdict means, rather than
  supporting it: a control that did not run, a finding suppressed with nobody accepting it, a
  cache hit on a mutable reference, and **what each control was measured against** — which carries
  what it did not cover, such as the operations a spec-driven scan was not allowed to send. So do
  the receipts: what the scan did to your systems, and the SBOM it produced.

- **A component whose resources could not be scanned reports `ERROR`, not `pass`.**

  ```
  Components:
    istio-system    ERROR   3/3 images not scanned
  ```

  A control that could not run found nothing by looking at nothing, so a clean verdict beside it
  covers less than it appears to. The count carries its denominator, because "3 images not
  scanned" does not say whether that is all of them or three of ninety.
- **Findings say whether you can act on them**, and a descriptor can say who operates a cluster.

  ```yaml
  infrastructure:
    - kind: kubernetes
      ref: prod-cluster
      operatedBy: provider     # self (default), or provider for a managed service
  ```

  On a managed cluster the control plane, API server and etcd are not reachable — there is no host
  to log into and no file to change — so findings about their configuration are reported and
  counted but are not work this team can do. RBAC, Pod Security, network policy and node settings
  stay yours whoever runs the cluster underneath, and are unaffected.

  Every finding now classifies its remediation: a version to upgrade to, a release underneath to
  move, somebody else's to fix, or nothing published yet. Machine-readable for now — what the
  console does with it comes next.

- **The progress line says when jobs are failing**, as they fail:

  ```
  scanning 9/17 · 8 failed · sast/semgrep
  ```

  A run whose image jobs are all failing to authenticate is one to stop and fix. Learning that
  only from the report means waiting out a scan that was never going to cover them.

- **Findings say when their operating system is past end of service life.** Trivy reports it and
  Draugr was parsing past it.

  It changes what a finding means. On a supported release, "no fix available" is a state that
  ends when the vendor publishes one; past end of service life no fix is ever coming, and
  upgrading the release is the only thing that resolves those findings — usually the largest
  single reduction available, because it moves the whole OS layer at once.

  Carried on the finding and in the SARIF, alongside the image and operating system it describes.

- **Image findings say which layer they came in on, and the build step that put them there.**

  An image's findings divide into ones this component introduced and ones it inherited, and only
  the first are fixable without rebasing. Each finding now carries its layer — position, and the
  instruction verbatim from the image's own history, such as
  `RUN /bin/sh -c apt-get update && apt-get install -y curl` — which names the line to change.

  Draugr does not name a base image: an image records nothing about what it was built `FROM`, and
  where a multi-layer base ends is not in there either. The layer and its build step are facts;
  a base image name would be a guess in a field a reader would trust.

### Changed

- **Cache entries are named `.json.gz`**, which is what they have been since they were compressed.
  Entries written by an earlier version are not read, so the first scan after upgrading repopulates
  the cache — a cache is disposable and this costs one cold run. Entries under the old name are
  removed as their keys are rewritten; deleting the cache directory clears them all at once.

- **Findings you can act on are listed first within their priority band.** A package with a fix,
  then a release that can be moved, then one with no published fix, and last the findings that
  belong to a provider.

  It does not change the priority. That feeds the gate, so demoting a finding because nobody here
  can fix it would weaken a build gate as a side effect of annotating a descriptor — and the risk
  is unchanged either way: a vulnerable control plane is exactly as dangerous whether or not the
  fix is yours. This is what `operatedBy` and `builtBy` do when the fix list is ungrouped.

- **kube-proxy checks count as the provider's on a managed cluster.** Section 4.3 of the benchmark
  was treated as yours because kube-bench files it under the same "node" heading as the kubelet —
  but every managed platform runs kube-proxy as a DaemonSet it owns, so a reader told to change
  the address it binds to has nowhere to make the change. The kubelet stays yours, because node
  pool settings usually reach it.

- **Everything a run writes is recommended under `.draugr/`** — `.draugr/out/` for reports,
  `.draugr/cache/` for the result cache — beside the descriptor and exclusions Draugr already
  keeps there. One directory to ignore in git rather than several names.

  `draugr explain` looks there first, and still reads `draugr-out/` and `.draugr-out/`, the names
  that came before. Neither path is imposed: `-o` writes where you point it, and caching stays
  opt-in.

  The GitHub Action and the GitLab template keep writing to `draugr-out` for now. A pipeline that
  uploads `draugr-out/results.sarif` would not fail if that moved — it would upload nothing, and
  the security tab would quietly empty — so they move on their own, deliberately.

- **The cache caveat counts rather than names.** It listed the image references, which repeated
  what the marked rows already say and, on a descriptor with dozens of images, put a list nobody
  reads at the foot of the one they do. What the count adds is the part the rows cannot say —
  one image out of thirty is a different report from thirty out of thirty. Which ones is in the
  JSON and in `--evidence`.

- **Tips are shorter and read as one voice.** They ranged from 103 to 201 characters and were
  written one at a time; a tip interrupts somebody reading a report, so it has to earn the
  interruption in the space of a glance. They now share a shape — an observation and what to do
  about it — and a test holds them to it, because each addition is individually reasonable and
  that is how a tip block becomes furniture.

- **Action rows keep a way into the findings they stand for**, and lost the version noise:

  ```
  P1  Upgrade libcrypto3 3.6.0-r3  images · 54 findings
      chainguard-sync/redis:8.2.2 · chainguard-sync/argocd:3.2.11 · CVE-2026-31789 +53
  ```

  Grouping answers *what do I do* and had taken away *what exactly is wrong*, which is the
  question a reader has next: the rule identifier is gone from the row and with it the link to
  what the scanner published about it. One is named and linked now, and the rest are counted.

  The version to upgrade to moved into the title, and only when every advisory in the group
  agrees on one — a list of four near-identical OS package releases said little and filled the
  line.

  Image references drop the digest and the registry host for display. A digest-pinned reference
  from a private registry runs past 130 characters, and two of them left room for nothing else;
  the digest is what makes a scan reproducible and is still in the report and the SARIF.
- **The cache caveat is shorter, sits below the findings, and marks the rows it applies to.**

  ```
  P1  Move off debian 11.11 — past end of service life  images · 277 findings · from cache
  ...
  from cache: draugr-baseimg-test:1 was reused on a tag, so may describe an earlier build. Pin a digest.
  ```

  It was three lines of prose above the fix list, competing with the thing it is a caveat about
  and leaving the reader to work out which rows it applied to. An action is marked only when
  *every* finding in it came from a reused entry, since one stale row among three current ones is
  not a stale action.

### Fixed

- **A descriptor that declares `config.reports` with nowhere to write them says so.** Declared
  reports are rendered for publishers to deliver; with no publisher and no `-o` they were built
  and discarded in silence, which reads exactly like a run that wrote them.

  ```
  config.reports declares html, markdown and this run had nowhere to write them — pass -o <dir>, or add a publisher.
  ```

  A warning rather than an error: a descriptor written for a pipeline that has publishers is
  reasonable to run locally without one.

- **CIS check titles drop the `(Automated)` and `(Manual)` suffix.** That is the benchmark's
  vocabulary for whether a recommendation can be *assessed* programmatically. It says nothing
  about the finding or its fix, a reader sees it beside something they have been told to act on
  and reads it as a claim about the remediation, and it costs a dozen characters of a line that
  is already truncated. Draugr already draws the distinction it encodes: a check the tool could
  not settle comes back as a warning rather than a failure.
- **Effects, the SBOM line and the cache caveat reappear in the default listing.** They were
  reachable only from the row-per-finding view, so the grouped default — what almost everyone
  sees — silently dropped them, including the record of what a scan did to somebody's systems.

- **The progress display shows every scanner and marks each one as it finishes**, instead of one
  line listing whatever is in flight:

  ```
  Scanning 7/12  2 failed
    ✓ sast/semgrep                       1/1
    ▸ images/trivy                       2/5, 2 failed
    · sca/trivy-fs                       0/3
  ```

  A scanner used to vanish the moment it completed, so a reader watching could not tell work that
  had finished from work that had not been reached — and those call for different patience. Each
  row now stays and changes state, with colour reinforcing the mark rather than carrying it, so
  the display reads the same without colour.

  Still only on a terminal, and erased before the report.
- **A contended tool cache is reported once, with its total, instead of a line per wait.** Draugr
  plans concurrent jobs that share a scanner's cache, so they queue on it — and with three retries
  per job, a scan with many images could fill the screen with identical `waiting for the scanner
  cache` lines before reporting anything.

  Those lines are now `debug`, where they serve whoever is diagnosing contention. What a scan that
  took three times as long owes its reader is the total, and that now sits beside the duration:

  ```
  Ran 17 jobs in 18.2s — 4 from cache, 11s waiting for the trivy cache.
  ```

  One figure a reader can act on, rather than several that overlap and cannot honestly be added up.

- **A component whose scans failed no longer reports as passing.** A component whose whole surface
  is three container images, none of which could be pulled, rendered as `pass  no findings` —
  nothing looked at it, so there were none to have, and the row invited exactly the wrong reading.

  It now reports what went unexamined, against what the component has, beside the findings when
  there are both:

  ```
  Components:
    api   FAIL   P1 2  P2 2  sca   1/4 images not scanned
    mesh  ERROR  3/3 images not scanned
  ```

  The fraction is the point: three images not scanned is a component nobody looked at when it has
  three, and a gap in one that was mostly covered when it has thirty. A target one scanner failed
  on and another read is not counted — it was examined.

  The `! … did not complete — this verdict does not cover it` line is gone with it. It was
  imprecise where this is exact: a control can fail for one target and succeed for others, so
  saying the verdict does not cover a whole control was wrong whenever part of it ran.

- **`--report evidence` works.** The format was registered as a document and given a filename but
  never added to the renderer registry, so the CLI rejected it as unknown while the renderer's own
  tests passed — they called it directly. A test now crosses the two lists in both directions.

- **A failure message no longer breaks the URL in it.** Wrapping split any token longer than the
  line at the margin, so the endpoint a scanner could not reach arrived in two halves and could
  not be copied — which is the only reason it is in the message. Long tokens now overflow whole,
  and a truncated line is cut at a word boundary rather than mid-word.
- **The progress line no longer prints over the report.** It was erased when the command returned,
  which is after the report has been written — so on a terminal the verdict arrived welded to a
  job counter (`scanning 17/17    Draugr — FAIL`). It is now cleared the moment the run finishes,
  before anything is rendered.

## [0.95.0] - 2026-08-15

### Added

- **Image findings say which image and which operating system they came from**, and a new
  `gitlab-container-scanning` report files them where GitLab looks for them.

  GitLab routes findings by report type — its deduplication, its merge-request widget and its
  approval policies all key on it. Container findings previously arrived only through Code
  Quality, so a container-scanning approval policy looked in a report that did not exist and
  found nothing, which reads as a clean image.

  ```bash
  draugr scan draugr.saga.yaml -o out/ --report gitlab-container-scanning
  ```

  The image reference and the operating system are now fields on every image finding, in the
  report and in the SARIF, so `draugr diff` and every platform format still have them on the
  second read. A finding whose image has no identifiable distribution — scratch, distroless — is
  left out of this report rather than given an invented one, and still reaches a reviewer through
  `gitlab-codequality`.

### Changed

- **Image scans read Trivy's JSON rather than its SARIF**, which is where the package identity and
  the operating system are. Image findings now carry the same structured package — name, version,
  the version that fixes it, and a purl — that dependency findings already did.

## [0.94.0] - 2026-08-15

### Added

- **`sca` can find JavaScript that never reaches a lockfile**, with an opt-in retire.js scanner:

  ```yaml
  config:
    controllers:
      sca:
        retirejs: { enabled: true }
  ```

  Lockfile-based scanning answers for what the package manager installed. Front-end code routinely
  ships JavaScript it did not — a library pulled from a CDN, a vendored `.js` under `static/`,
  bundled output shipped without its manifest — and a repository serving a five-year-old jQuery
  **scans clean today**: the control runs, reports, and passes.

  Findings carry package identity (name, version, the version that fixes it, and a `pkg:npm/…`
  purl), are reported under their CVE where one exists, and say how the library was recognised —
  which is the answer to "why is this not in my lockfile".

  **`draugr tools install retire` provisions it**, the way Semgrep is provisioned: retire.js
  publishes to npm rather than as a binary, so the install comes from a lockfile built into the
  Draugr binary, with every package verified against its integrity digest and install scripts
  disabled. It needs Node 18 or newer. Its advisory database is cached under
  `~/.draugr/data/retirejs` rather than `/tmp`, so it survives a CI job and travels with an
  air-gapped install.

_Nothing yet._

## [0.93.0] - 2026-08-15

### Added

- **`dast` can scan an API from its OpenAPI specification.** An API has no HTML to crawl, so
  probing it blind reaches whatever the scanner can guess. Point it at the document instead:

  ```yaml
  hosts:
    - url: https://staging.example.com
      spec:
        path: ./openapi.yaml
        methods: [get, post]      # absent → GET and HEAD only
  ```

  **The scan targets the endpoint you declared, never the one the document names.** A specification
  whose `servers:` block says production would otherwise send probe traffic at production while
  your descriptor said staging.

  **Read-only unless you name write methods.** A specification lists `DELETE` too, and a scanner
  handed one will use it — a default run against a three-operation document sent nine `DELETE`
  requests. Operations whose method you have not named are removed before the scanner sees the
  file, so the restriction does not depend on the tool behaving.

  The run reports what it excluded, and how many operations declare parameters it could not supply,
  so a scan that covered part of an API does not read like one that covered all of it.

- **`dast` can authenticate.** An unauthenticated scan of an application that requires a login
  tests the login page — everything behind it goes unexamined, and the report reads as though it
  were checked. Declare the credential on the endpoint:

  ```yaml
  hosts:
    - url: https://api.example.com
      auth:
        type: bearer                 # or: type: header, header: X-API-Key
        tokenEnv: DRAUGR_API_TOKEN
  ```

  **There is no field for the credential itself.** `tokenEnv` names the variable holding it; a
  descriptor is committed, so a token written into one is a leaked token. The value is read at the
  moment of the scan, handed to the scanner in a `0600` file, and removed afterwards — never on a
  command line, where a process list would show it, and never in a cache key or a report.

  **An unset variable fails the scan** rather than quietly falling back to anonymous, which would
  produce the exact pass this prevents. The report records that the scan authenticated and which
  variable it read, so an authenticated run is never mistaken for an anonymous one — and the cache
  key carries the same marker, so adding credentials invalidates results gathered without them.

_Nothing yet._

### Fixed

- **Editors no longer offer every control name twice** under `config.controllers`. The schema
  described the allowed keys in two places at once — once as the controls this build serves, each
  with its own options, and again as a list of the same names — so completion had two sources for
  one set of keys.

  It now says it once, and says it more strictly: an unknown control under `controllers` is a
  schema error in your editor rather than a shape that validates there and is rejected when Draugr
  loads it.

## [0.92.0] - 2026-08-14

### Added

- **`draugr doctor` now says what nothing is looking at.** Every tool being present is only half of
  "will this scan tell me what I think it will" — the other half is whether any enabled control
  examines what the descriptor declares. A component declaring images while the `images` control is
  off scans clean having never looked at them, and doctor is the command you run *before* the scan
  to find that out:

  ```
  Not checked:
        api declares hosts, and headers, tls are not enabled
        api declares images, and images is not enabled
  ```

  It comes from the same place `draugr scan` gets it, so the two cannot disagree, and `--json`
  carries it as `uncoveredSurfaces`.

  **Reported, not failed.** A deliberately narrow descriptor is legitimate, and a preflight that
  fails on a choice you made is one you learn to ignore. Pass **`--fail-on-uncovered`** when you
  want it enforced — usually in CI, against a descriptor meant to be complete. A missing tool still
  outranks it: that stops the scan outright, while an uncovered surface only narrows it.

### Changed

- **`draugr scan --help` groups its flags by what you are trying to decide** — what is scanned,
  what fails the build, exploitability data, output, caching, and running the scan — instead of
  listing thirty-odd of them alphabetically. Alphabetical order put `--artifact-min-priority` nine
  lines from `--min-priority` when the two are one decision.

  The CLI reference is grouped the same way, and `--report` now appears in it: it was explained in
  prose but missing from the table listing every flag.

  Nothing about parsing, precedence or completion changes — only how help is printed.

### Fixed

- **A cached image scan now says when its key was a tag rather than a digest.** Draugr's cache is
  content-addressed, which holds for a repository at a revision and for an image pinned to a
  digest — but not for `acme/api:latest`, whose name is stable while the bytes behind it are not.
  A rebuilt tag kept the same key, so the previous image's findings were served with nothing to
  say so.

  The findings are still reused, and the report now tells you which ones rest on that:

  ```
  Reused from cache, keyed on a tag: acme/api:latest — a tag can be rebuilt, so these findings
  may describe an earlier image. Pin a digest, or re-scan with --cache-require-digest.
  ```

  It appears only when a result was actually reused — a fresh scan of a tag read whatever that tag
  points at now — and `--format json` carries the same list as `stats.unpinnedCacheHits`. Pinning a
  `digest:` in the descriptor removes the caveat, and `draugr survey` records the running digest
  for you.

_Nothing yet._

## [0.91.0] - 2026-08-14

### Added

- **Anchore Grype as a second scanner for `images` and `sca`.** Trivy still runs by default;
  Grype is opt-in, per project or per component, and both run together when you enable it:

  ```yaml
  config:
    controllers:
      images:
        grype: { enabled: true }
      sca:
        grypeFs: { enabled: true }
  ```

  Two matchers over the same image or the same dependency tree draw on different advisory
  sources — Grype's include Chainguard, Wolfi, Bitnami and the GitHub Security Advisories
  alongside the usual distribution trackers — so where they disagree, that is worth knowing.

  `draugr tools install grype` provisions it, pinned and checksum-verified, and `draugr doctor`
  reports whether its vulnerability database is present and current enough to scan with. Grype
  refuses a database older than five days, so a binary on `PATH` is not yet a scanner that can
  run, and doctor says so before a scan finds out.

  Findings are reported under their CVE rather than the advisory identifier the source happened
  to use, so a vulnerability Grype and Trivy both find is recognisably the same one in both rows.
  `byCve: false` turns that off.

  Two things to know before you enable it. **Finding counts rise**, because a flaw both scanners
  find is reported twice — once under each tool's rule identifier — and nothing yet folds the pair
  into a single finding with two observations. And **an exclusion needs a trailing `*`** to cover
  both: Grype names the package in its rule identifier (`CVE-2020-14343-pyyaml`) where Trivy does
  not, so `rules: ["CVE-2020-14343"]` suppresses one and silently leaves the other standing, while
  `rules: ["CVE-2020-14343*"]` covers both.

  For an air-gapped runner, `GRYPE_DB_UPDATE_URL` points at an internal mirror and
  `GRYPE_DB_CACHE_DIR` relocates the cache; `--offline` stops Grype checking for updates at all.
  See the [air-gapped guide](docs/guides/air-gapped.md).

- **`draugr survey azure repos` writes a descriptor from Azure DevOps.** One component per Git
  repository, with its clone URL and default branch, for a whole organization or for one project:

  ```bash
  draugr survey azure repos --org acme -o draugr.saga.yaml
  draugr survey azure repos --org acme --project Platform -o draugr.saga.yaml
  ```

  The project is optional because the two answer different questions — one project is a team's
  surface, the organization is the estate. Authentication reads `AZURE_DEVOPS_EXT_PAT` (what the
  `az` CLI already exports), then `AZURE_DEVOPS_TOKEN`, and needs the **Code (read)** scope. An
  Azure DevOps Server instance is named by `AZURE_DEVOPS_URL`, including its collection.

  Repositories that are disabled or have no commits are skipped and reported, rather than written
  into a descriptor whose clone will fail. Without a token the survey warns that it saw public
  projects only: the descriptor that results is valid and complete-looking, and missing every
  private repository.

  Azure DevOps answers an unauthenticated or under-scoped API request with `203` and a sign-in
  page rather than a `401`, so that case says which of "missing", "expired" or "wrong scope" to
  check instead of reporting a status code that means "this is fine, from a cache".

### Fixed

- **`draugr survey github repos` now reaches GitHub Enterprise Server.** It reads `GITHUB_API_URL`
  — the same variable the `github-pr-comment` publisher already uses, and the one GitHub Actions
  sets for you on a GHES runner — so a survey in CI needs nothing configured, and a survey from a
  workstation needs one variable:

  ```bash
  GITHUB_API_URL=https://github.example.com/api/v3 \
    draugr survey github repos --org acme -o draugr.saga.yaml
  ```

  Previously the surveyor always asked github.com, whatever the publisher was pointed at, so the
  one command whose job is to write your descriptor for you was unavailable to the organizations
  most likely to have hundreds of repositories to write down.

## [0.90.0] - 2026-08-14

### Added

- **A dependency finding says which package it is about.** Scanners have always known — Trivy's
  message reads `Package: flask`, `Fixed Version: 0.12.3` — and only ever said it in prose, which
  is a fact formatted for a human and unavailable to anything else. Findings now carry the package
  name, installed version, fixed version, purl and ecosystem as fields, through the report and the
  SARIF file both.

  Draugr reads Trivy's JSON rather than its SARIF to get them. Nothing is lost in the swap — the
  rule documentation, the advisory link and the CVSS score behind `security-severity` are all in
  the JSON under other names — and the location improves: it is now the manifest the package was
  declared in (`requirements.txt`) rather than the root that was scanned.

- **`gitlab-dependency-scanning`**, which that unblocked. GitLab's schema requires a structured
  package and version on every finding, so the format could not exist while the only copy of
  either was inside a sentence. Verified against GitLab's published schema.

  `container_scanning` is still absent: it requires an image and an operating system that image
  findings do not yet carry as fields, and a required field filled with a guess is worse than a
  report that does not exist.

### Changed

- **The Action and both CI templates provision Semgrep with `draugr tools install`**, like every
  other scanner. Each carried its own `pipx` line because Draugr could not install it; now that it
  can, one command provisions everything the descriptor's controls need. The GitLab template's
  `DRAUGR_SEMGREP` switch is gone with it — there is nothing left for it to turn off.

  A GitLab runner still needs a **Python 3.10 or newer** image, for a different reason than before:
  Draugr uses an interpreter to build the environment it installs Semgrep into.

  Draugr's own self-scan is the exception, and structurally so: it provisions its scanners before
  the step that downloads Draugr, so it cannot use Draugr to do it.

## [0.89.0] - 2026-08-13

### Added

- **`draugr tools install semgrep` works.** Semgrep was the one scanner Draugr could not provision,
  so every integration carried its own `pipx` line and `doctor` reported it as somebody else's
  problem. It is installed like everything else now.

  It arrives by a different route because it publishes no release binary — its GitHub releases
  carry no assets at all. Draugr builds a virtual environment it owns under `~/.draugr/venv/` and
  installs the pinned set from PyPI with `--require-hashes`, then puts a launcher beside the other
  tools. **Python 3.10 or newer** is required, and `doctor` names it when missing rather than
  letting a scan fail with `sast` reporting that it could not run.

  The provenance claim is the same one a pinned release archive makes, and covers more: every
  artifact in the resolved tree — dependencies included — matches a digest recorded in this build
  of Draugr, so `semgrep` reports as `pinned` rather than `external`. Where the pinned set does not
  cover a platform, Draugr installs the pinned version unhashed and records `unverified` rather
  than claiming a check it did not make.

  A second install method rather than a special case, so the next scanner that ships only as a
  package drops in instead of becoming another exception.

### Fixed

- **`draugr validate` rejects a report format or publisher kind this build does not have**, and
  names the nearest one. It used to accept them: the registries live in packages the descriptor's
  own validation cannot import, so it could only check the fields were present. The failure then
  surfaced at publish time, after every scanner had run — a four-minute scan ending in a typo a
  check catches in milliseconds.

- **One unrenderable report no longer costs you the rest.** Every configured format was rendered
  before any was delivered, and the first failure returned — so a single bad format meant no
  evidence at all from that run, including the reports a pipeline downstream was waiting on. What
  renders is now delivered, and what did not is reported alongside it. A run where nothing rendered
  still fails, naming every reason rather than the first.
- **A sticky pull-request comment stays sticky past the first hundred comments.** GitHub returns
  comments a page at a time, and the publisher read one page — so on a pull request with a real
  conversation on it the marker fell off the end, no existing comment was found, and a fresh report
  was posted every run. It degraded by adding noise rather than by failing, exactly where a long
  thread makes the one comment worth having. The listing is now followed to the end.

  Azure DevOps needs no equivalent: its API documents itself as returning all threads in a pull
  request and offers no paging parameters, so there is nothing to follow.

## [0.88.2] - 2026-08-13

### Fixed

- **GitLab now reads the properties in the SBOM at all.** The document did not declare
  `gitlab:meta:schema_version`, which GitLab requires before it will parse any `gitlab:` property.
  Its absence is quiet: packages still appear with names, versions and licences, because those are
  plain CycloneDX, and GitLab infers the packager from a purl on its own — so the dependency list
  looked nearly right while *Location* stayed empty and GitLab's own dependency scanning never ran
  against the SBOM.

## [0.88.1] - 2026-08-13

### Fixed

- **CI builds on an exact Go patch release.** The workflows asked for `1.26`, and setup-go's version
  manifest lags go.dev by a day or two — so a floating minor resolves to yesterday's patch, and
  `govulncheck` fails every pull request for stdlib vulnerabilities that were fixed in the newer
  one and that no pull request introduced. The release workflow is pinned too: the binary people
  install should be built on the toolchain the gate was checked against.

- **The dependency list's Location column is filled in.** `gitlab-cyclonedx` named the manifest on
  every package and not on the document, and GitLab reads the document-level property for that
  column — its own analyzers emit one SBOM per manifest, where Draugr emits one covering everything
  it scanned. Where every package came from the same file the two shapes agree and the path is now
  stated at both levels. With several manifests it is stated per package only: there is no single
  answer, and picking one would attribute a package to a file that does not declare it.

## [0.88.0] - 2026-08-13

### Added

- **`gitlab-cyclonedx`**, so GitLab can actually read the SBOM. GitLab accepts CycloneDX 1.4–1.6
  and Syft emits 1.7, so the SBOM was reported as *"could not be parsed"*; and the manifest each
  package came from, plus its package manager, have to be stated in GitLab's own property namespace
  or the Dependency List shows *Location* and *Packager* as **unknown** — and GitLab will not run
  its own dependency scanning against it at all.

  Both facts were already present, under Syft's names and inside each purl. The new format renders
  a view of the SBOM with them translated, at a spec version GitLab reads. Draugr's own SBOM is
  written beside it and unchanged, so nothing else that consumes it pays for this.

  Enable `config.sbom` and the GitLab template does the rest. With no SBOM to render the format
  says so rather than writing an empty document.

### Changed

- **GitLab reads as a first-class target everywhere, not just in its own guide.** The README and
  the quickstart named the GitHub Action as *the* way to run Draugr in CI; all three platforms now
  sit side by side with what each one's findings land in, and the quickstart says plainly that
  anywhere else is the binary and an exit code. `examples/gitlab-ci.yml` is a complete commented
  pipeline to copy, `examples/reporting.saga.yaml` declares the GitLab publisher and formats
  alongside the GitHub one, and the code-scanning guide points GitLab readers at the equivalent
  that is not an upload.

## [0.87.0] - 2026-08-13

### Added

- **GitLab's Dependency List and License Compliance tab are populated.** Both read a CycloneDX
  SBOM rather than a report of their own, and Draugr's SBOM already carries SPDX identifiers in
  each component's `licenses` — the only form GitLab reads. The template collects
  `draugr-out/sbom-*.cdx.json`, so enabling `config.sbom` in the descriptor is all it takes, and
  one artifact fills both: every package with its version and its licence. Ultimate tier.

- **`DRAUGR_GATE_DEFAULT_BRANCH`** in the GitLab template, because gating the default branch and
  populating GitLab's merge-request widgets turn out to be mutually exclusive. GitLab baselines
  those widgets against the default branch's last *successful* pipeline, so a project whose default
  branch legitimately fails the gate never establishes one — the reports upload and there is
  nothing to compare them against. On by default, since a gate that does not fail is not a gate;
  set it to `"false"` to keep the default branch green and reporting, and leave gating to the
  merge-request path. The guide gives the trade-off as a table.

### Fixed

- **The GitLab template's merge-request diff compares the right two trees.** It named the base
  descriptor while standing in the head checkout, and a component's `url: .` resolves against the
  working directory — so both scans read the head, every diff reported no change, and the
  differential gate could not trip. It failed green, which is the only way a gate fails that nobody
  notices. The base is scanned from inside its own worktree now, as the GitHub Action already did.

- **The GitLab template's merge-request diff has something to diff.** `--report` replaces the
  default `json,sarif` rather than adding to it, so a job asking only for GitLab's own formats
  wrote no `results.sarif` — and the diff then failed on a missing file, which points at the diff
  rather than at the report list that caused it. The template names `sarif` explicitly, and a test
  now checks that whatever the template diffs is a format it asked the scan to write.

## [0.86.2] - 2026-08-13

### Fixed

- **The `secrets` control works in a container.** Draugr asked Gitleaks to write its report to
  `/dev/stdout`, which is a symlink to the process's own file descriptor — opening it is not the
  same as writing to the descriptor it inherited, and where stdout is a pipe (every containerised
  runner: GitLab CI, a GitHub Actions container job, a Kubernetes runner, a local `docker run`)
  the tool exited successfully having written nothing. The scan then reported
  `parse gitleaks SARIF: unexpected end of JSON input`, which blames the JSON for a plumbing
  problem. The tool is handed a real file now.

- **`--log-level debug` no longer prints a repository's credentials.** Planning logged the whole
  target struct, and a checkout's URL or its resolved git remote carries whatever was used to fetch
  it — a CI runner writes a token straight into the remote, so this affected any pipeline running
  at debug, whether or not the descriptor mentioned a credential. The log now records the target's
  identity, which is credential-free by construction and already what reports and cache keys use.
  A host reached with credentials in its URL is covered too.

  If you have run Draugr at `--log-level debug` — or with `--log-file`, which records at debug
  regardless — in a pipeline that clones over HTTPS with a token, treat that token as exposed and
  rotate it.

- **The GitLab template now runs the scanners it provisions.** It ran on Alpine, where the tools
  Draugr distributes are built against glibc and Semgrep's wheels do not install at all — so a
  pipeline installed Draugr, started, and reported `sast` and `secrets` as controls that could not
  run. It uses a glibc image, installs Semgrep (`DRAUGR_SEMGREP`, on by default), and marks the
  checkout safe for git, which a runner that clones and executes as different users otherwise
  refuses to read.
- **`draugr doctor` is invoked correctly by the template.** It was passed `--saga`, which that
  command does not take; the surrounding `|| true` swallowed the error, so the step reported
  success and never ran. Both CI templates are now checked against the real command tree, so a
  flag a template passes has to exist.

## [0.86.1] - 2026-08-13

### Fixed

- **`draugr scan --report --help` lists every format there is.** It restated them as a fixed
  string, so a format could ship, work, and appear nowhere a user looks for the list — the GitLab
  reports were missing from it. Built from the registry now, as `--format` already was.
- **The GitLab template's documented `include:` now works.** It showed `include: project:`, which
  resolves against your own GitLab instance — and Draugr is not on it, so the pipeline failed with
  a project-not-found error that reads like a permissions problem. The form is
  `include: remote:` with the raw URL of a pinned tag, and the guide says what to do when a runner
  has no route to it.
- **A publisher that cannot deliver no longer hides `draugr diff`'s verdict.** With `--publish`, a
  failure to post the comment was returned instead of the gate result, so a merge request that
  introduced a P1 reported a missing token and never mentioned the finding — sending a reader to
  fix a credential when what actually happened is that the change should not merge. The verdict is
  now the outcome and the delivery problem is reported alongside it, which is how `draugr scan`
  has always reconciled the two. A run that could not publish still exits non-zero.

## [0.86.0] - 2026-08-13

### Added

- **Draugr comments on GitLab merge requests.** The new `gitlab-mr-comment` publisher posts the
  markdown report as a sticky comment — one note per merge request, updated in place on each
  pipeline run instead of stacking up:

  ```yaml
  config:
    reports:
      - format: markdown
    publishers:
      - kind: gitlab-mr-comment
  ```

  Everything else defaults from the runner, and it no-ops on branch pipelines, so the same Saga
  keeps working outside a merge request and on a laptop.

  `draugr diff --publish` now recognises GitLab too, and posts the delta there rather than choosing
  a publisher that had nothing to say on that runner.

  One thing to set up: `GITLAB_TOKEN` must hold a project or group access token with `api` scope,
  as a masked CI/CD variable. The `CI_JOB_TOKEN` GitLab puts in every job is read-only on the notes
  API, so Draugr names that in the error rather than leaving you with an unexplained 401.

- **Findings reach GitLab's own surfaces, not just a comment.** GitLab does not read SARIF — it
  reads its own schema, collected by the runner as a build artifact — so there are three new report
  formats rather than a publisher:

  ```yaml
  config:
    reports:
      - format: gitlab-sast              # gl-sast-report.json
      - format: gitlab-secret-detection  # gl-secret-detection-report.json
      - format: gitlab-codequality       # gl-code-quality-report.json
  ```

  `gitlab-codequality` shows every finding in the merge request's **Reports** tab on any tier,
  including Free. The two security reports feed the Vulnerability Report and the merge-request
  security widget, which are Ultimate — the guide says which surface needs which plan rather than
  describing the best case and leaving you wondering why nothing appeared.

  Severity is sourced differently on purpose: the security reports carry the flaw's severity,
  because GitLab's approval policies gate on that field, and Code Quality carries Draugr's P1–P4,
  because it is a list a reviewer reads in order. Suppressed findings are in neither — GitLab would
  show one as open and ask again for a decision your Saga already records.

  Dependency and container findings reach the merge request through `gitlab-codequality` for now.
  GitLab's typed reports for those require a structured package name, version and operating system
  that Draugr's findings currently carry as scanner prose, and guessing at a schema's required
  field is worse than not filling it.

- **A GitLab CI template**, the counterpart of the GitHub Action and the Azure Pipelines template:

  ```yaml
  include:
    - project: draugr-dev/draugr
      ref: v0.86.0
      file: /gitlab-ci/draugr.yml
  ```

  On a merge request it scans the head and the merge base and posts the delta, gated on what the
  change introduces. On the default branch it scans and gates the whole descriptor. Both feed
  GitLab's reports.

  It fetches the merge base explicitly, because GitLab clones 20 commits deep by default and the
  commit to compare against is usually not in the checkout — a diff that works on a small test
  repository and fails on a real one.
- **`draugr survey gitlab projects --group <path>`** writes a Saga from a GitLab group, one
  component per project — the counterpart of `survey github repos`:

  ```bash
  draugr survey gitlab projects --group acme -o draugr.saga.yaml
  ```

  Subgroups are included, because a group is a tree and stopping at the top level would produce a
  descriptor that looks like the whole organisation and describes one floor of it. Archived and
  empty projects are skipped with the reason logged. Without `GITLAB_TOKEN` the survey warns that
  it saw public projects only, since the descriptor that results looks complete either way.

### Fixed

- **Two repositories with the same name in different groups are no longer treated as one.**
  Repository references were matched on their last two path segments, so on a forge that nests
  groups — GitLab most of all — `payments/backend/api` and `platform/backend/api` compared as the
  same repository. `draugr diff --repository` then kept the wrong findings, and a pull request
  could be annotated with another team's, on a file this checkout happens to share. Matching now
  uses the whole path, and still accepts a short form: a CI variable saying `org/repo` matches a
  descriptor's full clone URL, as it always did. Ports and credentials in a URL are handled too.

## [0.85.0] - 2026-08-13

### Fixed

- **A pull request is no longer annotated with another repository's findings.** A descriptor can
  describe several repositories — its own components, or ones a `fragments:` entry contributes from
  another project — and their paths are relative to themselves. Uploaded to code scanning here, a
  finding from elsewhere landed on a same-named file in this repository, on a line that does not
  have that problem. The GitHub Action now drops them from the upload; they remain in the scan, the
  artifacts and the pull-request comment. Findings belonging to no repository, like an image's, are
  unaffected.

### Added

- **`draugr diff --repository`** — keep only new findings from one repository, plus those belonging
  to none. What the Action uses for the above, and what to reach for when uploading to any surface
  whose paths anchor to a single checkout.

## [0.84.0] - 2026-08-12

### Fixed

- **Findings in different repositories, or different components, are no longer collapsed into
  one.** A finding's identity did not include the repository it came from, and the component it
  belonged to was written into the SARIF but never read back. Three consequences, each hiding a
  real finding:

  - A component holding two repositories reported **one** finding where both had the same file at
    the same line. The same leaked credential in two projects was reported once, with nothing to
    say the second existed — and the report named both repositories as scanned, so it looked
    complete.
  - `draugr diff` — the pull-request gate — dropped the component when reading a report back, so
    two components sharing a repository collapsed on every pull request.
  - The diff keyed findings on tool, rule, path and message only, so it collapsed them again even
    when the file carried enough to tell them apart.

  The repository now travels with a finding, both it and the component survive a round trip through
  SARIF, and the report shows a `Repository` column when findings span more than one — the same
  rule the `Component` column already follows.

  **This changes what a finding is, so every baseline is new.** The first `draugr diff` after
  upgrading compares old identities against new ones and reports the existing findings as fixed and
  re-introduced. It settles after one run: re-baseline, or expect one noisy pull request.

## [0.83.0] - 2026-08-12

### Changed

- **A rule in a diff is a link to what it means.** `CVE-2018-1000656` in a pull-request comment was
  a string to copy into a search box; it now points at what the scanner published about it — Trivy's
  advisory page for a CVE, the rule's own documentation for a static-analysis finding — falling back
  to NVD or the GitHub advisory database when a scanner published nothing, and to plain text when
  neither applies. In the terminal too, where the link costs no width.
- **The SARIF a pull request uploads carries the rules its findings cite.** A code-scanning alert
  arrived as a bare identifier: no description, and a link guessed from the identifier's shape
  rather than the advisory the scanner named. Only the rules the new findings cite travel — carrying
  the rest would put back the noise the diff upload exists to remove.

## [0.82.1] - 2026-08-12

### Fixed

- **`code-scanning: new` now reaches the caller.** The action's `sarif` output resolved to the scan
  step, while the diff step wrote the new-findings file — so the setting shipped in 0.82.0 wrote a
  file nobody could name, and an upload step still received the complete scan. Nothing failed: the
  run succeeded and the only symptom was the noise the setting exists to remove.

## [0.82.0] - 2026-08-12

### Changed

- **On a pull request, code scanning now receives the findings the pull request introduced.** The
  GitHub Action uploaded every finding in the repository, so a reviewer was annotated with hundreds
  they did not cause and the ones they did were lost among them. In diff mode `outputs.sarif` now
  names a SARIF of the new findings only. Set `code-scanning: all` for the previous behaviour; on a
  push there is nothing to diff against, so the upload is still the complete scan, and
  `outputs.report` is always complete.

  Worth knowing before you upgrade: **code scanning resolves any alert missing from an upload as
  fixed**, so the first PR run closes the alerts for pre-existing findings. That is the point on a
  pull request — those findings are still in the complete scan the default branch uploads.

### Added

- **`draugr diff --format sarif`** — the new findings, and only those, as SARIF. Fixed and
  unchanged are deliberately absent: a fixed finding is no longer there to annotate, and an
  unchanged one is the pre-existing noise this removes.
- **`draugr diff --min-priority P1`** — report only new findings at or above a band, in any format.
  It narrows the diff, never the scans it was computed from; a diff taken from filtered inputs
  reads every finding the filter removed as fixed.
- **`config.reports[].minPriority`**, and **`draugr scan --artifact-min-priority`** — narrow one
  written report to a priority band, leaving the others complete. For the SARIF that becomes review
  comments, where showing everything is why nobody reads any of it.

  `--min-priority` still narrows only what is printed. The difference is that these are *declared*:
  a narrowed artifact records the band inside itself, so nothing reading it later mistakes it for a
  complete scan — which matters because `draugr diff` reads a missing finding as a fixed one.
- **`code-scanning-min-priority`** on the GitHub Action, applying the band to what is uploaded.

## [0.81.1] - 2026-08-11

### Changed

- **`draugr feeds update` keeps a cached feed when the fetch fails**, instead of failing the run. A
  403 from CISA blocked a pipeline that already had the catalogue on disk. The step exists so a
  scan cannot rank everything as though nothing were exploited — and a cached catalogue does not do
  that: it ranks on data of a known age, and the report says how old. The failed fetch is reported
  with the age of the copy it kept, and warned about, so a run whose ranking is older than you
  think says so. With **nothing** cached there is no answer to keep, and it still fails.

## [0.81.0] - 2026-08-11

### Changed

- **`draugr survey k8s images` writes one component per namespace, not one called `cluster`.**
  Without `--namespace` it collapsed every image in the cluster into a single component and
  proposed no exposure for it — because one exposure covering everything running anywhere in a
  cluster would not mean anything. That is the right conclusion from the wrong shape: a namespace
  is what a team owns, so it is what a finding has to be attributed to, and exposure is a property
  of one namespace's topology. Every namespace now gets the same treatment `--namespace a,b`
  already gave the two you named — its own images, and its own proposed exposure.

  `--namespace` still narrows *which* namespaces are described. On a large cluster the unnarrowed
  survey is a lot of components, so name the ones you own.

  An image running in two namespaces now appears under both, which is what each component's
  surface actually is. The engine collapses identical targets when it plans, so scanning costs the
  same.

- **A survey writes the same YAML as everything else that touches a descriptor.** It used
  `yaml.Marshal`, whose default is four spaces — not a choice anybody made, and every other command
  that writes a Saga uses two. So `draugr classify` reindented a surveyed descriptor end to end the
  first time it set a field: a two-field edit that rewrote every line, which is a diff nobody
  reviews. `draugr init`, `classify`, `validate --resolved` and `survey` now share one definition.

- **`draugr survey --fragment` writes a Saga fragment** — components and nothing else — for a
  descriptor to include:

  ```bash
  draugr survey k8s images --namespace team-a --fragment -o team-a.saga-fragment.yaml
  ```

  A fragment is part of a descriptor rather than a thing to release, so it carries no `release:`
  and enables no controls; the descriptor that includes it decides what to run. `--name` and
  `--version` are refused alongside it, and `-o` has to end in `.saga-fragment.yaml`, because a
  fragment written under a Saga's name is read back as a Saga and rejected for having no release.
- **`draugr survey k8s images --no-exposure`** leaves `exposure` unset instead of guessing it from
  cluster topology. The lookups are skipped rather than made and discarded — they need permissions
  a namespace-scoped credential may not have.

### Added

- **A surveyed `exposure` says what it was read from**, in a comment beside the value:

  ```yaml
  components:
      - name: checkout
        exposure: public # a Service of type LoadBalancer exposes it
      - name: batch
        exposure: internal # no Ingress, external Service or NetworkPolicy found
  ```

  A proposal and a decision are the same three characters in a file, and exposure is what turns a
  severity into a P1 or a P3. The survey already named its guesses on the way out, but a terminal
  scrolls and the descriptor is what somebody opens later — so the reasoning is where the value is.
  Only proposals are commented; an exposure the descriptor already carried is left alone.

## [0.80.0] - 2026-08-10

### Fixed

- **The JSON report can tell you a control did not run.** `--format json` carried nothing about the
  errors that stopped a control — and a control that produced nothing at all had no verdict row, so
  it was absent from the document entirely. A pipeline parsing the JSON saw a shorter list of
  controls rather than a failure, with every remaining field describing what was found rather than
  what was attempted. Reading the JSON is exactly the case where nobody is watching the terminal
  that says otherwise.

  Each affected control now carries `scanErrors`, and a control that produced nothing is listed
  with `"verdict": "fail"` and no counts. Gate on it with
  `jq -e '[.controls[].scanErrors // empty] | length == 0'`.

### Added

- **`notMeasured` in the JSON report**, matching the console's `Not measured` section: the control,
  scanner, component and reason for anything planned and then not run. Not an error — nothing went
  wrong, so no `scanErrors` are recorded for it.

Both are omitted when there is nothing to report, so a clean run's document is unchanged.

## [0.79.0] - 2026-08-10

### Changed

- **A scanner that can only audit a whole cluster is skipped for a component that claimed part of
  one, instead of the descriptor being rejected.** Declaring a cluster twice — once narrowed to the
  namespaces a component owns, once whole — is a reasonable thing to write, and 0.78.0 refused it,
  asking you to turn the scanner off by hand for the narrowed component. Draugr already knows which
  scanners cannot be narrowed, so it works it out: `kubeBench` and `kubeBenchJob` run against the
  component that claims the whole cluster, `draugrK8sPolicies` runs against both, and nothing needs
  disabling. `draugr validate` accepts the descriptor again.

### Added

- **A `Not measured` section in the report**, naming any scanner that was planned and then not run,
  the component it could not answer for, and why:

  ```
  Not measured:
    infrastructure  kube-bench-job on team-a — audits the whole cluster and cannot be narrowed to namespace team-a
  ```

  A scanner that quietly does not run reads exactly like one that ran and found nothing, and the
  difference decides what a `PASS` is worth. Nothing is printed when every scanner could answer.

## [0.78.0] - 2026-08-10

### Fixed

- **A control's failure is printed under that control's own row.** It was gathered after the
  whole table, indented, where it sat against whichever control happened to be listed last — and
  because the message names a scanner rather than a control, nothing in it contradicted the
  misreading. An `infrastructure` failure read as a `secrets` one.
- **A scanner that cannot be narrowed to a namespace says what to do instead.** The refusal spent
  most of its length explaining itself and was cut off by the report's wrap before reaching either
  of the two fixes it offered. It now names both.
- **A scan no longer prints its failures three times.** Every error was logged above the report as
  well as appearing under its control and in the line the command exits with. The report and the
  exit are what remain.

### Changed

- **`draugr validate` rejects a namespace scope no enabled scanner can honour.** A component that
  narrows its infrastructure with `namespaces`, while `kubeBench` or `kubeBenchJob` is enabled, is
  asking for something neither can do — they audit the whole cluster or nothing. The descriptor was
  accepted, and you found out partway through a run, after a cluster had been contacted and a Job
  possibly created. Both halves are written in the file, so both are checked in it: `validate` and
  `scan` now name the component, the scanner, and the two ways out, before anything runs.
- **Jobs queueing for a shared scanner cache report it as a wait, not a warning.** The message
  said the cache was held by another scan, so a reader went looking for a second Draugr that was
  never running — the holder is another job in the same scan. The wait is still reported at the
  default log level, because a scan that took three times as long deserves a reason on the screen.

## [0.77.0] - 2026-08-10

### Fixed

- **`draugr tools install semgrep` no longer behaves like an installer.** It printed a plan,
  counted semgrep as a tool to install, asked you to approve it, took a yes — and then printed a
  `pipx` command, having installed nothing. Draugr does not distribute semgrep and never did; the
  plan says so, the prompt is skipped when there is nothing for Draugr to download, and the command
  you need is the whole output.
- **A scanner Draugr did not install now says which build ran.** The version came from Draugr's
  own install record, so a tool you brought had none — and that is the case the line exists for.
  It reported that Draugr had not installed the tool, which is a fact about Draugr rather than
  about the run, and nothing could be reproduced from it. The tool is asked directly now:
  `Scanner (unverified): semgrep 1.169.0 — found on PATH; Draugr does not distribute it (pipx)`.
- **The report distinguishes a tool Draugr did not install from one it does not distribute.**
  `Scanner (unverified): semgrep — found on PATH; Draugr did not install it` read as an omission
  worth fixing, and the command to fix it does not exist. A tool Draugr provisions now names
  `draugr tools install <tool>`; one it does not says so and names what does install it.

### Changed

- **`--scan=ask` asks the way the current protocol requires.** MCP 2026-07-28 forbids a server
  prompting while it is serving a request, which is how consent was obtained — so on a client
  speaking that version `--scan=ask` could not ask at all. The `scan` tool now returns the question
  and the client calls again with your answer; clients too old for that are asked the previous way
  by the SDK, so both work. A refusal, a cancellation, a client that cannot prompt, or an answer
  Draugr cannot read still all mean no scan.
- **The MCP SDK is updated to 1.7.0**, which the above unblocks.

- **An infrastructure finding says what the scan covered.** The scope was reported only when a scan
  was narrowed to namespaces, so a scan of the whole cluster and a scan whose scope nobody recorded
  looked the same — and that difference decides whether a finding is a namespace owner's to fix or
  the cluster owner's. It is now stated either way, beside the benchmark and the coverage:

  ```
  draugr-k8s-policies: benchmark cis-1.12 · coverage 20 of 34 checks decided · scope whole cluster
  draugr-k8s-policies: benchmark cis-1.12 · coverage 20 of 34 checks decided · scope namespace team-a
  ```

## [0.76.0] - 2026-08-10

### Added

- **A scan says what it is doing while it does it.** One line on the terminal, redrawn as jobs
  finish:

  ```
  scanning 3/11 · images/trivy ×2, sca/trivy-fs
  ```

  Between the first line and the report a scan printed nothing, and the jobs worth waiting on are
  the slow ones — an image being pulled, a benchmark Job waiting for a node — so a run that was
  working and one that had hung looked identical for as long as they lasted. Drawn only when
  stderr is a terminal, so a piped report stays parseable and a CI log keeps one line per event;
  `--no-tips` turns it off with the rest.
- **The report says what the run cost, and what it avoided.**

  ```
  Ran 11 jobs in 34.5s — 4 from cache, 1 shared with an identical job.
  ```

  The engine has counted all of this since caching was added and only the HTML report showed any
  of it, which left `--cache-dir` unverifiable from a terminal: a second run is faster, and nothing
  said whether the cache was the reason.

### Fixed

- **Ctrl-C no longer leaves a privileged Job running in your cluster.** Draugr installed no signal
  handler, so an interrupt terminated the process where it stood and every deferred cleanup was
  skipped — including the one that removes the `kube-bench-job` Job, which then ran on with nothing
  left to delete it or to say it was there. An interrupt now cancels the scan so those run, and
  says so; interrupting a second time stops immediately and warns that something may be left.
- **The GitHub Action can be published to the Marketplace.** Its description was 214 characters
  against a limit of 125 — a limit nothing enforces until the moment you publish a release that has
  already been tagged and built. It is shorter now, and a test fails if it grows back.

## [0.75.2] - 2026-08-09

### Fixed

- **A `kube-bench-job` whose pod the cluster refused says which plugin refused it.** A pod turned
  away by a CNI or admission plugin waits in `ContainerCreating` indefinitely, so the report named
  a condition and no cause — and then advised a longer `timeout`, which cannot fix a pod that will
  never start. The cluster's own warning is now included, and the advice follows the diagnosis:
  nothing scheduled it, the cluster refused it, or it is still working and waiting longer will help.
- **A `kube-bench-job` that ran out of time says what its pod was doing.** The wait reported
  `client rate limiter Wait returned an error: context deadline exceeded` — a message about
  Draugr's own Kubernetes client, in place of the one explaining what to do. It now names the pod's
  state, so `ContainerCreating` (wait longer) is distinguishable from a pod never scheduled (fix
  the node selector), and both from a genuine hang.
- **A scanner names every effect it needs at once.** Accepting them was a sequence of scans: allow
  `mutate`, run again, get refused for `privilege`, run again. `kube-bench-job` declares both, and
  the decision is whether to let it do all of it — so it is asked once, with a single
  `--allow-effects mutate,privilege` to copy.

## [0.75.1] - 2026-08-09

### Changed

- **A secrets finding says why it outranks its component.** The note read `↑ ranked as
  internet-facing: a credential is valid wherever it is valid` — the mechanism, printed against a
  component you had classified as internal, so it read as a claim about the component that you
  could see was untrue. It now states the conclusion: `↑ a leaked credential is high priority
  wherever it is found`.

### Fixed

- **A scanner that tried several ways reports why each failed.** A tool looking for an image ends
  its first line with `4 errors occurred:` and puts them on the lines after — so the report said
  the image could not be found in any of four places, and dropped the line saying the registry
  answered `401 Unauthorized`. That is the difference between checking the image name and logging
  in. A message ending by promising a list now carries it.
- **A failing scanner leads with what went wrong.** A tool's error is a chain running from general
  to specific, and Draugr has already said which scanner, control and component — so the tool's own
  account of what it was doing spent the whole message restating that, and pushed the words naming
  the failure off the end. An image that cannot be pulled reported `FATAL Fatal error run error …`
  and is now `… unable to find the specified image "…" in ["docker" "containerd" …]`. The log
  timestamp and level are dropped too.

## [0.75.0] - 2026-08-09

### Fixed

- **A scan with several images no longer loses some of them to a busy cache.** Every Trivy-backed
  control shares one on-disk cache, and Trivy takes an exclusive lock to write analysis results
  into it. Draugr scans images and repositories concurrently, so on a slow run two scans could want
  that lock at once and the one that waited too long failed outright — reporting a plausible
  finding count that was quietly missing whatever those images held. A scan that finds the cache
  busy now waits and tries again, up to three times, and says so each time it waits. Anything else
  still fails immediately.
- **Four documentation pages describe what the commands actually do.** The CLI reference claimed
  the retired `survey` flags error with the subcommand that replaced them; they are rejected as
  unknown flags. The `k8s-cluster` example passed `--merge`, which no longer exists. The Saga
  reference still described prioritization as something that would feed in once it shipped. And the
  quickstart carried a half-written note where a token was meant to be explained.
- **A tool's error keeps the part that says what went wrong.** The first line of a failing
  scanner's output was clamped to fit a terminal line, from the front — and a tool reports a
  wrapped chain whose cause is at the *end*. A Trivy failure arrived as `unable to initialize
  cache: unable to…`, which is true of that failure and of nothing else; the words that named it
  (`cache may be in use by another process: timeout`) were the ones cut. The middle is elided now,
  so both the operation and the cause survive.

### Changed

- **`--help` says what a command does, not why it works that way.** Every command's description
  carried the reasoning behind its design as well as its usage — `draugr mcp` ran to 211 words, a
  paragraph of which argued why pointing an assistant at Draugr beats letting it improvise. The
  reasoning is in the docs, where somebody who wants it goes looking; in a terminal it sits between
  you and what you are trying to do. Descriptions are a fifth shorter and the instructions are
  easier to find.
- **Three runtime messages state the fact and stop.** A scan that planned no jobs, a scan that
  could not use `--allow-scan-errors`, and a stale feed each explained the decision behind the
  message as well as the message. They now say what happened and what to do about it.

## [0.74.0] - 2026-08-09

### Changed

- **`draugr survey` says which exposures it guessed.** Surveying a Kubernetes namespace proposes
  each component's `exposure` from cluster topology, and the value landed in the descriptor
  looking exactly like one you had chosen — while being the input that decides whether a finding
  is P1 or P3. Every proposal is now named on the way out, with the value picked:

  ```
  exposure proposed from cluster topology, not confirmed — run `draugr classify` to set it:
    payments      public
    cert-manager  internal
  ```

  A component that already carries an exposure keeps it and is not listed: the merge does not
  overwrite a decision, so there is nothing there to confirm.
- **Your editor now completes inside a control, not just up to it.** Typing
  `controllers.sast:` used to offer nothing further — not `semgrep`, not `gosec`, and none of the
  options either takes — because the schema described only `enabled` and accepted any key beside
  it. It now names each control's scanners and the options each declares, with the same
  descriptions `draugr controls --options` prints, so a mistyped scanner or an option a scanner
  does not take is flagged as you type rather than when you run it.
- **`draugr survey` adds to an existing descriptor instead of overwriting it.** A descriptor
  carries decisions a survey cannot rediscover — exposure, criticality, exclusions, controls
  somebody chose — so replacing it has to be asked for, with `--replace`. **`--merge` is removed**
  — it asked for what now always happens. Drop it from any script that passes it; the flag is
  rejected rather than ignored, so a pipeline still passing it fails rather than quietly doing
  something else.
- **`draugr controls [control]`** narrows everything to one control, because `--options` across
  eleven of them is a screenful you scroll past to find the one you were writing. A name that is
  not a control says so and lists the ones that are.
- **A truncated finding list points somewhere useful.** `… and 24 more finding(s)` used to be
  followed by advice about `--format json` — a machine format, offered to somebody reading a
  human-readable list. It now suggests `--top 0` and `--min-priority`, with the machine formats
  on their own line.
- **Console output states the fact and stops.** The lines under a finding explaining why it
  ranked where it did, or that it came from git history, were arguments rather than labels — and
  they print on every matching row of a table people scan rather than read. They are one short
  line now; the reasoning stays in the docs, where somebody who wants it will look.
- **`draugr init` names the file it found**, rather than reporting `# Detected: dependency
  manifest` and leaving you to work out which one it meant.
- **`draugr classify` finds your descriptor.** It took a filename and nothing else, so the
  command after `draugr scan .` was the one that made you type the path. It now takes a directory
  or no argument at all, exactly like a scan.
- **`draugr classify --components gateway,api`** asks about the components you name and leaves
  the rest alone. Naming one re-asks about it even if it is already classified, so correcting a
  single component no longer means `--all` and re-answering for every other one. A name that
  matches nothing is an error listing the components that exist.
- **Every `[link](#heading)` in the docs goes where it says.** Twelve pointed at headings that had
  been renamed, most of them into the CLI reference from the guides that link to it, and a
  duplicated heading in the Saga reference. A dead heading link renders as an ordinary one and
  jumps nowhere, so nothing but a reader following it ever notices — the gate checks them now.
- **`draugr tools install` reports what changed.** It printed the plan — every tool, its version,
  where it lives, which were already current — and then printed the same list again as it walked
  it, so one download arrived buried under seven lines saying nothing had happened. The tools that
  did not change are counted now (`7 tools unchanged.`), and a tool that turns out not to be
  current after all is still installed and still named.

### Fixed

- **`format: vex` is no longer rejected by editors.** The schema's list of report formats was
  written by hand and had fallen behind the CLI, so a descriptor asking for a VEX document was
  valid to Draugr and flagged by your editor. The list is generated now, and a test fails if a
  renderable format is missing from it.
- **A list option's accepted values are shown, not just enforced.** `draugr controls --options`
  and the schema both now report that `pkgTypes` takes `os` or `library`, rather than silently
  accepting a third value and letting the scan reject it.
- **The `infrastructure` control passed its own `enabled` flag to its scanners**, so a descriptor
  that merely turned the control on failed with `unknown option "enabled"` — naming a key nobody
  wrote where it was reported. Scanner blocks were leaking the same way. Both are now stripped,
  and genuine control-level settings like `context` still reach every scanner.
- **`draugr survey --namespace` fails on a namespace that does not exist.** Listing pods in a
  namespace that is not there returns an empty list rather than an error, so a typo produced a
  survey that succeeded, discovered nothing from that namespace, and said nothing about it —
  and the descriptor that resulted became the scope of every later scan. A namespace that exists
  but is empty is reported too, since silence there reads as "found your images".
- **`draugr survey --merge` no longer discards what the new survey learned.** An entry matching
  one already in the descriptor was dropped whole, so a second survey that resolved an image
  digest, narrowed a repository's `paths`, or named a host it had previously only seen by URL
  left none of that behind — and the summary still counted the entry, so the file said what it
  said before while the command said it had merged. Matching entries are now merged rather than
  skipped.

  The case that surfaced it: `survey k8s cluster --namespace <ns> --merge` reported success and
  changed nothing, because the cluster was already in the descriptor.

- **A cluster scope is never quietly narrowed.** Merging a namespace-scoped survey into a
  descriptor that covers the whole cluster keeps the whole cluster, and says so. Two scoped
  surveys union. A descriptor that silently began scanning less than it did the day before is the
  dangerous direction for this to be wrong in, and nobody re-reads a descriptor to check that it
  still covers what it used to.

## [0.73.1] - 2026-08-08

### Fixed

- **A secret found in git history no longer reports a path that may not exist.** With
  `gitleaks: {history: true}`, Gitleaks names the path a secret had in the commit that introduced
  it — so a file since renamed was reported under a directory that had been deleted, and the
  finding read as something already cleaned up. That is exactly backwards when the credential is
  still in the working tree.

  `history: true` now scans the tree **and** the history. A live secret is reported at the path it
  is at now; a history finding says so, with the commit:

  ```
  P1  high  github-pat  secrets  gitleaks  old/scripts/check.ps1:1
          ↩ found in commit history — this path is as it was then, and may have moved or gone
            since. Still needs rotating: removing it from the tip does not unpublish it.
  ```

  A secret genuinely removed from the tip is still reported, marked as history — removing it is
  not remediation, because it remains fetchable by anyone who can clone.

## [0.73.0] - 2026-08-08

### Changed

- **A leaked credential now ranks P1 wherever it is found.** The `secrets` control ranks its
  findings at the context tier a public, business-critical component gets, whatever the component
  actually declares — because a credential is valid wherever it is valid, and git history is often
  readable by more people than the service is reachable by.

  This replaces the P2 floor with the position it was a compromise between. `--fail-on-priority P1`
  is the gate the documentation recommends, so anything lower meant a credential failed the
  severity gate and passed the priority one — the same contradiction, one band over.

  A tier rather than a fixed band: severity still decides the row, so a critical finding and a
  high one do not collapse into one because they share a control. A finding you have judged still
  belongs in `config.exclude`, where it stays in the report marked suppressed with your reason.

## [0.72.0] - 2026-08-08

### Changed

- **A leaked credential is never ranked as routine.** Priority folds in a component's exposure and
  criticality, which is exactly right for a dependency CVE and wrong for a credential: a
  credential is valid wherever it is valid — a cloud account, a registry, an artifact store — and
  git history is often readable by more people than the service is reachable by. The `secrets`
  control now declares a **P2 floor**, so a secret on an internal supporting component is "this
  cycle" rather than backlog, and the report says why:

  ```
  P2   high   -   github-pat   secrets   gitleaks   cfg.txt:1
       ↑ not damped by exposure — a credential is valid wherever it is valid, not only where
         the component sits
  ```

  A floor, not a fixed band: exposure still raises a credential on a public critical component to
  P1. Controls that declare no floor are unchanged.


- `draugr mcp`'s `scan` result now states its own scope: the controls that ran, any surface your
  descriptor declares that no enabled control looked at, and the classes a control-based scan
  does not cover — trust boundaries, build-context hygiene, how credentials reach a subprocess.
  An assistant handed a verdict can now tell what the verdict answers, and carry on from there
  with the reproducible part already settled.
- **An option a scanner does not accept is now an error, not a silent no-op.** Every scanner
  declares the options it takes, so `gitleaks: { severity: high }` fails validation naming the
  key instead of being dropped between the descriptor and the tool. Several scanners were also
  reading options nothing documented: `kube-bench` (`targets`, `benchmark`, `version`, `context`,
  `configDir`), `kube-bench-job` (those plus `namespace`, `image`, `nodeSelector`, `timeout`),
  `trivy-license` and `mend-licenses` (`deny`, `warn`), and the Mend scanners (`productToken`,
  `project`, `resultTimeout`, `settings`). All are now declared and listed.
- **A missing scanner now tells you how to install it.** `sast` and `secrets` failing with
  `executable file not found` was correct and unhelpful — most likely to happen on a first scan,
  when Draugr is installed and nothing else is:

  ```
  secrets  ERROR  did not run
           run gitleaks: … executable file not found in $PATH — run `draugr tools install gitleaks`
  ```

  For a tool Draugr does not distribute, it says so instead of suggesting an install that would
  find nothing.

### Added

- **`secrets` can scan git history.** A credential committed and later removed is still fetchable
  by anyone who can clone, so it is still compromised — and a scan of the tree alone will not find
  it. Ask for it per repository:

  ```yaml
  config:
    controllers:
      secrets:
        gitleaks:
          history: true
  ```

  Off by default because it needs a full clone rather than a shallow one, which is slower on a
  large repository. A good split is history on a schedule and the tree on every pull request.
  The `secrets` docs also now show how to handle a vendor identifier that authenticates nothing —
  a product or tenant token is 64 hex characters, which is what an API key looks like — with
  `config.exclude`, so the finding stays in the report marked suppressed rather than being moved
  out of the descriptor to hide from the scanner.
- **The MCP scan approval describes the scan in front of you.** `draugr mcp --scan=ask` now names
  which controls will run over how many components, which scanners do more than read, whether
  anything sends traffic to a live host you declared, and where results will be delivered. Five
  read-only controls over a checkout and a `dast` run against a production host are different
  decisions, and the person answering is often not the person who wrote the descriptor.
- **A scan through MCP honours the descriptor's `reports` and `publishers`**, as `draugr scan`
  does, and the result names where each landed. A conversation is the least durable place a
  finding can end up; a saved report is one your assistant can point you at, or read back with
  `summarize_report` instead of scanning again.
- **Per-scanner options for `gitleaks`, `gosec`, `trivy`, `trivy-fs` and `trivy-config`.** Point
  Gitleaks at a ruleset shared across repositories (`config`); select gosec rules and build tags
  (`include`, `exclude`, `tags`); narrow Trivy to a package type or pull its database from an
  internal mirror (`pkgTypes`, `dbRepository`); and run your own Rego alongside Trivy's built-in
  misconfiguration checks (`checks`, `namespaces`).

  None of them filters findings, deliberately: `--severity` and `--ignorefile` drop findings
  inside the tool, where a suppression cannot be recorded or reviewed. Use `exclusions` for a
  finding you have judged — it stays in the report, marked suppressed with your reason — and the
  gate thresholds for what fails a build.
- **`draugr controls --options`** — what each scanner accepts in its Saga block, read from the
  same schemas the gate enforces, so it cannot drift from what is actually validated. A scanner
  shown with no options is configured by choosing it.
- The MCP `list_controls` tool returns the same option lists, so an assistant writing a
  descriptor stops guessing at keys.

## [0.71.0] - 2026-08-07

### Added

- **`--log-file <path>` keeps the whole run, while your terminal keeps the summary.** Trace
  output is bigger than a scrollback and it is what you attach to a bug report, so one
  `--log-level` was never going to serve both:

  ```bash
  draugr scan . --log-file draugr.log   # nothing extra on screen; everything in the file
  ```

  The terminal keeps whatever level you asked for. The file gets every record at `trace`, with
  **no ceiling** on how much of a tool's output is kept — on the same scan, a terminal shows
  about 5 KB and says it truncated, and the file holds 80 KB and did not.

  Appended rather than truncated, since the second run is usually the one that reproduces the
  problem. Written `0600`, never coloured. A path that cannot be opened **fails the run** instead
  of being skipped.

- **`--components` and `--controls` scope a scan**, for iterating on one failing component or one
  control without waiting for the rest — and without editing the descriptor, which is how a
  temporary change gets committed:

  ```bash
  draugr scan --components app,frontend
  draugr scan --components app --controls sca --log-level debug
  ```

  **A scoped run still gates.** Answering *"is my fix good?"* with "no verdict" would send you
  back to a full scan. What it never does is look like an unscoped one:

  ```
  Draugr — FAIL   (multi 1.0.0)   (scope: 1 of 3 components; sca)

  Components:
    app       FAIL   P1 9  P2 8  P3 1  sca
    frontend  not scanned  (--components)
    payments  not scanned  (--components)
  ```

  Skipped components are listed rather than omitted, the scope is recorded in `report.json` and in
  the SARIF, and **`draugr diff` refuses to compare runs of different scope** — every finding the
  head did not look for would otherwise be reported as fixed. A name matching nothing is an error,
  not an empty scan that passes.

- **`draugr survey k8s` takes more than one `--namespace`.** The descriptor's
  `infrastructure.namespaces` is a list, so someone who owns three namespaces could describe that
  and not discover it.

  ```bash
  draugr survey k8s images --namespace payments --namespace checkout -o draugr.saga.yaml
  ```

  Each namespace becomes **its own component, with its own proposed exposure** read from its own
  topology — which is the difference from naming none. A whole-cluster survey is a single
  component and proposes no exposure, because one value covering everything running anywhere in a
  cluster would not mean anything.

- **`draugr scan` now points out things about the run you would otherwise have to know to look
  for.** Up to two one-line tips follow a console report, each gated on the run it describes:

  - the run **passed while carrying P1 or P2 findings** and nothing gates on priority — the one
    case where the verdict is right and your reading of it is not;
  - it looks like **CI, and the report exists only in this log** — no `-o` and no
    `config.publishers`, so the evidence goes wherever the log does;
  - **no component sets `exposure` or `criticality`**, so priorities are severity alone;
  - the run **took over a minute with no `--cache-dir`**.

  Two per run at most, in that order. A block of five tips is one nobody reads, so the cap is
  deliberate. `--no-tips` or `DRAUGR_NO_TIPS=1` silences them, as before.

- **The uncovered-surface note now says why `dast` is not on its list.** A component declaring
  hosts with `headers` and `tls` off is told so — and told that `dast` is never suggested,
  because it sends attack traffic at a live service and that is a decision to make rather than
  one to be nudged into.

- **Mend can also serve the `licenses` control**, reporting the licence of every dependency it
  resolved:

  ```yaml
  config:
    controllers:
      licenses:
        mendLicenses: { enabled: true, productToken: "…" }
        deny: ["GPL-3.0-only"]
  ```

  It shares one upload with `mend-sca`, so enabling both scans your dependencies once rather than
  twice — and it works with `sca` disabled or served by Trivy, because the upload belongs to
  neither.

  **Two things to know before enabling it.** Mend often reports licences by its own names rather
  than SPDX identifiers (`"BSD 3"`, not `BSD-3-Clause`); those are used as-is and the scan warns,
  listing what the run produced, so you can write rules against the strings that will actually
  appear. And Mend supplies no licence *category*, so this scanner reports only the licences your
  policy names — where Trivy would also flag copyleft you never listed.

### Changed

- **`--log-level debug` and `--log-level trace` are readable now.** Debug output is where you go
  when a run did something you did not expect, and it was rendered in one weight — finding the
  line that mattered meant reading all of them.

  Each part of a record now carries its own weight: the **message** strongest, because that is
  what you scan for; the level coloured; timestamps and attribute keys dimmed; values plain. An
  `error` or a non-zero `exit_code` is coloured, since in a few hundred debug lines that is
  nearly always the one you are looking for.

- **A relayed tool stream prints as a block, not as an escaped attribute.** At trace level a
  scanner's whole stdout arrived as one quoted `slog` value, escapes and all — correct for
  `--log-format json`, and the opposite of useful for the case you reach trace in:

  ```console
  10:35:10 TRACE  tool stdout tool=trivy
    ┌ stdout
    │ {
    │   "version": "2.1.0",
    …
    └
  ```

  Colour changes the rendering and never the text, so records stay greppable; `NO_COLOR=1`, a
  pipe or a redirect give the same output without the escapes, and `--log-format json` and `text`
  are untouched.

## [0.70.0] - 2026-08-07

### Added

- **Mend can serve the `sca` control**, alongside Trivy or instead of it:

  ```yaml
  config:
    allowEffects: [mutate]
    controllers:
      sca:
        mendSca:
          enabled: true
          productToken: "…"
  ```

  Credentials come from `MEND_URL`, `MEND_EMAIL` and `MEND_USER_KEY` — never the descriptor. The
  product token does live there, because it identifies a product rather than granting access, and
  a component can point at a different one.

  **Opt-in, and it requires `mutate`**, because a scan creates a project in your Mend account that
  outlives it. Draugr will not write into a third party's account because a scan happened to run.

  A scan that resolved no dependencies from a tree that declares them is reported as a control
  that **could not run**, not as a clean pass — the Mend agent exits successfully in that case and
  replaces the project inventory with nothing, which every other signal would read as "no
  vulnerabilities found".

  Install the Mend CLI yourself; Draugr executes it and never distributes it, and `draugr doctor`
  says where it comes from.

### Fixed

- **A VEX product identifier no longer goes stale when you cut a release.** A VEX statement is
  about a *version* of a product — `not_affected` in 2.3 says nothing about 2.4 — so a
  `config.vex.product` with the version written into it kept claiming the old one after the
  release moved on, quietly, in a document you had signed.

  Leave the version out and Draugr appends `release.version`:

  ```yaml
  release: { name: acme-api, version: "2.4.0" }
  config:
    vex:
      product: "pkg:oci/acme/api"     # → pkg:oci/acme/api@2.4.0, and follows the release
  ```

  A version you write yourself is kept exactly as given, since pinning to a digest is often the
  point. Qualifiers and subpaths are preserved, and a `product` that is not a package URL is
  left untouched.

  The docs now also spell out what `release` and `config.vex` are each for: `release` is what
  you call the product internally, `config.vex.product` is the identifier a consumer matches
  against — and getting the second wrong means the document is read, understood, and applied to
  nothing.
- **A local checkout is now named by the repository it came from.** `url: .` reported as `.`,
  so a scan on a laptop and a scan in a pipeline were two unrelated sources — different cache
  entries, and nothing `draugr diff` could compare. Draugr now resolves the checkout's git remote:

  ```
  Scanned: https://github.com/acme/sample.git at 4c71c87c
  ```

  A checkout with no remote keeps its path, which is the only name it has and the one a reader
  can act on. The URL used to clone is unchanged.

- **A repository's credentials no longer reach reports, filenames or cache keys.** A clone URL of
  the form `https://oauth2:TOKEN@github.com/acme/api.git` — the ordinary shape in CI — had its
  token carried verbatim into the `Scanned:` line, the SARIF repository provenance and generated
  SBOM filenames.

  A finding is about a repository, not about who fetched it, so the username and any credentials
  are now **dropped** from everywhere a repository is named rather than merely hidden. The URL
  used to clone is untouched, because fetching is the one thing they are for.

  Two consequences beyond the leak. Azure DevOps URLs (`https://my-org@dev.azure.com/…`) no longer
  carry the organisation twice. And two people scanning one repository with different credentials
  now produce the **same** identity, so they share a cache entry and read as one source in a
  report instead of two.

## [0.69.0] - 2026-08-05

### Added

- **Mend can now serve the `sca` control**, alongside Trivy or instead of it:

  ```yaml
  config:
    allowEffects: [mutate]
    controllers:
      sca:
        mendSca:
          enabled: true
          productToken: "…"
  ```

  Credentials come from `MEND_URL`, `MEND_EMAIL` and `MEND_USER_KEY` — never the descriptor. The
  product token does live there, because it identifies a product rather than granting access, and
  a component can point at a different one.

  It is **opt-in and requires `mutate`**, because a scan creates a project in your Mend account
  that outlives it. Draugr will not write into a third party's account because a scan happened to
  run.

  A scan that resolved no dependencies from a tree that declares them is reported as a control
  that **could not run**, not as a clean pass — the agent exits successfully in that case and
  replaces the project inventory with nothing, which every other signal would read as "no
  vulnerabilities".

### Added

- **Saga fragments: split a descriptor across files.** A descriptor half of which is
  `config.exclude` is two things in one file — a structural account of the system, and a log of
  dated decisions by named people. They change at different times, for different reasons, and get
  reviewed by different people. `fragments:` lets them live apart:

  ```yaml
  # azure.saga.yaml
  release: { name: acme-azure, version: "3.1.0" }
  fragments:
    - path: "**/draugr.saga-fragment.yaml"    # every component's shared description
    - path: "**/azure.saga-fragment.yaml"     # plus the Azure-specific parts
  ```

  A fragment carries `components`, `config.exclude` and further `fragments` — it **adds scope or
  adds attributed suppressions, and can never change policy**, so pulling one in cannot quietly
  lower your gate or switch a control off.

  Two fragments naming one component **merge into one**, so a shared fragment can declare the
  repository and a per-cloud one add the image. That makes a monorepo serving several products
  work without duplicating anything: name the audience in the file's stem, and each product's
  Saga globs the exact stems it wants. Adding a component is one directory and no edit to either
  product's Saga.

  Globs use the descriptor's usual dialect (`*` within a segment, `**` across them), resolve
  relative to the file that names them, and a pattern matching **nothing is an error** — silence
  from a line somebody wrote on purpose is indistinguishable from a typo.

- **`draugr validate --resolved`** prints the descriptor with every fragment merged in, each
  block attributed to the file it came from. Provenance is emitted as comments, so the output is
  both the answer to "what is actually in force" and a valid descriptor you can scan — which is
  how you flatten a descriptor to carry across an air gap, or commit one to diff in CI so a
  one-line `fragments:` change is reviewed by its effect rather than its cause.

- **Fragments can live in another repository**, so a platform team can publish component
  descriptions once and every product pull them in:

  ```yaml
  fragments:
    - url: https://github.com/acme/platform.git
      revision: v2.4.0
      path: "components/**/draugr.saga-fragment.yaml"
  ```

  `revision` is **required** — without it your gate could change with no commit in your own
  repository. A tag is fine: the commit it resolved to is recorded, so a tag that moves is visible
  afterwards. Several fragments from one repository share a single clone.

  Offline, an unreachable fragment is an **error**, never a quietly smaller scan. Resolve on a
  connected machine and carry the flattened descriptor across instead —
  `draugr validate <saga> --resolved > flat.saga.yaml` — which is reproducible as well as
  portable.

- **`draugr init --fragment`** scaffolds a fragment, naming the component after its directory —
  the field that has to match for a component's fragments to merge into one.

- **`draugr schema --fragment`** prints the fragment schema this build enforces, for pinning or
  air-gapped editor validation.

- **The report says which file suppressed what** once exclusions live in more than one place:

  ```
  3 findings suppressed — 2 from extra.saga-fragment.yaml, 1 from sup.saga.yaml — 3 accepted by …
  ```

  A descriptor that is a single file reads exactly as before.

- **A published schema for fragments**, at
  `https://draugr.dev/schema/draugr.saga-fragment.schema.json` and in `draugr schema --fragment`.
  Editors validate a fragment as a fragment, and `draugr validate` checks one on its own.

### Removed

- **`componentsMetaSources`**, replaced by `fragments`, which does the same job for local and
  remote files with one key. It never resolved anything, so a descriptor using it was silently
  doing nothing; it is now a parse error naming the replacement.

## [0.68.0] - 2026-08-05

### Changed

- **Draugr's own release archives now ship a CycloneDX SBOM** (`*.cdx.json`, previously
  `*.sbom.json` in SPDX). Same format `config.sbom` produces by default, so the tool and its own
  artifacts agree about what an SBOM looks like here.

### Added

- **`--report vex` publishes an OpenVEX document** — for every vulnerability a scan saw, whether
  it affects your product and on whose authority. Your customers stop asking by email, one at a
  time, whether the CVEs in your SBOM matter.

  Most of it is already in your descriptor: a suppression keeps its reason, who accepted it and
  when that lapses, and those are most of a VEX statement. A finding nobody has triaged is
  published as `under_investigation`; a suppressed one as `affected`, carrying your reason.

  To claim a vulnerability cannot affect you, say so — Draugr will not read your `reason` and
  decide you meant it:

  ```yaml
  config:
    vex:
      author: "Acme Ltd <security@acme.example>"
      product: "pkg:oci/acme/api@2.4.0"
    exclude:
      - rules: ["CVE-2018-18074"]
        reason: "The redirect path that leaks the header is never taken; we pin the host."
        vex:
          status: not_affected
          justification: vulnerable_code_not_in_execute_path
  ```

  Trivy and Grype both read the result, so you can check it against a real consumer:
  `trivy image acme/api:2.4.0 --vex openvex.json`. The document is deterministic and its `@id` is
  a digest of its own content, so it can be committed and reviewed like any other file. See
  [publish a VEX document](docs/guides/vex.md).

- **`config.sbom.scope: project` produces one SBOM for the whole release**, instead of one per
  repository and image. SBOMs are asked for per product — a customer questionnaire, EO 14028 and
  the CRA all want the bill of materials of the thing you shipped — so a project with four
  repositories and three images used to produce seven documents and no answer to the question.

  ```yaml
  config:
    sbom:
      enabled: true
      scope: project      # component (default) | project | both
  ```

  The assembled document's root is the release, with a node per component, per repository or
  image, and then the packages. A package shared by three components appears **once**, with the
  graph recording which targets contain it — so "what do we ship" and "who ships it" are both
  answerable, and two versions of one library stay two packages. `both` keeps the per-target
  documents alongside the assembled one.

  CycloneDX JSON only for now, and it says so if you ask for anything else.

### Fixed

- The Saga JSON Schema still offered `spdx-json` as the SBOM default, so editor autocompletion
  disagreed with what a scan produced.

- **Generated SBOMs no longer embed the temporary checkout path.** A repository SBOM recorded each
  file it hashed by absolute path inside a throwaway directory, so scanning the same commit twice
  produced different documents and the inventory disagreed with the findings about where anything
  lived. Paths are now repository-relative, like `app/requirements.txt`.

## [0.67.0] - 2026-08-04

### Changed

- **Generated SBOMs are CycloneDX JSON by default** (previously SPDX JSON). A CycloneDX document
  can carry nested components and state how complete it is, so it can describe a whole project
  and not only one repository; it is also what most security tooling reads first. SPDX remains
  fully supported and is often the name a procurement or licence-compliance process asks for —
  set `config.sbom.format: spdx-json` to keep it. Anything consuming `sbom-*.spdx.json` by
  filename needs either that setting or a new filename.

## [0.66.0] - 2026-08-04

### Added

- **A `virustotal` scanner for the `threats` control**, opt-in beside `urlhaus`:

  ```yaml
  config:
    controllers:
      threats:
        enabled: true
        virustotal: { enabled: true }
  ```

  Two or more of VirusTotal's engines calling a domain malicious is an error; a single detection
  is a warning, because one engine flagging a legitimate domain is routine and failing a build on
  it is how a control gets switched off.

  **Domain reports only.** VirusTotal's terms attach sharing to "Sample submissions" — files and
  URLs sent for analysis — and a domain report is a lookup of an aggregate they already hold. The
  scanner has exactly one endpoint and a test that it has not grown another. Opt-in because a
  second feed means a second party told about your hosts.

- **Scanners can declare a rate limit, and Draugr respects it without slowing the run.** A scanner
  implementing `plugin.RateLimited` says how often it may be called; the engine spaces its calls
  out **before** taking a concurrency slot, so a hosted API allowing four requests a minute does
  not leave workers idle while every other control queues behind it.

  This is why `virustotal` needs no tuning: three hosts take about thirty seconds, nothing else
  waits, and you do not have to lower `--jobs` to avoid a 429. A paid key raises the limit with
  `requestsPerMinute`.

- **`threats` control** — asks whether your own hosts are already known to be serving malware,
  via [abuse.ch URLhaus](https://urlhaus.abuse.ch/).

  ```yaml
  config:
    controllers:
      threats: { enabled: true }
  ```

  It answers a question no scan of your own endpoint can. A scanner you point at your host checks
  the paths you know about; this asks whether somebody else has already seen that host serving
  malware — from a path you never deployed and would never think to probe. A hit means either a
  compromise you have not found, or a name that was abused before you held it.

  Malware being served **now** is an error; a host that served it once and no longer does is a
  warning. Treating a years-old record as an emergency is how a control gets switched off.

  Two things to know before enabling it. It **tells abuse.ch that your hosts exist** — declared as
  an effect, shown in `draugr controls` and in `draugr doctor`'s list of outbound calls, and the
  hostname is all that is ever sent. And abuse.ch's **free tier is non-commercial**: the key is
  free from https://auth.abuse.ch/ and goes in `URLHAUS_AUTH_KEY`, but commercial use is routed
  through a Spamhaus subscription, so read https://abuse.ch/terms-of-use/ before you rely on it.

  Offline, the control refuses and names the host it would have asked about, rather than passing
  quietly with nothing checked.

  VirusTotal, the optional second connector in the original issue, is **not** included: its terms
  and privacy notice are not readable by automation, and for a control whose whole risk is what a
  third party learns about your infrastructure, that is not something to infer from behaviour.

- **Running one Trivy server for the fleet is documented**, and needs nothing from Draugr — it
  passes its environment through, so `TRIVY_SERVER` is enough. Measured with an empty local
  cache: the `sca` control returned its usual findings and downloaded no database at all.

  The guide is explicit about the gap, because it is easy to miss: Trivy's client/server mode does
  not support `trivy config`, so the `iac` control still runs locally, and Gitleaks, Semgrep and
  Nuclei keep their own data regardless.

- **Cache settings live in `draugr.config.yaml`.** A cache directory is a fact about a runner
  image, not about an application, so every pipeline on that runner can share one setting instead
  of repeating four flags:

  ```yaml
  cache:
    dir: /var/cache/draugr
    ttl: 24h
    requireDigest: true
  ```

  A flag you type always wins — including `--cache-ttl 0` for no expiry, which is a deliberate
  instruction rather than an absent one. `readOnly` and `requireDigest` only ever turn *on* from
  the config, so a project file that never mentions caching cannot undo a machine that declared
  its results untrustworthy.

_Nothing yet._

## [0.65.0] - 2026-08-04

### Changed

- **A repository is checked out once per scan, not once per control.** Every repository scanner
  used to clone for itself, so a five-control scan cloned the same repository five times.

  At default concurrency this is not faster — the clones overlapped, so they cost about the
  wall-clock of one. What it saves is **bandwidth and disk**, in proportion to how many controls
  you run: on a four-control scan of a small repository, peak checkout disk halved. On a runner
  with constrained concurrency it is also faster (measured 3.35s → 1.62s at `-j 1`).

  The reason to do it anyway is agreement: independent clones of a branch that moves mid-scan can
  resolve to different commits, so two controls could report against different code while the
  report named one revision. One checkout per run removes the possibility.

  The shared checkout is **read-only**, so a tool that writes into what it scans fails where it
  writes rather than quietly changing what the next scanner reads.

## [0.64.0] - 2026-08-04

### Added

- **`draugr scan --working-tree`** scans the checkout as it is on disk, uncommitted work included.

  A scan reads the committed revision, which is what makes a report reproducible — and what makes
  the loop of fixing a finding need a commit per iteration. Now it does not:

  ```
  Scanned: . working tree at 3f9a1c2b+ (7 uncommitted files, not reproducible)
  ```

  It reads a **copy**, so scanners cannot write into your files and `paths`/`ignore` scoping prunes
  the copy rather than your work. The file list is git's own (`ls-files -co --exclude-standard`),
  so an ignored `node_modules` or `.env` stays out for the same reason a commit would leave it out.
  These scans are never cached, since two runs at one revision read different bytes. A remote
  repository is refused by name rather than quietly scanned at its committed revision.

- **The report names the revision it describes.**

  ```
  Scanned: . at 3f9a1c2b (7 uncommitted files not included)
  ```

  A scan reads the committed revision rather than your working tree so that a report names
  something reproducible — but the report never said which commit that was, and the only thing
  said out loud was a warning on every local run about the revision it was *not* reading. The
  commit is now in the console, Markdown and HTML reports and in the JSON under `repositories`,
  and the uncommitted count travels with it as a clause rather than a warning. The warning is
  gone.

- **A reusable Azure Pipelines template.** `azure-pipelines/draugr.yml` collapses the install,
  scanner provisioning, scan, pull-request diff and publishing into one reference. Copy it into
  your repository and the pipeline is four lines of Draugr:

  ```yaml
  steps:
    - template: .azure/draugr.yml
      parameters:
        saga: draugr.saga.yaml
  ```

  Parameters for the descriptor, the mode (`auto` scans a push and diffs a pull request), a pinned
  version, scanner provisioning, the priority to gate on, and whether to publish results.

- **`draugr scan --no-gate`** reports the verdict and exits 0 anyway. It is what the two scans
  either side of a `draugr diff` need: their job is to produce reports, and the diff is the gate.
  Without it the base scan's `FAIL` — which any repository with a backlog produces — takes the
  whole CI step down before the comparison runs.

  It suppresses the *verdict's* exit code and nothing else. A scan that could not run still fails,
  so a missing report can never reach a diff disguised as "no new findings" — which is exactly
  what `|| true` in a pipeline does instead.

- **A worked `draugr diff` pipeline for Azure DevOps.** GitHub's action hides the two-scan dance
  behind `mode: auto`; Azure has no first-party task, so
  [the guide](https://github.com/draugr-dev/draugr/blob/main/docs/guides/azure-pipelines.md)
  now spells it out — including getting back to the pull request's merge commit, which
  `git checkout -` cannot do.

- **The exploitability line says what the feeds actually did.** It named KEV and EPSS and their
  dates, which tells you enrichment ran but not whether it changed anything — so the only way to
  find out was to read every finding looking for a note that might not be there, and then wonder
  whether you had missed one.

  ```
  Exploitability: KEV 2026-08-04 · EPSS 2026-08-04 — 3 findings raised
  Exploitability: KEV 2026-08-04 · EPSS 2026-08-04 — nothing raised
  ```

  The count covers the whole run, not the visible listing, so `--top` and `--min-priority` cannot
  make it read as though a feed did less than it did.

_Nothing yet._

### Fixed

- **A mistyped gate level is now an error instead of a wider gate.** `--fail-on` and
  `--fail-on-new` accepted anything. An unrecognized level ranks below every finding, so
  `--fail-on-new high` — which is exactly what the report's `high` invites you to type — quietly
  meant *fail on anything new at all*, and looked like it had narrowed the gate. Both flags now
  reject what they cannot rank, and say so before the scan rather than after it. A severity band
  gets a message explaining that the gate is on the other ladder.

## [0.63.0] - 2026-08-04

### Added

- **`azure-pr-comment` publisher** — Draugr's report as a sticky Azure DevOps pull-request
  comment, updated in place on each push rather than stacking a copy per run:

  ```yaml
  config:
    reports:
      - format: markdown
    publishers:
      - kind: azure-pr-comment
  ```

  Everything defaults from the pipeline environment, so that is usually the whole configuration.
  Map `SYSTEM_ACCESSTOKEN: $(System.AccessToken)` into the step — Azure does not expose it to
  scripts by default — and grant the build service *Contribute to pull requests* on the
  repository. Draugr names both in its error messages rather than leaving you with a bare 401
  or 403.

  `draugr diff --publish` follows the CI system it is running on, so the same command posts to a
  GitHub or an Azure pull request. It used to name the GitHub publisher outright, which on an
  Azure agent meant a flag that quietly did nothing.

- **`draugr --version`** now works, printing exactly what `draugr version` prints. Container
  smoke tests, tool caches and version probes reach for the flag rather than the subcommand.

- **A report now says which build of each scanner produced it.** A scan runs whatever is on
  `PATH`, which is right — an operator may have an experimental build or a fork, and refusing
  them would be Draugr mistaking "I cannot verify this" for "this is wrong". But a report that
  cannot say which build produced its findings cannot be reproduced.

  ```
  Scanners: gitleaks 8.30.1, trivy 0.69.3
  Scanner (unverified): semgrep 1.99.0 — found on PATH; Draugr did not install it
  ```

  The first line lists the builds Draugr fetched and checked: in `~/.draugr/bin`, in the install
  record, and still hashing to what was recorded — which makes it a claim about a file rather than
  about a path. Anything else is used and labelled with the reason, and none of it affects the
  verdict: it is a fact about the run, not a finding about your software.

- **Pin the version of each scanner.** Write it once, where it gets reviewed, and every pipeline
  provisions the same build — so two runners cannot turn identical code into different findings:

  ```yaml
  # draugr.config.yaml
  tools:
    trivy:    { version: "0.69.3" }
    gitleaks: { version: "8.30.1" }
  ```

  `draugr tools install trivy --version 0.68.0` does it for one run.

  Draugr will not refuse a version it cannot vouch for — asking for a fork, a release candidate or
  a build newer than this release is a case where you know something Draugr does not. It installs
  what you asked for and records how well it could check it: matched against a checksum recorded
  in this build, against checksums the upstream signed, against an unsigned checksums file, or
  against nothing at all. That level then appears in every report the tool produces, so nothing is
  weakened quietly. A published checksum the download *contradicts* is still refused — that is
  evidence, not a gap.

### Fixed

- **`draugr diff` reports severity, not SARIF levels.** A column headed *Severity* printed
  `error` / `warning` / `note`, so the same finding read as "error" in a diff and "critical" in
  the scan report it came from, and a reader comparing the two had to translate between
  vocabularies. Diffs now use the same `critical` / `high` / `medium` / `low` bands everywhere,
  and the headline names only the bands that occur — `12 new (4 high, 8 medium)` rather than a
  row of zeroes. In `--format json`, `newByLevel` / `fixedByLevel` become
  `newBySeverity` / `fixedBySeverity`, counting bands instead of levels.

- **JUnit findings link to the advisory.** A CI test panel showed a CVE number and its
  description, which left the reader retyping the number into a search engine. The failure now
  carries the scanner's advisory URL — or one derived from the identifier when the scanner
  published none, and nothing at all when there is nowhere honest to point.

- **`draugr diff --publish` keeps its own pull-request comment.** It shared a marker with the
  Saga's PR-comment publisher, so a pipeline running both — the state of the branch, and what the
  pull request changed — got one comment silently overwritten by the other, with nothing to say a
  second had ever been posted. They are two questions and now get two comments. Set `marker` on
  the publisher if you were relying on the old shared one.

- **JUnit reports are written as `report.junit.xml` everywhere.** `-o` and the `file` publisher
  named the same format differently, so a CI step globbing for one found nothing when the other
  had produced it — and the common test-publishing tasks warn rather than fail, leaving a green
  run with no results in it. Every format now has exactly one name. If you glob for `junit.xml`,
  update it to `report.junit.xml`.

## [0.62.0] - 2026-08-03

### Added

- **`draugr config` — machine and organisation settings, kept apart from the Saga.** A Saga
  describes an application; which build of a scanner runs and what a control defaults to describe
  the environment scanning it, and want to be the same everywhere.

  ```
  $ draugr config show
  In effect:
    Setting                          Value            From
    controllers.sast.semgrep.config  p/owasp-top-ten  /repo/draugr.config.yaml
    tools.trivy.version              0.69.3           ~/.draugr/config.yaml
  ```

  Defaults are merged **underneath** the descriptor, so a project overrides only the keys it names
  and inherits the rest. Discovery is `~/.draugr/config.yaml` then `./draugr.config.yaml`, and
  `--config`/`DRAUGR_CONFIG` replaces both.

  **A broken config fails the run rather than falling back**, because silently reverting a pinned
  toolchain is how a scan stops being reproducible. Recovery is one command — `config validate`
  says what is wrong and `config init --force` starts again — and `config set`/`unset` cannot
  produce a broken file: they edit the document, so comments survive, and parse the result before
  saving.

## [0.61.0] - 2026-08-03

### Changed

- **Cache entries are compressed.** An entry is a whole SARIF report, which is repetitive by
  construction — a measured one went from 375 KB to 60 KB, a factor of six.

  It matters most where a cache is persisted between CI runs: uncompressed, a large project spends
  on restoring the cache what it saves on scanning. A cache written by an older Draugr still reads,
  so upgrading does not silently discard a warm one.
### Added

- **Two ways to keep a shared cache honest.** `--cache-read-only` reads entries and writes none,
  for a run whose results should not be trusted by the next one; `--cache-require-digest` refuses
  to cache a container image identified only by a tag, because a tag can be rebuilt and the key
  cannot tell.

  **The GitHub Action sets `--cache-read-only` on a pull request from a fork**, without being
  asked. A job running unreviewed code that can *write* a shared cache decides what the next run
  on your default branch reads — a pass nobody earned. GitHub's own cache already scopes writes by
  branch, but a bucket or a self-hosted runner does not, and the guarantee should not depend on
  which transport somebody picked. Reading stays on, because the entries already there are what
  make a pull-request scan fast.

  There is now a guide to [persisting a cache between CI runs](docs/guides/caching-and-performance.md),
  which leads with the part that carries no trust question at all: Trivy's databases are 2.6 GB and
  a cold runner downloads all of them before scanning anything.

## [0.60.0] - 2026-08-03

### Changed

- **`--format` prints, `--report` writes.** One flag used to mean both, and
  `--format html` answered by dumping a styled document — CSS and all — into the terminal.

  ```
  draugr: html is a document, not something to print: use `--report html` with `-o <dir>`
  ```

  `--format` now accepts only what a person or a pipe can receive: `console`, `markdown`,
  `json`, `sarif`, `template`. Documents are produced with `--report` into `-o`:

  ```bash
  draugr scan draugr.saga.yaml -o out/ --report html,junit
  ```

  `-o` alone still writes `report.json` and `results.sarif`. This mirrors the descriptor, which
  has always kept `config.reports` (what to render) apart from `config.publishers` (where to send
  it) — the command line just had no way to say it.
- **`draugr classify` asks one kind of question, in plain words, with the weight of each answer
  visible.** Exposure was a tree of yes/no questions and criticality a numbered list, so a reader
  switched modes halfway through a wizard whose whole point is to be quick.

  ```
    Exposure — who can reach it?
      1) public         anyone on the internet can reach it, no sign-in
      2) authenticated  on the internet, but behind a login
      3) internal       only from inside your own network or VPN
      4) restricted     inside your network and locked down further — an allowlist, a private link, its own segment
  ```

  Options are coloured by rank in the same palette findings use, so how exposed an answer is shows
  while you choose it rather than afterwards in a report. The list also shows the whole ladder: a
  decision tree hid `restricted` from anyone who answered "not public".

  **The wording names no platform.** "Is its network access restricted (namespace / network
  policy)?" was answerable if you run Kubernetes and a guess otherwise — and a guess here silently
  miscolours every P1 that follows, because exposure and criticality drive the whole ranking. The
  reference table now uses the same words.

## [0.59.0] - 2026-08-03

### Added

- **`draugr controls` now says who publishes each scanner.** Reading the control table,
  `draugr-headers` and `gitleaks` looked alike — one is Draugr's own detection logic needing no
  external tool, the other is somebody else's binary executing on your machine, and nothing on the
  row said so.

  ```
  Who publishes each scanner:
    Origin            Scanners
    draugr            draugr-headers, draugr-k8s-policies, draugr-tls
    aquasecurity      kube-bench, kube-bench-job, trivy, trivy-config, trivy-fs, trivy-license
    projectdiscovery  nuclei
  ```

  Grouped by publisher, because that is the shape of the question a supply-chain review asks. The
  origin is declared on the scanner rather than inferred from its name, and a plugin will not be
  able to set its own — the loader stamps it, so it is an answer the subject does not supply.

### Changed

- **A descriptor key that names no scanner is now an error.** `controllers.headers.httpHeaders`
  — or any other key a control does not have — used to be read by nothing and changed nothing, so
  a descriptor turning a scanner off ran it anyway and reported a pass either way.

  ```
  draugr: config.controllers.headers: "httpHeaders" is not a scanner of the "headers" control (it has draugrHeaders)
  ```

  It names the keys the control does accept, so a rename explains itself without anyone having
  written a migration note for it. That is why this release carries none: a per-rename entry only
  helps with the renames somebody thought of.

- **Draugr's own scanners now say so in their names**: `http-headers` → `draugr-headers`,
  `tls-probe` → `draugr-tls`, `k8s-policies` → `draugr-k8s-policies`.

  A table can carry a column saying who published a scanner. A descriptor cannot — there the name
  is all you get, and `controllers.headers.draugrHeaders` is the only place the provenance can
  appear. Same for a log line, a SARIF `tool` value, or a grep.

  **This renames descriptor keys.** `controllers.headers.httpHeaders` becomes `draugrHeaders`,
  `tls.tlsProbe` becomes `draugrTls`, and `infrastructure.k8sPolicies` becomes
  `draugrK8sPolicies`.

  Cache keys change with the names, so expect one re-scan. **Rule ids are unchanged** —
  `headers/csp-unsafe-inline` is already unambiguous, and renaming it would break every
  `config.exclude` that mentions it for no gain.

- **`draugr controls` no longer prints a Scope column.** Every controller is component-scoped, so
  it repeated one word down the whole table and took width the Purpose column wanted. It reappears
  on its own if a project-scoped control ever ships.

## [0.58.1] - 2026-08-03

### Added

- **A helper for editing the CHANGELOG.** `make changelog` checks its structure — a duplicate
  `### Fixed` under one version splits the published notes in half and looks perfectly correct in
  review — and `./scripts/changelog.sh add fixed` puts an entry under the right heading. See
  [CONTRIBUTING](CONTRIBUTING.md#editing-the-changelog).

### Fixed

- **A cached result is now invalidated by the update that made it wrong.** Only the Trivy-backed
  scanners folded their data version into the cache key; Semgrep, Nuclei, Gitleaks, gosec,
  trivy-license, kube-bench and the native scanners contributed nothing, so an upgrade left
  yesterday's `no findings` looking current.

  Nuclei is the sharpest case — its templates are republished daily, so a cached clean run could
  be answering a question from last week. Its key now follows the **template** version rather than
  the binary's. The native scanners key on Draugr's own version, so a release that adds a check
  re-scans what it affects instead of leaving every cached result standing.

  This mattered little on a fresh CI runner, which has nothing cached to serve. It is the
  prerequisite for a cache that outlives one machine — see
  [caching and performance](docs/guides/caching-and-performance.md) for what each scanner follows.

  **If you use `--cache-dir`, expect one full re-scan.** Every key changes, so every existing
  entry misses once. That is the fix working: those entries were answers to a question that had
  moved on.

## [0.58.0] - 2026-08-02

### Added

- **The `headers` control now grades your Content-Security-Policy, not just its presence.** A CSP
  of `default-src *; script-src 'unsafe-inline' 'unsafe-eval'` passed the old check while
  permitting exactly what a CSP exists to prevent.

  ```
  P1  error  headers/csp-unsafe-inline  headers  http-headers  https://app
      Content-Security-Policy allows 'unsafe-inline' in script-src, so an injected <script> tag
      or event handler runs — which is most of what a CSP is for. Use a nonce or a hash per
      script instead.
  ```

  Ten checks, each saying what to change, graded by real risk: an injected script running is an
  error, a missing `report-uri` is a note.

  **A nonce, a hash or `'strict-dynamic'` makes `'unsafe-inline'` inert**, and `'strict-dynamic'`
  does the same to host and scheme sources — so those are reported as *doing nothing* rather than
  as flaws. Without that distinction the check would fire on the policies people were right to
  write, which is how a checker becomes something you switch off.

  It also reports a missing `base-uri`, which does **not** inherit from `default-src` — the
  subtlety that most often leaves a policy weaker than its author believes.

### Fixed

- **A misspelled control name is now an error, and the schema knows every control.** Two halves of
  the same gap.

  `config.gate.controls: { iaac: error }` used to validate clean and do nothing — a gate policy
  that was reviewed, merged, and silently not applied. It now fails, wherever a control is named
  (`config.controllers`, `config.gate.controls`, a component's own `controllers`), and suggests
  the name you meant:

  ```
  draugr: config.gate.controls: "iaac" is not a control this build of Draugr provides — did you mean "iac"?
  ```

  **This can fail a descriptor that used to scan.** That is the point — the typo was never doing
  what it looked like it was doing — but it is a change worth knowing about before your pipeline
  finds it.

  Separately, the JSON Schema's control list had fallen two behind: `licenses` and
  `infrastructure` were missing, so an editor flagged descriptors Draugr accepts. Editors now also
  autocomplete control names inside `config.gate.controls`, which previously offered nothing.

  Both come from the registry rather than a hand-written list, so `draugr controls`, the schema and
  the validator cannot disagree again.

## [0.57.0] - 2026-08-02

### Added

- **The GitHub Action can fetch the exploitability feeds** — `feeds: true` runs
  `draugr feeds update` before the scan, so a Saga whose `config.exploitability` reads `cache` has
  something to read.

  Its own step on purpose, which is what the docs already told you to do by hand: the scan then
  never reaches the network, and a feed outage fails at the fetch instead of producing a scan that
  ranked everything as though nothing were exploited.

  Draugr's own self-scan now uses it.

  **The `draugr` binary is unchanged from 0.56.0.** This release exists to move the `v0` tag, which
  is how `draugr-dev/draugr@v0` picks up a new action input — there is nothing to gain from
  upgrading a pinned CLI.

## [0.56.0] - 2026-08-02

### Added

- **One way to say offline.** `--offline`, on any command, or `DRAUGR_OFFLINE=1`:

  ```bash
  draugr scan draugr.saga.yaml --offline
  ```

  Draugr reaches out from several places — a release check, Trivy's database, Nuclei's templates,
  the exploitability feeds, tool downloads — and each used to decide for itself, so an air-gapped
  runner met the failures one at a time. Now one flag covers all of them.

  Nothing fails quietly. An optional fetch is skipped with a line saying so; a command whose whole
  purpose is to download refuses and **names what it would have fetched**:

  ```
  draugr: draugr feeds update needs the network, and DRAUGR_OFFLINE/--offline is set

  it would have fetched https://www.cisa.gov/…/known_exploited_vulnerabilities.json
                        https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  ```

  A scan runs against whatever each tool already has on disk, and Trivy is told not to refresh
  mid-scan — so a run with no vulnerability database reports an error rather than returning a
  clean result it never earned.

  **`draugr doctor` now lists every network call Draugr can make** and what each is for, so a
  runner can be prepared from that list instead of discovered one failure at a time. There is a
  new guide for [running air-gapped](https://github.com/draugr-dev/draugr/blob/main/docs/guides/air-gapped.md).

  `draugr doctor --offline` and `DRAUGR_NO_UPDATE_CHECK=1` keep working and keep their narrower
  meaning — "do not check for a release" is a reasonable thing to want on a machine that does
  have a network.
- **A report now says why a finding was escalated, and on what data.** Enrichment used to change
  a severity and leave no trace: the finding was critical, and nothing said it was critical
  because CISA had observed it being exploited on a particular date.

  ```
  Exploitability: KEV 2026-08-01 · EPSS 2026-08-02

    P1  high  8.1  CVE-2024-3094   sca  trivy  go.mod:12
        xz: malicious code in the upstream tarballs
        ↑ ranked as critical — on KEV (2026-08-01)
  ```

  The Severity column still shows what the scanner said — enrichment feeds the ranking rather
  than rewriting the scanner's rating — so the note is what explains a `high` finding sitting at
  P1.

  Findings nothing moved carry no note, so the note means something when it appears. Markdown and
  HTML get the same, and both `--format json` and `--format sarif` carry `escalation` per finding
  plus the feeds themselves — URL, fetch time and digest — so a report can be checked against the
  data it was computed from.

  A **stale** feed is now recorded in the report, not only warned about while the scan ran. The
  logs of the run that produced a report are exactly where nobody looks six weeks later.

- **Exploitability enrichment can be turned on in the Saga**, instead of a flag every pipeline
  has to remember:

  ```yaml
  config:
    exploitability:
      kev: cache          # path | cache | auto
      epss: cache
      epssThreshold: 0.5  # optional
      maxAge: 24h         # optional — how old a cached feed may be before it counts as stale
  ```

  ```bash
  draugr feeds update
  draugr scan draugr.saga.yaml     # enrichment is on, no flags
  ```

  It is a decision about how findings are ranked, so it belongs somewhere a reviewer sees it and
  every pipeline reads. `--kev`, `--epss` and `--epss-threshold` still work and override the
  descriptor — but only when you actually type them, so `--epss-threshold 0.5` beats a descriptor
  saying `0.1` while leaving it off does not.

  `maxAge` was a fixed 24 hours. A runner deliberately pinned to a known copy of the data has a
  legitimate reason to raise it: reproducing last quarter's verdict requires last quarter's feed.

- **`draugr feeds update` fetches the KEV and EPSS datasets for you.** Exploitability enrichment
  used to start with two `curl` commands and a `gunzip`, which meant knowing that CISA publishes
  KEV as JSON at a stable URL — so the feature was off for the people it helps most.

  ```bash
  draugr feeds update                                    # into ~/.draugr/feeds
  draugr scan draugr.saga.yaml --kev cache --epss cache
  ```

  `--kev` and `--epss` still take a file path, unchanged, and now also take `cache` (read what
  `feeds update` left; never touch the network) or `auto` (fetch when the cache is missing or
  over a day old). **A scan never fetches on its own**: the network is touched when you ask,
  which is what keeps a gated run reproducible and an air-gapped runner working.

  `draugr feeds status` reports what is cached, how old it is, and the digest of each copy —
  because "escalated to critical because it was on KEV as of 2026-08-01" is an auditable
  statement and "KEV said so" is not.

  Staleness is treated as a correctness problem rather than housekeeping. EPSS is republished
  daily, so a week-old copy does not fail — it ranks a finding lower than today's data would. A
  scan reading a feed over a day old warns and names the age. `DRAUGR_OFFLINE=1` stops `auto`
  fetching at all.

### Fixed

- **A count of days no longer reads as "4 daies".** The plural rule turned any noun ending in
  `y` into `-ies`, which is right after a consonant and wrong after a vowel.

## [0.55.0] - 2026-08-01

### Changed

- **CIS rule ids are namespaced by the scanner that emitted them** — `draugr/cis/5.1.1` and
  `kube-bench/cis/5.1.1`. Both scanners audit the same benchmark with the same numbering, so a
  bare `cis/5.1.1` was an id two tools both claimed. Inside Draugr the Scanner column told them
  apart; in SARIF, in GitHub code scanning and in an editor the rule id *is* the identity — and
  the collision also let one tool's description and `helpUri` attach to the other's finding.

  **This changes exclusion rules.** A `config.exclude` naming `cis/5.1.1` no longer matches. To
  excuse a check whichever scanner reports it — the more accurate thing to write in any case —
  glob the namespace:

  ```yaml
  exclude:
    - rules: ["*/cis/5.1.1"]
      reason: "wildcard roles are how our operator works; accepted"
  ```

### Added

- **A scan says when a local repository has uncommitted work it will not see.** A repository
  given as a path is cloned like any other source, so the scan describes the committed revision
  rather than the files on disk — which is what makes a report reproducible, and what makes an
  uncommitted change look like it did nothing:

  ```
  WARN scanning the committed revision, not your working tree repository=/srv/web uncommitted_files=3
  ```

  The reference now covers [URLs versus paths](https://github.com/draugr-dev/draugr/blob/main/docs/reference/saga-schema.md#where-a-repository-comes-from-urls-and-paths) in full, including
  what it means for `draugr diff`: scan, edit, re-scan compares `HEAD` with itself and reports no
  change, so commit between the two scans or name each `revision` explicitly.

- **A scan records which classifications it reached a verdict on.** Both CIS scanners now report
  the controls they settled — including the ones they found compliant, which produce no finding:

  ```json
  "decided": [{"taxonomy": "CIS-Kubernetes", "id": "5.1.1", "version": "cis-1.12"}]
  ```

  A scanner reporting nothing about a control has either examined it and been satisfied or never
  examined it at all, and those mean opposite things. Without this, "one of two scanners found it"
  is a guess that the other dissented — when far more often the other does not check that control.
  It is the prerequisite for saying two scanners agree, and for answering *what is nothing
  checking?*

  Decided, not examined: a control a scanner looked at and could not settle — kube-bench's `WARN`,
  our manual-review checks — is not a dissent either.

- **SARIF output declares the classifications a rule implements.** Both CIS scanners now reference
  the benchmark control their checks cover, using SARIF's own `taxonomies` and `taxa`:

  ```json
  "taxonomies": [{"name": "CIS-Kubernetes", "version": "cis-1.12",
                  "taxa": [{"id": "5.1.1", "name": "Minimize wildcard use"}]}]
  ```

  Namespacing the rule ids removed the accidental correspondence between the two scanners; this
  puts it back where it belongs. A consumer that has never heard of Draugr can group findings by
  the control they implement, from a published vocabulary rather than from two ids colliding —
  and a third-party scanner can join in by referencing the same taxon.

- **A scan reports exclusions that matched nothing.** An exclusion doing nothing reads exactly
  like one that is working — usually a typo, a rule id that moved, or a finding someone fixed and
  forgot to stop excusing. In every case the descriptor claims a decision it is not making:

  ```
  1 exclusion matched nothing in this run:
    rules cis/5.1.1 — written before the ids were namespaced
  ```

  An expired exclusion is still reported as lapsed rather than unmatched: it was withdrawn before
  matching was attempted, and saying both would describe two different things happening.

- **`draugr tools install kube-bench`** fetches the binary and its `cfg/` tree together — 276
  benchmark definitions the tool cannot run without. The scanner then points `--config-dir` at
  them, so the install is usable rather than merely complete.

  Installing the binary alone was the common mistake and did not look like one: every run exited
  with `config file is missing 'target_mapping' section`, naming an internal structure rather
  than the directory nobody copied.

### Fixed

- **`draugr doctor` with no descriptor reports rather than fails.** It treated the whole tool
  catalogue as required, so a clean machine was told it was missing seven tools it may never
  need — kube-bench most clearly, since the default infrastructure scanner is native Go and
  needs no binary at all.

  Nothing has been selected without a descriptor, so nothing is required. It now lists what is
  present, says which tools are absent, and points at `draugr doctor <saga>` — the same question
  with an answer. **`draugr doctor <saga>` is unchanged** and still fails on anything that
  descriptor needs.

- **A tool whose data is missing is no longer reported as already installed.** `tools install`
  compared versions and stopped there, so kube-bench with a current binary and no benchmarks was
  skipped by the very command that would have fixed it.

## [0.54.0] - 2026-08-01

### Added

- **`draugr doctor` sees kube-bench's missing benchmark configuration.** kube-bench ships its
  benchmarks as a `cfg/` tree beside the binary and people install the binary alone; every run
  then dies with `config file is missing 'target_mapping' section`, which names an internal
  structure rather than the directory nobody copied. Doctor checks the paths kube-bench itself
  searches, including beside the binary where a tarball extract leaves it.

- **The report says which component passed and which failed**, when there is more than one:

  ```
  Components:
    payments       FAIL   P1 10  P2 8  P3 1  sca, secrets
    internal-tool  pass   no findings
  ```

  The controls table answers "is the project shippable". A component is the unit a team owns and
  the unit `exposure` and `criticality` are declared on, so it is the unit someone is deciding
  about — and with five components, `sca FAIL` said the project had a problem and stopped there.

  Each component is judged by **the same policy as the run**, re-applied to its own findings, so
  the parts cannot disagree with the whole about what failing means. Clean components are listed
  too: a `pass` against a named component is the answer someone takes back to their team.
  Findings from project-wide controls belong to no component and are counted separately rather
  than quietly left out. Also in the markdown report.

### Fixed

- **`acceptedBy` reaches the report.** The field was parsed, validated, and used to count
  unattributed suppressions — and the name itself appeared nowhere: not the console, not the
  markdown report, not even SARIF. The point of recording who accepted a finding is that a reader
  months later can ask them, and there was nobody to ask:

  ```
  2 findings suppressed by config.exclude — 1 accepted by a.reviewer, 1 unattributed
  ```

  In every human format, and in SARIF's suppression property bag (with `expires`) so a consumer
  can filter on it rather than parse it out of a sentence.

- **The suppression line is no longer greyed out.** It is the one line saying part of the report
  was set aside, and dimming put it below the reading threshold of the thing it qualifies.

- **`draugr diff` names the component a finding belongs to.** Neither table read it, so two
  components sharing a dependency produced rows identical in every visible column — correctly
  counted as two, and indistinguishable to a reader:

  ```
  | Priority | Severity | Rule | Tool | Component | Location |
  ```

  This is the pull-request comment: one PR touches one service in a monorepo, and the first
  question is whether the finding is yours. Shown only when a finding has a component, so a
  single-component project is not given a column repeating itself.

## [0.53.0] - 2026-08-01

### Added

- **A scan says when part of your descriptor has nothing checking it.** A component declaring a
  `hosts:` entry with the host controls off was scanned for everything *except* the thing it
  exposes to the internet, and reported a clean pass over it:

  ```
  Note: nothing checks part of what this descriptor declares.
        web declares hosts, and headers, tls are not enabled
        svc declares images, and images is not enabled
        Run `draugr controls` to see what each control does.
  ```

  A note, not a failure — the choice may be deliberate. It appears whether or not the run found
  anything, because an empty report over an unchecked surface is exactly when a reader concludes
  there is nothing to find. Partial cover counts as cover, and `--no-tips` / `DRAUGR_NO_TIPS=1`
  silences it.

### Changed

- **`draugr scan <dir>` finds any `*.saga.yaml`**, not only `draugr.saga.yaml` — `web.saga.yaml`,
  `.saga.yaml` and the `.yml` spellings all count. These are the names our editor integration
  already validates, so a scan that ignored three of the four was contradicting it.

  **A directory with more than one stops the scan.** Two descriptors are two different accounts
  of what the project is, so Draugr does not choose: on a terminal it asks, and anywhere else it
  lists them and stops. Naming the file skips the question.

### Fixed

- **`draugr tools install` no longer plans work it will not do.** The plan listed every named
  tool whether or not it was already installed at the pinned version — six rows for one
  download — and presence was only discovered afterwards, inside the install loop. It is now
  resolved first and shown:

  ```
  Install plan:
    Tool      Version  Category  Verify  Destination
    trivy     0.69.3   scanner   —       already at 0.69.3
    cosign    3.1.1    utility   sha256  ~/.draugr/bin/cosign

  1 tool to install, 6 already current.
  ```

  A run with nothing to do says so and **does not prompt**: a confirmation that gates no action
  teaches people to answer it without reading, on the command where reading matters most. And
  the Semgrep instruction only appears when Semgrep is actually missing — being told to install
  something you already have reads as a failure.

- **An identical failure is reported once, with a count.** A control with two jobs that failed
  the same way printed the same sentence twice — and two identical lines invite the reader to
  look for the difference between them, which there isn't:

  ```
  sast  ERROR  did not run
        run semgrep: exec: "semgrep": executable file not found in $PATH (2 jobs)
  ```

  Collapsed when rendering, not when recording: each entry belongs to a real job, and the SARIF
  and JSON report keep them all.

- **`--log-level trace` relays a tool's stdout as well as its stderr.** It only ever showed
  stderr, and only on a non-zero exit — but our scanners are deliberately configured not to fail
  on findings, so success is the normal path, and a tool that produced an empty report because it
  was misconfigured looked exactly like one that found nothing. Long streams are trimmed with a
  note saying how much was left out.

- **`draugr mcp --scan=ask` can ask again.** The approval request went out without a
  `requestedSchema`, which the protocol requires for a form — so a spec-conformant client
  rejected it and the mode failed before it could prompt. Nothing was ever scanned without
  consent; the consent could not be requested at all.

- **`draugr survey` says what it wrote.** It produced a descriptor and reported nothing — no
  path, no counts, no account of what it discovered — so the only evidence a survey had worked
  was the absence of an error. With `-o .saga.yaml` the file is not even visible to `ls`:

  ```
  wrote .saga.yaml — 3 components, 3 repositories
  ```

  A merge says what this run contributed, and a survey that discovered nothing says so rather
  than reporting a count that reads as success.

- **`survey github repos` says when it could only see public repositories.** With no
  `GITHUB_TOKEN` the GitHub API answers with the org's public repositories, and the descriptor
  that resulted was syntactically fine, enabled every control, and silently omitted every private
  repository. Nothing about the artifact looked unfinished. It now warns, naming the consequence
  and the variable to set.

- **A prompt is no longer printed when stdin is `/dev/null`.** It is a character device, so the
  terminal check said yes to it — and it is exactly what a script redirects from when it means
  there is nobody here. Affected the `tools install` confirmation too.

## [0.52.0] - 2026-07-31

### Added

- **`ignore` on a repository removes paths from a scan.** Gitignore-shaped, applied after
  `paths`, so it can carve fixtures out of a subtree you selected:

  ```yaml
  repositories:
    - url: https://github.com/acme/monorepo.git
      paths: [services/web]
      ignore: ["**/testdata/**", vendor/]
  ```

  Not the same tool as `config.exclude`: `ignore` narrows what is **scanned**, so nothing is
  reported about those files at all. `exclude` narrows what is **counted** — the finding is still
  made and still in the report, marked suppressed with the reason someone gave. Use `ignore` for
  code that is not yours to answer for; use `exclude` for a finding you have looked at.

### Fixed

- **`--allow-scan-errors` can no longer pass a scan that ran nothing.** A descriptor enabling no
  control reported `no controls ran` and failed, as it should — and the flag the error message
  recommended turned that into a green **PASS** over a scan that had checked nothing.

  The flag accepts a *scanner* that failed, when other controls did run and you choose to proceed
  on those. A planning failure is not a scanner, so there is no partial result to accept. It now
  says so instead of offering the flag. A failed SBOM stays waivable: that is missing evidence,
  not a missing check.

- **A failure's explanation is wrapped rather than cut.** The one-line clamp is right for a
  tool's own stderr, which can be a usage screen, but it was also truncating Draugr's own
  sentences at the clause that said what to do.

- **`dast` works.** The Nuclei template download never ran: the prewarm passed `-duc` alongside
  `-update-templates`, and on that command `-duc` disables the update itself. Nuclei exits 0
  either way, so nothing noticed — every `dast` run then failed with Nuclei's own
  `no templates provided for scan`, which reads like a mistake in your descriptor.

  The flag is gone, and the download is now verified rather than assumed: Draugr asks Nuclei what
  template set it has afterwards, because an exit code that is 0 on both outcomes cannot answer
  that. If there is still no template set, the control's error says so instead of relaying the
  symptom.

- **`draugr doctor` reports a tool that is installed but cannot run.** Being on PATH is not the
  same as being able to work — Nuclei needs its template set — so doctor now probes for a tool's
  data and fails when it is missing, with how to get it:

  ```
  nuclei  ✗ no data  3.11.0  run `nuclei -update-templates`
  ```

- **A scanner's prewarm failure is now logged.** It was recorded as a trace span event and
  nowhere else, so the only thing a user ever saw was whatever the scanner said later about a
  consequence of it.

- **`paths` on a repository now scopes the scan.** It was accepted, documented and carried into
  the scan target, and no scanner ever read it — every repository control scanned the whole tree.
  A monorepo scoped to one service reported findings against a component that does not own the
  code.

  Draugr now checks out only the selected directories, so a large repository is cheaper to scan
  as well. **Files at the repository root always come with them**, whatever `paths` says:
  `go.mod`, `package.json`, `Dockerfile`, `.trivyignore` and their kin are how a scanner knows
  what it is looking at, and a tool that cannot find the manifest reports less rather than
  failing.

  **Scope is now part of a target's identity.** Two components on different subtrees of one
  repository previously shared a cache entry and collapsed into a single scan whose findings both
  received.

- **A publishing failure no longer hides the gate's verdict.** A run that both failed its gate
  and could not deliver its reports named only the publisher — so a red build read as "fix your
  token" when what actually happened is that it should not ship. The verdict leads and the
  publishing failure follows it:

  ```
  draugr: policy verdict: fail (publishing also failed: github publisher missing: $GITHUB_TOKEN)
  ```

## [0.51.0] - 2026-07-31

### Added

- **An exclusion can record who accepted it and when it lapses.** `acceptedBy` names the person
  to go back to; `expires` is a date after which the exclusion stops applying, the finding
  returns, and the report says the exclusion lapsed:

  ```yaml
  config:
    exclude:
      - rules: ["CVE-2026-1234"]
        reason: "no fixed release yet; not reachable from our entry points"
        acceptedBy: "a.reviewer"
        expires: "2026-09-30"
  ```

  Both are optional and existing descriptors keep working. Suppressions with nobody attached are
  counted in the report, because an exclusion nobody can be asked about is worth knowing about.
  An unparseable date is rejected when the descriptor loads rather than ignored — suppressing
  indefinitely while the descriptor says otherwise is worse than having no date.

- **The console names the component a finding came from**, when there is more than one to tell
  apart. A path alone does not say which part of the application it is relative to, and two
  components can carry the same one.

- **"Fix first" now says how much of the run it is showing** — `Fix first (top 10 of 56, by
  priority)` — so the heading stays true under `--top 0`, where the same words previously sat
  above every finding in the run.

- **The console shows what each control measured**, under the controls it describes.

- **A report now says what it measured and against what.** The `infrastructure` scanners record
  the benchmark applied, how much of it could be decided, and the namespaces in scope:

  ```
  Measured against
  - infrastructure — k8s-policies: benchmark cis-1.12 · coverage 20 of 34 checks decided
  ```

  Which standard was used is chosen from the cluster rather than stated in the descriptor, so
  until now nothing in the evidence recorded it — the first question an auditor asks had no answer
  in the artifact. The coverage figure is the other one a reader could not get: counting
  manual-review findings by hand was the only alternative.

  Rendered in `markdown`, `html` and `json`, and carried in SARIF's run property bag so it reaches
  consumers that read SARIF rather than only Draugr's reporters. Console follows.

- **A report can now carry what a scanner says about the run**, not only what it found — which
  benchmark was applied, how much of it could be decided, what the scan was scoped to. It travels
  in `--format json` and in SARIF's own run property bag, so it reaches any consumer that reads
  SARIF rather than only Draugr's reporters.

  Nothing renders it yet; the scanners that will fill it in, and the human-facing formats, follow.
  This is the plumbing.

- **Every report records the version of the scanner that produced it**, filled in by the engine
  so a scanner cannot forget. Where caching resolved a live version — Trivy folds in its
  vulnerability-DB version — that is the one recorded, so the evidence and the cache key cannot
  disagree about what ran.

### Fixed

- **`draugr scan <dir>` uses the descriptor in that directory.** It previously ran zero-config
  even with a `draugr.saga.yaml` present, discarding the controls, components, exposure and
  criticality the file declared, and then suggesting `draugr init` to scaffold a file the reader
  already had. Nothing in the output distinguished a project scanned as intended from one whose
  configuration had been ignored.

  A descriptor that cannot be read now fails the scan instead of falling back — falling back
  would reproduce the same problem with an extra step. Zero-config still applies to a directory
  with no descriptor.

  **This changes what an existing command does:** a pipeline running `draugr scan .` in a repo
  that has a descriptor will now honour it, which may enable more controls than the run used to.

- **Two components sharing a repository no longer collapse into one finding.** A finding's
  identity did not include its component, so the same issue reached from two components was
  deduplicated down to one — and which one survived was arbitrary, so a P1 on a public,
  business-critical component could be discarded in favour of the same issue on an internal tool.

## [0.50.0] - 2026-07-31

### Added

- **The native CIS reader decides 20 of the 34 policies checks**, up from 11 — nine past what
  kube-bench automates. Added: root containers, the NET_RAW capability, capabilities generally,
  Windows HostProcess containers, hostPath volumes, host ports, seccomp profiles, whether a
  securityContext was applied at all, and use of the default namespace.

  All nine are questions about a pod spec, so they cost nothing extra: the same single listing
  already answered the others. kube-bench leaves them manual because correlating pod specs is
  what a `kubectl | jq | xargs` pipeline is worst at.

  The 14 still reported for review are honestly manual — whether an admission control mechanism
  is in place, whether the CNI supports NetworkPolicy, whether secrets belong in an external
  store. Those are questions about intent, not cluster state.

- **A managed cluster's report now says which part of its benchmark went unassessed.** Every
  managed benchmark ships a **Managed Services** section — 33 checks on GKE, 12 on EKS, 13 on AKS
  — covering what the cloud provider controls rather than what the cluster does. Draugr evaluates
  none of it, and previously said nothing, so the benchmark looked smaller than it is and a clean
  result looked more complete than it is.

  One finding names the section, its benchmark and its size, rather than one per check: nothing
  in it is evaluated, so saying that once is clearer than fifty-eight identical prompts burying
  the findings that came from an actual assessment.

## [0.49.0] - 2026-07-31

### Added

- **`draugr survey` now enables the controls the discovered surface can be checked with**, so a
  descriptor written by discovery scans something. Repositories imply `sca`, `secrets`, `sast`
  and `iac`; images imply `images`; hosts imply `headers` and `tls`; infrastructure implies
  `infrastructure`.

  A surveyed descriptor previously enabled nothing, so its first scan reported `PASS` having run
  no control — not what "the descriptor writes itself" should mean.

  **`dast` is never enabled this way.** The other host controls read a response; `dast` sends
  attack traffic at a live service, and enabling that because a survey noticed the service exists
  is not a decision discovery gets to make for you.

  A control already in the descriptor is left exactly as it is, including one set to
  `enabled: false` — `--merge` runs against a file people edit, and a survey that switched
  something back on would be worse than the problem it solves.

- **`draugr survey k8s cluster`** writes the cluster itself as an `infrastructure` component, so
  the CIS benchmark controls apply to it without hand-writing the entry.

  A separate surveyor from `k8s images` rather than an option on it: a surveyor named for images
  that also emitted an infrastructure component would surprise anyone reading the command that
  produced the descriptor. They also describe different things — the images are the application,
  the cluster is what it runs on — and those differ in criticality often enough that one
  component would assert a single classification over both.

  `--namespace` makes the component own that namespace rather than the whole cluster, so a scoped
  survey produces a scoped component instead of one you narrow by hand afterwards.

- **`--context` on `draugr survey k8s`** selects which cluster to survey, for both of its
  surveyors, instead of relying on whatever the kubeconfig currently points at.

- **`draugr tools install --saga <descriptor>`** installs only the tools that descriptor's scan
  will run, instead of everything Draugr can provision. It resolves them exactly as
  `draugr doctor` does, so the command that tells you what you need and the one that installs it
  cannot disagree.

  A project running `sca` and `secrets` was getting `gosec` — a Go-only scanner it never enables.
  On a security tool that matters beyond disk: every binary on `PATH` is one more thing to trust,
  keep patched and explain.

  Where a descriptor needs something Draugr cannot provision — `kubectl`, `git`, semgrep via pipx
  — the plan names it rather than installing the rest and reporting success.

  Behaviour without the flag is unchanged. Where a descriptor is present in the working directory
  the plan points out what `--saga` would save, rather than quietly provisioning a smaller set
  that a pipeline may not expect.

- **A component can declare the namespaces it owns**, so a shared cluster stops reporting
  everybody's findings to everybody:

  ```yaml
  infrastructure:
    - kind: kubernetes
      ref: prod-cluster
      namespaces: [team-a, team-a-jobs]
  ```

  Most CIS policy checks are namespace-scoped, so a team owning three namespaces of eighty was
  receiving seventy-seven namespaces' worth of findings it could not act on. It also fixes what
  the component's `exposure` and `criticality` mean, which otherwise asserted a risk
  classification over everybody else's workloads.

  Scoping changes what is **read**, not what is kept: namespaced resources are listed per
  namespace, so a credential with access to only those namespaces can run the scan. Cluster-wide
  checks still run and are still reported — you are affected by a cluster-admin binding you
  cannot remove — and fall back to manual review where that credential cannot read them.

  The scope appears in the finding's location and in the cache key, because the same check
  against the same cluster means something different depending on how much of it was examined.

  Only the `k8sPolicies` scanner can honour a scope. `kubeBench` writes `--all-namespaces` into
  its own checks, and the in-cluster Job reads a node filesystem that has no namespace, so both
  **refuse** a scoped component rather than auditing everything and reporting it as if scoped.

### Changed

- **`draugr survey` now has a subcommand per surveyor** instead of a flag per surveyor:

  ```bash
  draugr survey k8s images --namespace prod -o draugr.saga.yaml
  draugr survey github repos --org acme --merge -o draugr.saga.yaml
  ```

  The old flags were related to each other in ways nothing expressed —
  `draugr survey --github-org acme --k8s-namespace prod` was accepted in silence, with the
  namespace applied to nothing and no warning that it had been. Each surveyor's options now sit
  on its own command, where an option that does not belong is rejected rather than ignored.

  Running several surveyors at once still works through `--merge`, which folds each survey into
  the Saga already at `--output`.

  `--k8s-images`, `--k8s-namespace` and `--github-org` now **error**, naming the subcommand that
  replaced them. A flag left behind to be ignored is the defect this change exists to fix.

### Fixed

- **Documentation that the last few releases had quietly falsified.** The glossary still said
  Draugr could not run the benchmark inside a cluster, which stopped being true in 0.46.0; the
  README described the `infrastructure` control as kube-bench and discovery as images-and-repos
  only. Same-PR doc discipline keeps the pages next to a change correct — it does not catch a
  page elsewhere the change made wrong.

  A test now holds the integrations catalog to the registry on the claim most likely to rot:
  which scanner a control runs **by default**. That one is written once in a table nobody
  revisits and read by everyone deciding what a scan does.

- **A scan that checked nothing no longer reports `PASS`.** A descriptor enabling no control — or
  none whose surface its components carry — produced no findings, no failures and a pass:
  output identical to a spotless application.

  The wrong reading was the likelier one. A descriptor reaches that state by being unfinished, or
  by being generated with `draugr survey`, which describes a surface without enabling anything to
  check it. It is now reported the same way a control that could not run is, because it is the
  same failure one level up — the gate answered without having looked.

  A descriptor that asks only for an SBOM is unaffected: it enables no control by design and
  still produces the evidence it was asked for.

## [0.48.0] - 2026-07-31

### Changed

- **The `infrastructure` control now reads section 5 through the Kubernetes API by default**,
  instead of exec'ing kube-bench. Both decide the same 11 of the section's 34 checks, so this
  costs no coverage — what changes is that a default scan needs neither `kube-bench` nor
  `kubectl` installed, creates nothing, and finishes in seconds on a cluster where the exec'd
  path took tens of minutes.

  `kubeBench: { enabled: true }` restores the previous behaviour, and remains the reference the
  native reader is checked against.

- **`draugr doctor` asks only for the tools a scan will actually use.** A control served by
  several scanners was reporting every tool any of them might need, so a project would be sent to
  install something its scan never runs — and a control it could run perfectly well would be
  reported as unable to. It now follows the same scanner selection `Plan` does, for every control
  rather than just `sast`. Where nothing is required it says so, instead of reporting an empty
  table as everything being present.

### Added

- **The native CIS reader now decides 11 of the 34 checks in the policies section**, up from 3 —
  the same count kube-bench automates. Added: broad access to secrets and to pod creation,
  service account token mounting, and the five pod-security checks (privileged containers,
  host PID/IPC/network namespaces, and privilege escalation).

  The six pod-security questions are answered from **one** listing rather than a `kubectl` call
  per pod per check: on a cluster of 8,393 pods that is 8.6 seconds.

  Access to secrets and to pod creation are asked of the cluster's own authorizer rather than
  reassembled from roles and bindings, so the answer matches what the cluster would actually
  allow. That query needs a permission a read-only credential may not have; where it is refused
  the check is reported for manual review rather than failing the scan.

- **The CIS catalogue is now checked against kube-bench's own benchmark definitions.** The
  `k8s-policies` scanner reports every check in the section so that partial coverage cannot read
  as a clean result — a guarantee only as good as the list, which is hand-maintained against a
  benchmark someone else revises. A check added upstream and missing here would never be
  reported; one retired upstream but left here would be reported forever. The check fails on
  either, naming it, and runs against definitions fetched at a verified commit that is kept in
  step with the kube-bench image, so bumping the tool is when a revision is discovered.

## [0.47.1] - 2026-07-30

### Fixed

- **AKS clusters are now audited against the AKS benchmark.** GKE and EKS put their distribution
  in the reported Kubernetes version; AKS does not — a real AKS cluster reports a bare `v1.34.2`,
  so it was treated as vanilla and measured against the generic `cis-*` benchmark. Nothing
  signalled it: with no platform detected there was no expectation for the output check to
  disagree with.

  Draugr now reads a node for the label AKS puts on its own nodes, fetching a single node and
  only when the version string came back bare. If reading nodes is denied, the platform is simply
  not detected and the version decides, as before.

  A cluster you manage yourself on Azure VMs is not affected: the `azure://` provider ID is
  deliberately not treated as a signal, because RKE2, RKE and kubeadm all carry it when the Azure
  cloud provider is configured. Distributions that stamp their own version — RKE2 among them —
  are resolved before any node is read.

## [0.47.0] - 2026-07-30

### Changed

- **The `infrastructure` control selects scanners the way every other control does**, with a
  per-scanner block instead of a `mode` setting:

  ```yaml
  config:
    controllers:
      infrastructure:
        enabled: true
        kubeBench: { enabled: false }    # section 5 by exec'ing kube-bench (the default)
        k8sPolicies: { enabled: true }   # section 5 through the Kubernetes API
        kubeBenchJob: { enabled: true }  # sections 1-4, from inside the cluster
  ```

  `mode` conflated two separate choices — which sections you want, and how section 5 is read —
  and it had no way to express the node sections *without* section 5. It also sat awkwardly with
  consent: effects are declared per scanner, so accepting `mutate` and `privilege` should mean
  accepting them for a scanner you named, not for a preset that implies one.

  **`mode` is removed rather than deprecated**, and a descriptor still using it fails at load
  naming the replacement. A setting that is read by nothing changes the scan without changing the
  verdict, which is the failure the whole control exists to refuse.

- **Scanner keys in a descriptor are camelCase**, like every other field: `kubeBenchJob`,
  `k8sPolicies`, `tlsProbe`. Scanner *names* are unchanged in reports and `draugr controls`. A
  hyphenated key is now an error at load — previously it matched no scanner and silently ran one
  fewer than asked for.

### Fixed

- **`mode: job` now covers the whole benchmark.** It ran the node and control-plane sections and
  silently omitted section 5 — RBAC, service accounts, Pod Security Standards, network policies —
  because a component plans one scanner and the Job does not request that section. The control
  reported a pass on the half it ran.

  It now plans the native reader alongside the Job, so one descriptor gets the complete
  benchmark. Nothing extra is created: that scanner only reads, and finishes in about a second on
  a cluster of eighty namespaces.

### Added

- **`mode: api` reads the CIS policies section through the Kubernetes API**, instead of running
  kube-bench:

  ```yaml
  config:
    controllers:
      infrastructure:
        enabled: true
        mode: api
  ```

  kube-bench answers this section with a shell pipeline per check, and for the pod-security ones
  a `kubectl` call per pod. On a shared cluster of 78 namespaces a pass takes tens of minutes,
  almost none of it spent on the queries. The same questions are a handful of API calls, and
  nothing needs `kubectl` installed.

  **Coverage is stated, not implied.** Every check in the section is reported: three are decided
  from the cluster's actual state, and the rest are reported as needing manual review — which is
  what CIS says about them and what kube-bench reports too. So a check that is not yet
  implemented can never read as a clean result, and implementing one only ever replaces a prompt
  with an answer.

  Rule ids are unchanged (`cis/5.1.1`), so an exclusion written against the default scanner keeps
  working when you switch.

## [0.46.2] - 2026-07-30

### Changed

- **The docs now say what the default `infrastructure` scan is worth.** Its section of the CIS
  benchmark is the advisory one: none of its 34 checks are scored and only 11 carry an audit
  command, so a clean result there is a list of things to review rather than a measured pass.
  The scored checks are the node and control-plane ones, which `mode: job` reaches.

### Fixed

- **The `infrastructure` control now audits a managed cluster against its own CIS benchmark.**
  EKS, GKE, AKS, k3s, RKE2 and ACK clusters were being measured against the generic `cis-*`
  benchmark instead of the provider one.

  The two are not variations on each other — they do not even share check numbers. The generic
  benchmark's policy checks are section 5; on EKS and GKE they are section 4. So a report cited
  rule ids that do not exist in the benchmark for that cluster, failed it for control-plane
  settings a managed provider does not expose, and skipped the provider checks that were the
  point.

  Nothing to change in your descriptor: Draugr reads the distribution from the version the
  cluster already reports. A vanilla cluster is unaffected. `benchmark` still pins a config
  directly — needed for OpenShift, which is identifiable only by running `oc`.

  A scan whose benchmark does not match the cluster now **fails** rather than reporting.
  Selecting a provider benchmark means letting kube-bench choose, and kube-bench falls back to a
  benchmark for Kubernetes 1.16 when its own detection fails, so the result is checked rather
  than assumed.

## [0.46.1] - 2026-07-30

### Fixed

- **The integrations catalog now lists `kubectl` among the utilities**, which the `kube-bench`
  scanner needs — its `policies` checks shell out to it. A test now holds the catalog's tool
  table to the registry `draugr doctor` checks, so a tool a scan requires cannot be missing from
  the page you read to find out what to install.

### Changed

- **Surveyors are called surveyors.** The docs previously introduced them as "Surveyors (the
  Ravens)" — two names for one thing. Nothing about how they work has changed.
- **The Saga and Surveyors concept pages now explain their subjects.** The descriptor page makes
  the case for a descriptor, walks the anatomy field by field, covers the two risk axes no
  scanner can infer, and states plainly that an excluded finding stays in the report marked
  suppressed. The surveyors page covers what `--merge` preserves, why the running digest is
  recorded, and what discovery cannot do for you — `criticality` is a judgement, and a proposed
  `exposure` is a proposal.

## [0.46.0] - 2026-07-30

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

  The image is pinned **by digest**, not just by tag: a tag can be repushed, and a compliance
  result that changes while the descriptor does not is worth nothing. Override `image` for a
  private registry or air-gapped mirror — and pin yours by digest too.

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

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.97.0...HEAD
[0.97.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.97.0
[0.96.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.96.0
[0.95.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.95.0
[0.94.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.94.0
[0.93.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.93.0
[0.92.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.92.0
[0.91.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.91.0
[0.90.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.90.0
[0.89.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.89.0
[0.88.2]: https://github.com/draugr-dev/draugr/releases/tag/v0.88.2
[0.88.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.88.1
[0.88.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.88.0
[0.87.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.87.0
[0.86.2]: https://github.com/draugr-dev/draugr/releases/tag/v0.86.2
[0.86.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.86.1
[0.86.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.86.0
[0.85.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.85.0
[0.84.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.84.0
[0.83.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.83.0
[0.82.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.82.1
[0.82.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.82.0
[0.81.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.81.1
[0.81.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.81.0
[0.80.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.80.0
[0.79.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.79.0
[0.78.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.78.0
[0.77.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.77.0
[0.76.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.76.0
[0.75.2]: https://github.com/draugr-dev/draugr/releases/tag/v0.75.2
[0.75.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.75.1
[0.75.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.75.0
[0.74.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.74.0
[0.73.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.73.1
[0.73.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.73.0
[0.72.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.72.0
[0.71.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.71.0
[0.70.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.70.0
[0.69.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.69.0
[0.68.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.68.0
[0.67.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.67.0
[0.66.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.66.0
[0.65.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.65.0
[0.64.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.64.0
[0.63.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.63.0
[0.62.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.62.0
[0.61.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.61.0
[0.60.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.60.0
[0.59.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.59.0
[0.58.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.58.1
[0.58.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.58.0
[0.57.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.57.0
[0.56.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.56.0
[0.55.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.55.0
[0.54.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.54.0
[0.53.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.53.0
[0.52.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.52.0
[0.51.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.51.0
[0.50.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.50.0
[0.49.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.49.0
[0.48.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.48.0
[0.47.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.47.1
[0.47.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.47.0
[0.46.2]: https://github.com/draugr-dev/draugr/releases/tag/v0.46.2
[0.46.1]: https://github.com/draugr-dev/draugr/releases/tag/v0.46.1
[0.46.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.46.0
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
