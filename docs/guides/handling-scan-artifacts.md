---
title: Handle scan artifacts that hold sensitive data
description: What each file Draugr writes and each payload it sends contains, what never leaves the machine, and how to keep the rest where it belongs.
section: Guides
order: 75
---

# Handle scan artifacts that hold sensitive data

A scan's output names an application's weaknesses, the files they sit in, and how much the business
depends on each component. Some environments hold that as closely as the code. This guide lists
what each artifact Draugr writes or sends carries, so you can decide where each may be kept, who
may read it, and what may leave the machine.

**Contents:** [What a run writes](#what-a-run-writes) ·
[What no artifact carries](#what-no-artifact-carries) ·
[What leaves the machine](#what-leaves-the-machine) ·
[Keep the rest where it belongs](#keep-the-rest-where-it-belongs)

## What a run writes

`draugr scan` writes nothing to disk unless asked. `-o <dir>` writes `report.json` and
`results.sarif`, and `--report` names further formats for the same directory.

| Artifact | Written when | Carries |
|---|---|---|
| `results.sarif` | `-o`, by default | each finding's rule, message, file path and line, package and version, component, the component's declared exposure, criticality and labels, its priority, reachability call paths where an analyzer found them, and suppressions with their reason and who accepted them; what each scanner said about its run |
| `report.json` | `-o`, by default | the same findings, plus the descriptor's path and digest and the gate. In CI it names the pipeline run, who started it and who wrote the commit: handle, display name and account ID, and an email only when `config.ci.recordEmail` asks for it |
| `report.html`, `report.md`, `report.txt`, `evidence.txt` | `--report html`, `markdown`, `console`, `evidence` | the findings, rendered for a person |
| `report.junit.xml`, `gl-*.json` | `--report junit` or a GitLab format | the findings, in the shape that platform reads |
| `openvex.json` | `--report vex` | a status for each vulnerability on each component, with the reason and the person an exclusion records |
| SBOM files (`*.cdx.json`, `*.spdx.json`) | an `sbom` setting in the descriptor | every package each component ships, with versions and package URLs |
| cache entries | `--cache-dir` | one normalized report per job, holding the same finding fields as `results.sarif`: gzipped JSON, not encrypted |
| a trace log | `--log-file`, or `--log-level trace` on stderr | every record, including each scanner's raw output, which carries source lines from the files a finding names |

Each repository is cloned into the system's temporary directory for the scan and removed when the
run ends. The databases, rule packs and exploit feeds Draugr keeps under `~/.draugr` hold public
data. Trivy keeps its own cache in `~/.cache/trivy`, which can hold the packages it found in a
scanned image or tree; `trivy clean --scan-cache` empties that part.

## What no artifact carries

- **A secret's value.** Gitleaks reports the matched text; Draugr writes the file and the line,
  never the text, into any report or cache entry.
- **Who committed a secret found in history.** A finding from `history: true` keeps the commit it
  was found at, not the commit's author, email, date or message.
- **Source code**, except in a trace log.

## What leaves the machine

- **Draugr's own fetches**: rule packs, vulnerability databases and exploit feeds.
  `draugr doctor <saga>` lists each one under **NETWORK**, and `--offline` stops all of them. See
  [run Draugr air-gapped](air-gapped.md).
- **Scanners that send something about the target.** A scan prints a `disclosure:` line naming
  what each one sent and to whom, and each such scanner's page in the
  [catalog](../reference/catalog.md) has a *What is sent* section.
- **Publishers.** Each `publish:` destination delivers findings to somebody else: a code-scanning
  upload, a pull-request comment, an issue or a work item. Adding one is a decision about who
  receives the fields [what a run writes](#what-a-run-writes) lists, and `--no-publish` skips every
  publisher for a run. A publisher sends a finding whole; there is no setting to withhold fields
  from it (https://github.com/draugr-dev/draugr/issues/1416).

## Keep the rest where it belongs

- **Store no baseline unless you need one.** `draugr diff` compares two files it is handed, and
  the GitHub Action, the GitLab template and the Azure Pipelines template scan the base branch in
  the same run on a pull request. Nothing persists between runs by default. Storing the base's
  `results.sarif` as an artifact works when both sides run the same Draugr release; see
  [gate pull requests on new findings](pr-diff.md).
- **Keep a cache inside one trust boundary.** An entry is a result: whoever can write one decides
  what the next scan reports. Give runs whose results the next run must not trust, such as pull
  requests from forks, `--cache-read-only`. `--cache-ttl` bounds how old a reused entry may be, 24
  hours unless set. See [caching and performance](caching-and-performance.md).
- **Treat a trace log as source code.** It is the one artifact that carries lines of the
  repository; keep it out of artifact uploads.
- **Let the platform hold retention and access.** How long an artifact or cache is kept and who may
  read it are set where it is stored: [GitHub Actions
  artifacts](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/removing-workflow-artifacts)
  and [caches](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/caching-dependencies-to-speed-up-workflows),
  [GitLab job artifacts](https://docs.gitlab.com/ci/jobs/job_artifacts/) and
  [caching](https://docs.gitlab.com/ci/caching/), and [Azure Pipelines
  retention](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/retention).
- **Decide what a finding may say before it is written.** No setting removes paths, packages,
  reachability or the declared exposure, criticality and labels from a report. Where those are
  sensitive, the artifacts that carry them are, too.
