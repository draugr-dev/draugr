---
title: Quickstart
description: From zero to a security verdict, describe your app, scan it, and focus on what to fix.
section: Getting started
order: 20
---

# Quickstart

This guide takes you from zero to a security verdict, then shows how discovery can write
the descriptor for you. If you haven't installed Draugr yet, start with
[install](install.md).

**Contents:** [Fastest path](#0-fastest-path-zero-config) · [Describe your app](#1-describe-your-app) ·
[Scan](#2-scan) · [Focus: what to fix first](#focus-what-to-fix-first) ·
[Discovery](#3-let-discovery-write-the-descriptor) ·
[Run it in CI](#4-run-it-in-ci) · [Troubleshooting](#troubleshooting)

## 0. Fastest path (zero-config)

No descriptor needed. Point Draugr at a repository:

```bash
draugr scan .          # scans the current repo with sca, secrets, sast, iac
```

That's the whole path to a verdict. Nothing to write first. When you want to pick controls, add
container images or endpoints, or classify components for prioritization, scaffold a descriptor:

```bash
draugr init            # writes a stack-detected draugr.saga.yaml to customize
```

The rest of this guide covers that descriptor-driven flow.

## 1. Describe your app

Create `draugr.saga.yaml`. The **Saga** maps your software to the controls that must pass, and
`draugr init` writes a runnable one:

```bash
draugr init
```

A control only runs when it is **enabled**, globally under `config.controls` or on a component.
[Write your first Saga](first-saga.md) builds one field by field; the
[Saga schema](../reference/saga-schema.md) has every field.

> **Turn on editor support first.** A Saga written with schema-backed completion is quicker and
> harder to get wrong: your editor offers the valid control names, the `exposure` and `criticality`
> values, and flags a typo as you type. Most editors need no setup. See
> [write a Saga in your editor](../guides/editor-support.md).

## 2. Scan

```bash
draugr scan draugr.saga.yaml
```

Draugr plans the work (controllers × components), runs the scanners concurrently, merges
and deduplicates results as SARIF, judges them against a policy, and prints a **human console
summary** by default (verdict, priority/severity counts, and the top findings to fix first):

```text
DRAUGR  PASS  my-app 1.0  1.104s

CONTROLS
  images  pass   no findings

No findings. ✓
```

For a machine-readable report use `--format json` (or write artifacts with `-o out/`):

```json
{
  "release": { "name": "my-app", "version": "1.0" },
  "verdict": "pass",
  "controls": [
    { "name": "images", "verdict": "pass", "highest": "none",
      "threshold": "error", "errors": 0, "warnings": 0, "notes": 0, "total": 0 }
  ],
  "stats": { "jobs": 1, "concurrency": 8, "scans": 1, "cacheHits": 0, "deduped": 0 }
}
```

The `verdict` and counts depend on what the scanners find, a real image like `alpine:3.19` will
typically report several vulnerabilities, so you'll see `fail` unless you use a minimal image or
raise `--fail-on`. The process **exits non-zero when the verdict is `fail`**, so it gates a pipeline
directly.

Useful flags:

```bash
draugr scan draugr.saga.yaml -o out/            # write out/report.json + out/results.sarif
draugr scan draugr.saga.yaml --fail-on P2      # widen the gate from the default, P1
draugr scan draugr.saga.yaml --fail-on medium  # or judge severity instead of the band
draugr scan draugr.saga.yaml --cache-dir .draugr/cache   # skip re-scanning unchanged targets
draugr scan draugr.saga.yaml --min-priority P2  # list only the findings worth acting on now
draugr scan draugr.saga.yaml --fail-on P1      # the default: fail on any P1 finding
```

See the [CLI reference](../reference/cli.md#draugr-scan-sagayaml--dir) for every flag.

## Focus: what to fix first

Priority folds in what you declared about each component, so a `critical` CVE on something nobody
can reach ranks below a `medium` on your login. `draugr classify` asks a few questions per
component and writes `exposure` and `criticality` back into your Saga, keeping your comments and
formatting:

```bash
draugr classify
```

[Rank findings by priority](../guides/classify-components.md) walks through the questions and what
each answer means. `draugr survey` on a Kubernetes namespace already *proposes* `exposure`.

## 3. Let discovery write the descriptor

Instead of hand-writing components, point a surveyor at your environment:

```bash
# Repositories in a GitHub org (GITHUB_TOKEN env var, or a token in scope config)
GITHUB_TOKEN=*** draugr survey github repos --org my-org -o draugr.saga.yaml

# Unique container images running in a Kubernetes namespace (uses your kubeconfig)
draugr survey k8s images --namespace prod -o draugr.saga.yaml
```

A survey adds to an existing Saga rather than overwriting it. The descriptor holds decisions a
survey cannot rediscover. Pass `--replace` to start again. See the [surveyors
reference](../concepts/surveyors.md) for what each one discovers.

## 4. Run it in CI

`scan`'s exit code is the gate, so Draugr runs anywhere that can run a binary. Each of the three
big platforms has a first-party integration that does the install, the mode selection and the
reporting for you:

| Platform | Add | Findings land in |
|---|---|---|
| **GitHub Actions** | `uses: draugr-dev/draugr@v0` | code scanning (Security tab), a sticky PR comment |
| **GitLab CI** | `include: remote: …/gitlab-ci/draugr.yml` | the merge request's Reports tab, and on Ultimate the Vulnerability Report, Dependency List and License Compliance |
| **Azure Pipelines** | `- template: azure-pipelines/draugr.yml@draugr` | the Tests tab, a sticky PR comment |

All three do the same two things: scan the branch and gate it, and on a pull or merge request
report only what the change **introduced** rather than the backlog it inherited.

- [GitHub Action guide](../guides/github-action.md) · [code scanning](../guides/code-scanning.md)
- [GitLab guide](../guides/gitlab-ci.md), one include and one masked variable
- [Azure Pipelines guide](../guides/azure-pipelines.md)

Anywhere else, Jenkins, a laptop, a cron job, install the binary and run `draugr scan`; the exit
code is the whole contract.

## 5. See the findings in your editor

CI tells you at the end; your editor tells you while you're writing. `draugr scan -o out` writes
`out/results.sarif`, which VS Code and JetBrains read as inline diagnostics, squiggles on the
offending lines, and click-to-line from a Problems list, with no Draugr-specific extension. See [see
findings in your editor](../guides/findings-in-your-editor.md).

## Troubleshooting

- **Not sure what's installed?**. Run `draugr doctor draugr.saga.yaml` for a preflight: it
  validates the descriptor and lists every scanner the Saga needs as found / missing / version,
  with an install hint for each. Use it as a CI gate: `draugr doctor saga.yaml && draugr scan saga.yaml`.
- **Sure it ran, but did it look at everything?**. The same preflight answers that. Doctor lists
  any surface the descriptor declares that no enabled control examines, so a component with images
  and the `images` control switched off is reported before the scan passes over it rather than
  after. Add `--fail-on-uncovered` to make that a failure when the descriptor is meant to be
  complete.
- **No findings / control didn't run**. Ensure the control is `enabled` and the component
  has the relevant resources (e.g. `images` for the images control).
- **`executable file not found`**, the scanner for a control isn't on `PATH`; run
  `draugr doctor` to see exactly which tool is missing and how to install it.
- **Descriptor errors**. Run `draugr validate draugr.saga.yaml` to check the Saga against the
  schema without running any scanners (good in a pre-commit hook or CI lint step).
- **Verbose output**. Add `--log-level debug` (optionally `--log-format text`).
