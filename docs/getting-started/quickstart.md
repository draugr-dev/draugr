---
title: Quickstart
description: From zero to a security verdict — describe your app, scan it, and focus on what to fix.
section: Getting started
order: 20
---

# Quickstart

This guide takes you from zero to a security verdict, then shows how discovery can write
the descriptor for you. If you haven't installed Draugr yet, start with
[install](install.md).

**Contents:** [Describe your app](#1-describe-your-app) · [Scan](#2-scan) ·
[Focus: what to fix first](#focus-what-to-fix-first) ·
[Discovery — the Ravens](#3-let-discovery-write-the-descriptor-the-ravens) ·
[Run it in CI](#4-run-it-in-ci) · [Troubleshooting](#troubleshooting)

## 1. Describe your app

Create `draugr.saga.yaml`. The **Saga** is the one artifact that maps your software to the
controls that must pass. A minimal, runnable example:

```yaml
release:
  name: my-app
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
```

A control only runs when it is **enabled** (globally under `config.controllers`, or on a
component). See [write your first Saga](first-saga.md) for a gentle walkthrough, or the
[Saga schema](../reference/saga-schema.md) for every field.

## 2. Scan

```bash
draugr scan draugr.saga.yaml
```

Draugr plans the work (controllers × components), runs the scanners concurrently, merges
and deduplicates results as SARIF, judges them against a policy, and prints a **human console
summary** by default (verdict, priority/severity counts, and the top findings to fix first):

```text
Draugr — PASS   (my-app 1.0)

Controls:
  images  pass  0 error  0 warning  0 note

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

The `verdict` and counts depend on what the scanners find — a real image like `alpine:3.19`
will typically report several vulnerabilities, so you'll see `fail` unless you use a minimal
image or raise `--fail-on`. The process **exits non-zero when the verdict is `fail`**, so it
gates a pipeline directly.

Useful flags:

```bash
draugr scan draugr.saga.yaml -o out/            # write out/report.json + out/results.sarif
draugr scan draugr.saga.yaml --fail-on warning  # stricter gate (default: error)
draugr scan draugr.saga.yaml --cache-dir .draugr-cache   # skip re-scanning unchanged targets
draugr scan draugr.saga.yaml --min-priority P2  # list only the findings worth acting on now
draugr scan draugr.saga.yaml --fail-on-priority P1  # also fail the gate on any P1 finding
```

See the [CLI reference](../reference/cli.md#draugr-scan-sagayaml) for every flag.

## Focus: what to fix first

**Classify your components.** The fastest way to set up prioritization is the guided wizard —
it asks a few questions per component and writes `exposure` and `criticality` back into your
Saga (comments and formatting preserved):

```bash
draugr classify draugr.saga.yaml
```

```
Component: web
  Exposure — how reachable is it?
  Reachable from the public internet? [y/N] y
  Does it require authentication? [y/N] n
  Criticality — impact if it fails or is compromised?
    1) outage or data loss   2) degraded, no outage   3) limited impact
  Choose [1-3]: 1
  → web: exposure=public, criticality=critical
```

(Prefer to hand-edit? The fields are in the [Saga schema](../reference/saga-schema.md). And
`draugr survey` on a k8s namespace already *proposes* `exposure` for you.)

Once components declare `exposure` and `criticality`, Draugr ranks every finding into a
priority band — combining the finding's severity with how exposed and how business-critical
its component is. The report always includes a `priorities` count (P1–P4); `--min-priority`
adds a ranked `findings` list of just those at or above the band, so you can act on the short
list instead of the whole wall:

```json
{
  "priorities": { "p1": 2, "p2": 5, "p3": 3, "p4": 0 },
  "findings": [
    { "priority": "P1", "level": "error", "score": 9.1, "control": "sca",
      "ruleId": "CVE-2025-0001", "message": "…", "location": "go.mod" }
  ]
}
```

P1 = act now · P2 = this cycle · P3 = backlog · P4 = track. A component left unclassified is
treated as high-risk so nothing slips.

**Gate on priority.** `--fail-on-priority P1` fails the build when any finding reaches that
band — component-aware gating without a per-component config, since priority already folds in
exposure and criticality. It composes with the level gate (`--fail-on`): the run fails if
*either* trips. Each control also reports its `highestPriority` as evidence. See
[prioritization](../concepts/prioritization.md) for how the bands are computed.

## 3. Let discovery write the descriptor (the Ravens)

Instead of hand-writing components, point a surveyor at your environment:

```bash
# Repositories in a GitHub org (token via --? no: GITHUB_TOKEN env or scope config)
GITHUB_TOKEN=*** draugr survey --github-org my-org -o draugr.saga.yaml

# Unique container images running in a Kubernetes namespace (uses your kubeconfig)
draugr survey --k8s-images --k8s-namespace prod --merge -o draugr.saga.yaml
```

`--merge` blends discovered components into an existing Saga instead of overwriting it. See
the [Ravens](../concepts/surveyors.md) for what each surveyor discovers.

## 4. Run it in CI

`scan`'s exit code is the gate. The easiest way to wire it into GitHub Actions is the
first-party **`draugr-dev/draugr`** action, which downloads a cosign-verified Draugr release,
runs the scan, and exposes the SARIF path for code scanning. See the
[GitHub Action guide](../guides/github-action.md) for the full workflow and all inputs, and
[code scanning](../guides/code-scanning.md) for publishing findings to the Security tab.

## Troubleshooting

- **Not sure what's installed?** — run `draugr doctor draugr.saga.yaml` for a preflight: it
  validates the descriptor and lists every scanner the Saga needs as found / missing / version,
  with an install hint for each. Use it as a CI gate: `draugr doctor saga.yaml && draugr scan saga.yaml`.
- **No findings / control didn't run** — ensure the control is `enabled` and the component
  has the relevant resources (e.g. `images` for the images control).
- **`executable file not found`** — the scanner for a control isn't on `PATH`; run
  `draugr doctor` to see exactly which tool is missing and how to install it.
- **Descriptor errors** — run `draugr validate draugr.saga.yaml` to check the Saga against the
  schema without running any scanners (good in a pre-commit hook or CI lint step).
- **Verbose output** — add `--log-level debug` (optionally `--log-format text`).
