---
title: Controls & scanners
description: Controllers own a security control; scanners wrap a tool and normalize to SARIF.
section: Core concepts
order: 20
---

# Controls & scanners

A **control** is a category of security check (e.g. dependency scanning). Draugr models each
control with a **controller** that plans the work, and one or more **scanners** that do it.

## Controllers

A **controller** owns one **security control**. It plans the work for the components it
applies to and aggregates the results. Controllers are either **project-scoped** or
**component-scoped**.

> Implemented today: **`images`**, **`sca`**, **`licenses`**, **`secrets`**, **`sast`**,
> **`iac`**, **`headers`**, **`dast`**, **`tls`**, **`infrastructure`**. On the roadmap: `threats`.
> See the [integrations catalog](../reference/catalog.md) or run `draugr controls`.
>
> **An SBOM is not a control.** Every row in the controls table means "checked, and here is the
> verdict"; an inventory has no verdict to give, so one would always read `pass` without having
> looked for anything. `config.sbom` produces it as evidence instead — written alongside the
> other artifacts and never part of pass or fail.

## Scanners

A **scanner** wraps a single security tool and normalizes its output to **SARIF**. Most
tools are integrated declaratively via a *tool adapter* — describe how to invoke the tool
and Draugr runs it and parses its SARIF. Built-in today: **Trivy** in four modes —
`trivy` (`images`), `trivy-fs` (`sca`), `trivy-config` (`iac`) and `trivy-license` (`licenses`) —
**Gitleaks** (`secrets`), **Semgrep** (`sast`, with opt-in **gosec** for Go components),
**Nuclei** (`dast`), **kube-bench** (`infrastructure`), and native scanners for `headers` and
`tls` that need no external tool.

`trivy-license` and `kube-bench` are the two that do not consume SARIF — Trivy reports licenses
only in its JSON output, and kube-bench has no SARIF mode at all — so those scanners do the
conversion themselves.

## How much of a tool a descriptor can reach

Two coherent positions exist and drifting between them is how a descriptor becomes a wrapper
around somebody else's command line. Draugr takes the first, with one deliberate exception.

**Curated.** A scanner exposes named options for the settings Draugr can be responsible for. Each
one is declared in a JSON Schema, validated before the scan runs, listed by
`draugr controls --options`, and means the same thing in every release. The tool's flags are
Draugr's business; the option is the contract. This is what makes a Saga survive a scanner being
swapped for a different one — `deny: [AGPL-3.0-only]` is a statement about the release, and it
holds whichever tool answers the `licenses` control.

**Verbatim passthrough**, where curating would mean tracking a surface that is not ours. Mend's
`settings` block is the one that exists: what the Unified Agent discovers depends entirely on how
each ecosystem's package manager was told to run, a curated subset would lag behind every
ecosystem Mend supports, and the people running it already know these keys from their own Mend
setup. The test for adding another is whether the option space belongs to somebody else and
changes on their schedule — not whether a passthrough would be convenient.

**A scanner that accepts nothing declares that too.** An unrecognized key under any scanner's
block is an error naming the key, not a setting that quietly does nothing:

```
sca/trivy-fs: config: unknown option "severity"
```

The alternative is worse than it looks. A validator that ignores what it does not recognize
turns a typo into a silent behavior change: the scan is green, the log says nothing, and the
only symptom is a setting that never took effect. Someone reading the descriptor afterwards has
every reason to believe it did.

## SARIF everywhere

Every finding is normalized to **SARIF 2.1.0** (the OASIS standard). That means plugins
interoperate, and results push straight into GitHub / Azure DevOps / GitLab security
dashboards.

## Content-hash caching

Each scan job has a cache key derived from its inputs (scanner, version, target identity,
config). With a cache enabled (`--cache-dir`), an unchanged target is never re-scanned —
the "cheap at scale" pillar. Cache entries have a configurable TTL because new
vulnerabilities can affect an unchanged artifact; the key also folds in the scanner tool and
its vulnerability-DB version, so a DB refresh (new CVEs) invalidates stale results before the
TTL expires.

For **container images**, the target identity is the immutable **digest** when known,
falling back to the tag otherwise. A tag is mutable — a rebuilt image pushed under the same
tag would keep the same key and serve the old scan until the TTL. To make caching
content-addressed (a rebuilt image re-scans immediately), give each image a `digest:` in the
Saga: the `k8s-images` surveyor records the running digest automatically, and Draugr scans
the digest-pinned reference so the bytes scanned match what the result is cached under.

## Going deeper

The **Learn** section explains the security categories themselves — what each control is for,
independent of Draugr:

- [The security controls landscape](/learn/security-controls-landscape/) — how the categories
  fit together, and which ones a given app actually needs
- [SCA](/learn/sca/) · [SAST](/learn/sast/) · [Secret scanning](/learn/secret-scanning/) ·
  [IaC misconfiguration](/learn/iac-misconfiguration/) ·
  [Container image scanning](/learn/container-image-scanning/) ·
  [DAST](/learn/dast/) · [TLS assessment](/learn/tls-assessment/) ·
  [HTTP security headers](/learn/http-security-headers/)
- [SARIF](/learn/sarif/) — the interchange format everything here normalizes to
- [Shift-left / DevSecOps](/learn/shift-left-devsecops/) — why this runs in CI at all
