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

`trivy-license` and `kube-bench` are the two that do not consume SARIF — Trivy reports licences
only in its JSON output, and kube-bench has no SARIF mode at all — so those scanners do the
conversion themselves.

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
