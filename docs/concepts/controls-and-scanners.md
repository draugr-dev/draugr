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

> Implemented today: **`images`**, **`sca`**, **`secrets`**, **`sast`**, **`iac`**, **`headers`**.
> On the roadmap: `dast`, `tls`, `sbom`, `infrastructure`, `threats`. See the
> [integrations catalog](../reference/catalog.md) or run `draugr controls`.

## Scanners

A **scanner** wraps a single security tool and normalizes its output to **SARIF**. Most
tools are integrated declaratively via a *tool adapter* — describe how to invoke the tool
and Draugr runs it and parses its SARIF. Built-in today: **Trivy** (`images`, `sca`, `iac`),
**Gitleaks** (`secrets`), **Semgrep** (`sast`, with opt-in **gosec** for Go components), and a
**native HTTP-headers** scanner (`headers`).

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
