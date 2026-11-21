---
title: Write your first Saga
description: A gentle walkthrough of authoring draugr.saga.yaml, release, controls, and components.
section: Getting started
order: 40
---

# Write your first Saga

The **Saga** (`draugr.saga.yaml`) is Draugr's descriptor, a declarative account of an application's
security surface and the controls that must pass. This page walks you from a one-component file to a
classified, multi-control descriptor. For the exhaustive field list, see the [Saga
schema](../reference/saga-schema.md).

> **Shortcut:** `draugr init` scaffolds this file from what your tree holds: dependency files,
> copied JavaScript, infrastructure code, Dockerfiles and OpenAPI documents. And if you just want a scan now, `draugr scan .` needs no Saga at all.

## The smallest thing that runs

A Saga names its project and declares at least one component with an enabled control:

```yaml
project: my-app
config:
  controls:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
```

Run it with `draugr scan draugr.saga.yaml`. A control only runs when it is **enabled**, globally
under `config.controls`, or on an individual component. `release: { version: "1.0" }` labels the
reports with the build being scanned.

## A starter for a repository

The sections most projects set first, for the repository the file sits in. Copy it and run
`draugr scan draugr.saga.yaml`:

```yaml
project: my-app
config:
  gate:
    failOn: P1                 # fail the run on a P1 finding, the most urgent of P1 to P4 (the default)
  fixes:
    upgrade: minor             # never propose a major-version upgrade, which can break your code
  controls:
    sca:     { enabled: true } # vulnerable dependencies
    secrets: { enabled: true } # leaked credentials
    sast:    { enabled: true } # flaws in your own code, such as injection
    iac:     { enabled: true } # misconfigured Dockerfiles, Terraform and Kubernetes manifests
components:
  - name: app
    # exposure: internal       # who can reach it: public, authenticated, internal or restricted
    # criticality: supporting  # what an outage costs: critical, important or supporting
    repositories:
      - url: .
```

`exposure` and `criticality` decide a finding's priority, so a flaw in a public, critical service
ranks above the same flaw in an internal tool. Left out, as here, the component is ranked as
`public` and `critical`, so nothing hides before you decide. Declare them once you know: a lower
exposure or criticality moves this component's findings down, which is right only when it is true.
The Saga schema's [`components`](../reference/saga-schema.md#components) section says what each
value means.

## Add more of your surface

Each component is one logical part of your app. List whatever applies, repositories, images, hosts,
Kubernetes clusters, and enable the controls that should cover it:

```yaml
config:
  controls:
    images:  { enabled: true }
    sca:     { enabled: true }   # dependency scanning
    secrets: { enabled: true }   # leaked-credential detection
components:
  - name: web
    repositories:
      - url: https://github.com/acme/web.git
        revision: main
    images:
      - image: registry.example.com/acme/web:1.0
        digest: sha256:…            # optional. Pin the immutable content digest
```

A repository scan needs `git` on your `PATH`; an image scan needs Trivy. Run
`draugr doctor draugr.saga.yaml` to confirm the tools each enabled control needs are present.

It answers a second question at the same time, and this is the moment it is most worth asking:
whether anything is set to look at what you just declared. A descriptor that names images while
the `images` control is off scans clean over them, and a first Saga is exactly where that happens:

```
NOT CHECKED
  Component  Surface  Controls off
  web        images   images
```

## Classify components so priority means something

Two optional attributes turn a wall of findings into a ranked list, `exposure` (how reachable the
component is) and `criticality` (the business impact if it fails):

```yaml
components:
  - name: web
    exposure: public          # public | authenticated | internal | restricted
    criticality: critical     # critical | important | supporting
    images:
      - image: registry.example.com/acme/web:1.0
```

Draugr combines these with each finding's severity to assign a **P1–P4** priority. See
[prioritization](../concepts/prioritization.md). You can set them by hand, or let the guided
[`draugr classify`](../reference/cli.md#draugr-classify-sagayaml--directory) wizard write them for
you.

## Reference environment variables, not secrets

Any string value may reference an environment variable with `${{ VAR_NAME }}`, if it is one of
the [built-in CI names](../reference/saga-schema.md#substitution) or one the pipeline lists in
`$DRAUGR_SAGA_ENVS`. Loading fails fast on any other name, and on a listed one that is unset. Never
put a token in the Saga itself:

```yaml
project: my-app
release:
  version: "${{ RELEASE_VERSION }}"
```

## Next steps

- [Quickstart](quickstart.md). Scan the Saga and read the verdict.
- [Saga schema](../reference/saga-schema.md), every field, including `config.publishers` and
  `references`.
- [Let discovery write it for you](../concepts/surveyors.md). Surveyors can generate the
  descriptor from a cluster or GitHub org.
