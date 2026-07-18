---
title: Write your first Saga
description: A gentle walkthrough of authoring draugr.saga.yaml — release, controls, and components.
section: Getting started
order: 30
---

# Write your first Saga

The **Saga** (`draugr.saga.yaml`) is Draugr's descriptor — a declarative account of an
application's security surface and the controls that must pass. This page walks you from a
one-component file to a classified, multi-control descriptor. For the exhaustive field list,
see the [Saga schema](../reference/saga-schema.md).

## The smallest thing that runs

A Saga needs a `release` and at least one component with an enabled control:

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

Run it with `draugr scan draugr.saga.yaml`. A control only runs when it is **enabled** —
globally under `config.controllers`, or on an individual component.

## Add more of your surface

Each component is one logical part of your app. List whatever applies — repositories, images,
hosts, infrastructure — and enable the controls that should cover it:

```yaml
config:
  controllers:
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
        digest: sha256:…            # optional — pin the immutable content digest
```

A repository scan needs `git` on your `PATH`; an image scan needs Trivy. Run
`draugr doctor draugr.saga.yaml` to confirm the tools each enabled control needs are present.

## Classify components so priority means something

Two optional attributes turn a wall of findings into a ranked list — `exposure` (how
reachable the component is) and `criticality` (the business impact if it fails):

```yaml
components:
  - name: web
    exposure: public          # public | authenticated | internal | restricted
    criticality: critical     # critical | important | supporting
    images:
      - image: registry.example.com/acme/web:1.0
```

Draugr combines these with each finding's severity to assign a **P1–P4** priority — see
[prioritization](../concepts/prioritization.md). You can set them by hand, or let the guided
[`draugr classify`](../reference/cli.md#draugr-classify-sagayaml) wizard write them for you.

## Reference environment variables, not secrets

Any string value may reference an environment variable with `${{ VAR_NAME }}`; loading fails
fast if a referenced variable is unset. Never put a token in the Saga itself:

```yaml
release:
  name: my-app
  version: "${{ RELEASE_VERSION }}"
```

## Next steps

- [Quickstart](quickstart.md) — scan the Saga and read the verdict.
- [Saga schema](../reference/saga-schema.md) — every field, including `config.reports`,
  `config.publishers`, and `references`.
- [Let discovery write it for you](../concepts/surveyors.md) — the Ravens can generate the
  descriptor from a cluster or GitHub org.
