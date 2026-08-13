---
title: Principles
description: What Draugr optimizes for — great UX and a low learning curve for people new to security.
section: Core concepts
order: 5
---

# Principles

Draugr is a security orchestration engine, but the hard part of security at most teams
isn't running scanners — it's making their output *usable* by the people who have to act on
it. Draugr is built around two values, and when a design choice is in tension, these are how
it's resolved.

## 1. Great UX

Security tooling earns its keep only if people actually run it and read what it says. Draugr
treats the developer experience as a feature, not an afterthought.

- **Zero-config start, sensible defaults.** `draugr scan .` scans the current repo with no
  descriptor — Draugr picks a reasonable set of controls and gets out of your way. You add a
  [Saga](saga.md) when you want to describe more of your app, not to get started. See the
  [Quickstart](../getting-started/quickstart.md).
- **Describe *what*, not *how*.** The Saga is declarative: you describe your app's surface and
  which controls must pass; Draugr figures out which scanners to run, in what order, with
  caching and parallelism. You don't wire tools together by hand.
- **One tool, one mental model.** The same descriptor and the same verdict drive a local run, a
  [GitHub Action](../guides/github-action.md), a [GitLab pipeline](../guides/gitlab-ci.md), an
  [Azure template](../guides/azure-pipelines.md), and a [PR diff](../guides/pr-diff.md). What you
  see locally is what CI enforces — and a platform's own dashboards get the format they read,
  rather than the one Draugr would rather emit.

## 2. Human-readable by default

Draugr's output is meant to be read by a person first. The readable, colorized presentation is
the **default**; machine-readable formats are always available, but you opt into them — never
the other way around.

- **Readable and colorized out of the box.** The scan summary leads with a verdict, priority
  counts, and a ranked table of what to fix first (with a header and a column naming both the control
  *and* the scanner behind each finding). Logs render the same way —
  `HH:MM:SS LEVEL  message key=value` — so diagnostics are legible at a glance. Color appears
  only on an interactive terminal and honors [`NO_COLOR`](https://no-color.org); piped or
  redirected output stays plain text.
- **Machine formats are the opt-in.** Structured output is one flag away —
  [`--format json` / `--format sarif`](../guides/reports-and-publishers.md) for reports,
  `--log-format json` for logs — for CI and observability pipelines. Draugr never makes a person
  read JSON just to see what happened.

## 3. A low learning curve for people new to security

You should not need to already be a security expert to get value from Draugr. Every choice that
lowers the barrier for a newcomer — without dumbing things down for a professional — is worth
making.

- **Recognized industry terms, not invented jargon.** Controls use the names practitioners
  already know (`sca`, `sast`, `secrets`, `dast`, …) so the tool is easy to learn and respected
  by security professionals. Draugr's Norse names are flavor, never something you must learn to
  use it — see [Naming & control taxonomy](../contributing/naming.md).
- **Plain-language definitions.** The [security glossary](../reference/glossary.md) defines
  every category in plain language, so the whole team shares the vocabulary — no prior security
  background assumed.
- **It tells you what to fix first.** Findings are ranked into [P1–P4](prioritization.md) from
  exposure, criticality, and severity, so a newcomer isn't handed an undifferentiated wall of
  results and left to guess what matters.
- **Gentle on-ramps.** `draugr init` scaffolds a starter Saga, and the
  [surveyors](surveyors.md) can discover your app's surface and write one for you — so the first
  useful scan is minutes away, not a research project.
- **Actionable evidence.** Each finding carries where it is, how serious it is, and which
  scanner reported it, so "what do I do about this" has an answer without deep tooling
  knowledge.

## What this means in practice

These aren't only user-facing promises; they constrain how Draugr is built. A new control or
flag should have a sensible default and read clearly in the console before it grows knobs. New
output is readable first — a machine format is added as an explicit option, not the default. A
new term gets a plain-language glossary entry. Output that a newcomer can't act on is a bug,
not a detail. When two designs are otherwise equal, the one that a person new to security can
pick up faster wins.
