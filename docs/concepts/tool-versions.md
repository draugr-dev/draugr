---
title: Scanner versions
description: Which build of each external tool Draugr installs, why a pin is not always the newest release, and how to run a different one.
section: Core concepts
order: 25
---

# Which version of each scanner Draugr runs

Draugr does not bundle its scanners. It provisions them, at versions it names, and verifies the
bytes before they touch disk. This page is what that means for you, and why the version Draugr
installs is sometimes not the newest one published.

## A pin is a version that has been run

Every tool Draugr can install is pinned to one release, with the SHA-256 of the archive for each
platform recorded alongside. `draugr tools install` downloads that release, hashes it, and refuses
anything that does not match.

**The pin moves when a bump has been tested, not when a release appears.** That is the whole
difference between this and `latest`. A scanner's new version can change its output format, rename
a flag, alter how it caches, or start failing under conditions the release notes do not mention,
and any of those reaches you as a control that reports nothing or a scan that will not finish.

So a pin is a claim: this exact build was installed, checksum-verified, and run against a real
project across every control, and the findings it produced were compared with the ones before it.

## Seeing what is available

```bash
draugr tools outdated
```

```
Tool         Pinned   Upstream
gitleaks     8.30.1   8.30.1    current
trivy        0.69.3   0.74.0    draugr tools install trivy
```

Nothing is downloaded and nothing on disk changes. **Being behind is not a fault to fix**, and the
command exits zero when tools are behind; it exits non-zero only where an upstream could not be
asked, because a network that refused is a different answer from "current".

`--json` gives the same comparison for a pipeline to read. A tool that could not be asked carries
`error` there and has `behind: false`, the same value a current tool has, so a consumer checks
`error` rather than `behind` alone.

## Running a version Draugr has not pinned

```bash
draugr tools install trivy --version 0.74.0
```

The archive is still fetched from the upstream and still hashed, but against that release's own
published checksums rather than a value recorded in Draugr. You get the version you asked for and a
weaker claim about it, which the install line says.

This is the right escape hatch for a CVE fixed upstream today. It is the wrong default for a
pipeline, because the version everybody scans with then depends on when each machine last ran the
command.

## Configuration

A team that wants every pipeline scanning with the same build writes it where it gets reviewed,
rather than in each runner's setup:

```yaml
# draugr.config.yaml
tools:
  trivy: { version: "0.74.0" }
```

See [configuration](../guides/configuration.md#what-it-can-hold).

## Three tools are built rather than downloaded

`govulncheck`, `retire.js` and `semgrep` publish no release binary, so Draugr builds them from
source with the Go toolchain, npm and Python respectively. Two things follow.

**The runtime has to be on the machine.** `draugr tools list` names which one each needs, and
`draugr tools install` with no arguments skips the ones it cannot build, tells you which, and
installs the rest. Asking for one of them by name on a host without its runtime is an error rather
than a skip.

**The pin is a resolved tree, not one file.** Semgrep is pinned by the digest PyPI publishes for
every package in its dependency tree, and retire.js by an npm lockfile. Where that resolution
cannot be applied on your platform, the install falls back to an unpinned resolve and says so,
because a pin that only holds on the maintainer's machine would make the tool uninstallable
everywhere else.

## How a pin moves

A scheduled job asks the same question `draugr tools outdated` does, and for each tool that is
behind it moves the pin, then tries to break it:

- every tool installed for real at the new version and checksum-verified;
- a full scan of every control against a live project, **three times against a cold cache**;
- the findings compared with what the previous pin produced.

It opens one pull request per tool, with that comparison in the body, and merges nothing.

**Three cold runs rather than one, and the reason is worth knowing if you run scanners
concurrently yourself.** A scanner release once broke a control only when several tools raced for
one cache directory on a machine that had never run them, in roughly one run in three. The hashes
were right, the unit tests passed, and a single warm scan proved none of it.

**A difference in findings is not automatically wrong.** A scanner release changes what it reports,
and a threshold that failed on every real improvement would be one people route around. A control
that reported findings before and reports none after is different, and stops the bump.

Only the platform CI runs on is exercised. The other three are pinned by hash and unrun, which is
the next bullet.

## What a pin does not cover

- **The data the tool reads.** A vulnerability database, a rule pack and a template set are
  fetched at their own cadence and are not pinned by version. `draugr doctor` lists what a scan
  contacts, and [air-gapped](../guides/air-gapped.md) covers running without that.
- **A tool you installed yourself.** Draugr uses what is on `PATH` when it is not the one Draugr
  provisioned, and reports the version it found. `draugr doctor` says which it is and where.
- **Platforms other than yours.** All four are pinned by hash; only the one you run is exercised
  before a pin moves.
