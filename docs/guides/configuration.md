---
title: Configure Draugr for a machine or an organization
description: Where draugr.config.yaml lives, what belongs in it rather than in a Saga, and how a platform team sets defaults for every repository.
section: Guides
order: 95
---

# Configure Draugr for a machine or an organization

`draugr scan` has a lot of flags. Most of them answer the same question every time you run it on a
given machine — where the cache lives, which build of a scanner to use, how you like the report —
and retyping them, or pasting them into every pipeline, is how they end up inconsistent.

`draugr.config.yaml` is where those answers live.

```yaml
tools:
  trivy:
    version: "0.69.3"

cache:
  dir: .draugr/cache
  ttl: 12h

output:
  group: action
  top: 20

controllers:
  sca:
    trivyFs:
      pkgTypes: [library]
```

## The question that decides where a setting goes

**Is this a fact about the application, or about the machine reading it?**

A descriptor describes an application: its components, what they are exposed to, which controls
apply, what has been accepted and by whom. It is committed, shared, and read by everyone who scans
that application.

Configuration describes the place the scan is happening. A cache directory is a fact about a
runner image; two projects on one runner want the same one, and one project on two runners does
not want its descriptor naming a path that exists on only one of them. Rendering preferences are
the same: an auditor wants the evidence on every scan *they* run, and asserting that in a
descriptor imposes it on everybody else.

If the answer would be wrong for a colleague scanning the same application on a different machine,
it belongs here rather than in the Saga.

## Where Draugr writes

Everything a run produces belongs under `.draugr/` in the project, beside the descriptor and
exclusions it already keeps there:

| Path | What |
|---|---|
| `.draugr/out/` | reports and SARIF from `-o` |
| `.draugr/cache/` | the result cache, when you enable one |
| `.draugr/self.saga.yaml`, `.draugr/exclusions/` | descriptor and shared exclusions |

One directory to ignore in git rather than several names, and it stays out of the way of the
project's own files.

Neither is a default Draugr imposes: `-o` writes where you point it, and caching stays opt-in —
a cache is a promise that an unchanged input has an unchanged answer, which somebody should ask
for. These are the paths the examples use and the ones `draugr explain` looks in first.

Draugr also reads `draugr-out/` and `.draugr-out/`, the names it recommended before, so a
pipeline built on those keeps working.

## Where it is read from

| Source | Use |
|---|---|
| `$DRAUGR_CONFIG` | An explicit path. The organization-wide lever: set it in a runner image and every pipeline picks up the same defaults with no per-repository change |
| `draugr.config.yaml` beside the descriptor | This project, on this machine |

Later sources win per key, and only per key: a project that sets one thing inherits the rest.

Controller settings are merged **underneath** the descriptor's, so a project that has an opinion
keeps it. That is deliberate — defaults a Saga cannot override are a guarantee a CLI cannot keep,
because the configuration file lives on a machine the same person controls.

## Reading and editing it

```bash
draugr config show          # every setting in effect, and which file each came from
draugr config get cache.dir # one value, as resolved
draugr config set cache.ttl 12h
draugr config unset cache.ttl
```

`show` reports provenance rather than just values, which is the question you actually have when a
scan behaves unexpectedly on one machine. `set` edits the file in place and keeps it valid,
preserving the comments you wrote around the setting.

## What it can hold

### `tools`

Pins the build of an external scanner:

```yaml
tools:
  trivy: { version: "0.69.3" }
```

Provisioning rather than behavior, and deliberately not readable from a Saga — a descriptor that
pinned a scanner version would be asserting something about every machine that ever scans it.

### `cache`

```yaml
cache:
  dir: .draugr/cache
  ttl: 12h
  readOnly: false
  requireDigest: true
```

See [caching & performance](caching-and-performance.md) for what each means and
[the cache architecture](../contributing/cache.md) for why the settings live here.

Note `ttl: 0` in a file means *the built-in default*, not "never expire" — a file that omits a
field is not asking for entries that live forever. Write `0s` to mean that.

### `output`

```yaml
output:
  group: action      # or none, to list every finding on its own row
  evidence: false    # true to always print what stands behind the verdict
  top: 20            # rows in the fix list
```

### `controllers`

The same shape as `config.controllers` in a Saga, merged underneath it. A platform team can set a
default for every repository — a scanner's options, a database mirror an internal network requires
— without editing a descriptor anywhere.

## Flags always win

Every setting here has a `--flag` that overrides it, and typing the flag wins **even when what you
typed is the zero value**. `--top 0` means show everything, and a configured cap does not quietly
override an explicit instruction.

That is what makes a configured default safe to set: it is a default, not a policy. Whether the
*gate* should work the same way — whether an organization can set a floor a descriptor cannot
lower — is [an open question](https://github.com/draugr-dev/draugr/issues/809) rather than settled
behavior, and the gate is deliberately not configurable here yet.

## A worked example: one runner, many repositories

A platform team maintains a CI image and wants every pipeline to share a warm cache, use the
scanner builds they have reviewed, and never fail a build on a tag-named image:

```yaml
# /etc/draugr/config.yaml — referenced by DRAUGR_CONFIG in the runner image
tools:
  trivy: { version: "0.69.3" }
  semgrep: { version: "1.173.0" }

cache:
  dir: /var/cache/draugr
  requireDigest: true

output:
  group: action
```

Nothing changes in any repository. A project that needs something different sets that one key in
its own `draugr.config.yaml`, or passes the flag, and inherits everything else.
