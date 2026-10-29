---
title: Configure Draugr for a machine or an organization
description: Where draugr.config.yaml lives, what belongs in it rather than in a Saga, and how a platform team sets defaults for every repository.
section: Guides
order: 95
---

# Configure Draugr for a machine or an organization

`draugr scan` has a lot of flags. Most of them answer the same question every time you run it on a
given machine. Where the cache lives, which build of a scanner to use, how you like the report, and
retyping them, or pasting them into every pipeline, is how they end up inconsistent.

`draugr.config.yaml` is where those answers live.

```yaml
tools:
  trivy:
    version: "0.69.3"

cache:
  dir: .draugr/cache
  ttl: 12h

output:
  view: actions
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

Neither is a default Draugr imposes: `-o` writes where you point it, and caching stays opt-in. A
cache is a promise that an unchanged input has an unchanged answer, which somebody should ask for.
These are the paths the examples use and the ones `draugr explain` looks in first.

Draugr also reads `draugr-out/` and `.draugr-out/`, the names it recommended before, so a
pipeline built on those keeps working.

## Where it is read from

| Source | Use |
|---|---|
| `--config <path>` or `$DRAUGR_CONFIG` | That file **alone**. The organization-wide lever: set it in a runner image and every pipeline reads the same defaults with no per-repository change |
| `./draugr.config.yaml`, in the directory the command runs from | This project |
| `~/.draugr/config.yaml` | This machine |

The two discovered files are layered, the project's over the machine's, and only per key: a project
that sets one thing inherits the rest. A value the project writes replaces the machine's, `false`
and `0s` included, except for `cache.readOnly` and `cache.requireDigest`, which only turn on (see
[`cache`](#cache)). An explicit file replaces both.

`draugr config show` run where there is no `draugr.config.yaml` names the directory it looked in and
says that no project file was read, which is what a command run from a parent directory reads.

Controller settings are merged **underneath** the descriptor's, so a project that has an opinion
keeps it and nothing set here can override a committed Saga.

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

The file is held to the checks `draugr validate` makes of a descriptor. `set`, `validate` and every
command that reads the file, `scan` included, refuse a control or scanner this build does not
provide, a tool `tools install` does not provision, and a value a scan would refuse, naming the
file, the key and the nearest valid name:

```console
$ draugr config set controllers.sats.semgrep.config x
draugr: that edit would produce a file Draugr cannot load, so nothing was written:
  controllers: "sats" is not a control this build of Draugr provides, did you mean "sast"?

run `draugr controls` to see what this build provides
```

## What it can hold

### `tools`

Pins the build of an external scanner:

```yaml
tools:
  trivy: { version: "0.69.3" }
```

Provisioning rather than behavior, and deliberately not readable from a Saga, a descriptor that
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

`ttl: 0s` means no expiry, as `--cache-ttl 0` does. Leaving `ttl` out keeps the built-in default.

`readOnly` and `requireDigest` only turn on across files, so a project's `false` does not turn off the
machine's `true`. `draugr config show` lists that `false` under **Overridden**, beside the file that
outranks it, and `draugr config set` reports it when it writes one.

### `output`

```yaml
output:
  view: actions      # findings (the default) | actions, a row per thing to do | compact
  evidence: false    # true to always print what stands behind the verdict
  top: 20            # rows in the fix list
```

### `controllers`

The same shape as `config.controls` in a Saga, merged underneath it. A platform team can set a
default for every repository, a scanner's options, a database mirror an internal network requires,
without editing a descriptor anywhere.

### `publish`

Where runs are delivered, for the organization rather than per project.

```yaml
publish:
  apiUrl: https://draugr.acme.example
```

Forty repositories pointing at one install would otherwise repeat the endpoint in forty
descriptors, and change it in forty places when the host moves. Set it once in a runner image and
every pipeline picks it up.

**The environment names the server.** The `draugr-api` publisher sends its token to the first of:

1. `$DRAUGR_API_URL`.
2. `publish.apiUrl` in `~/.draugr/config.yaml`, or in the file `--config` or `$DRAUGR_CONFIG` names.

- A `url:` in the descriptor, or `publish.apiUrl` in `./draugr.config.yaml`, is used only on the
  origin of the server above, or on an [origin](../reference/cli.md#environment)
  `$DRAUGR_API_ORIGINS` lists (comma-separated).
- Any other origin fails the scan before it starts, naming both values.
- With no server set and a token present, every `url:` that `$DRAUGR_API_ORIGINS` does not list is
  refused.
- `publish.apiUrl` in `./draugr.config.yaml` is ignored while `$DRAUGR_API_URL` is set, or while the
  descriptor has a `url:`.

**No token, here or anywhere in this file.** It is committed alongside a project, and a credential
in it is a credential in somebody's git history. `$DRAUGR_API_TOKEN` is the only way in.

## Flags always win

Every setting here has a `--flag` that overrides it, and typing the flag wins **even when what you
typed is the zero value**. `--top 0` means show everything, and a configured cap does not quietly
override an explicit instruction.

That is what makes a configured default safe to set: it is a default, not a policy. Whether the
*gate* should work the same way. Whether an organization can set a floor a descriptor cannot lower,
is [an open question](https://github.com/draugr-dev/draugr/issues/809) rather than settled behavior,
and the gate is deliberately not configurable here yet.

## A worked example: one runner, many repositories

A platform team maintains a CI image and wants every pipeline to share a warm cache, use the
scanner builds they have reviewed, and never fail a build on a tag-named image:

```yaml
# /etc/draugr/config.yaml, referenced by DRAUGR_CONFIG in the runner image
tools:
  trivy: { version: "0.69.3" }
  semgrep: { version: "1.173.0" }

cache:
  dir: /var/cache/draugr
  requireDigest: true

output:
  view: actions
```

Nothing changes in any repository. A project that needs something different sets that one key in
its own `draugr.config.yaml`, or passes the flag, and inherits everything else.
