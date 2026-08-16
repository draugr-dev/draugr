---
title: What to fix first
description: How Draugr turns findings into a list of actions, and how operatedBy and builtBy change what it recommends.
section: Core concepts
order: 45
---

# What to fix first

A scan of a real project produces hundreds of findings. Ranking them by severity produces a
correctly ordered list that is still no use, because the top of it is usually work nobody reading
it can do.

Draugr's fix list answers a different question: **what should I do, and what will it clear?**

```
Fix first — 5 actions clear 616 findings:
  P1  Update istio/install-cni:1.30.0  images · 184 findings · upstream
      CVE-2026-8925 +183
  P1  Upgrade Jinja2 2.10  sca · 6 findings
      fixed in 2.10.1, 3.1.6, 3.1.5 and 3 other releases — take the latest
```

## Rows are actions, not findings

One remediation usually clears many findings. Eight vulnerabilities in one library are one
upgrade; the same misconfiguration in three Dockerfiles is one habit. Listing those as eight and
three rows makes the repetitive work crowd out everything else.

| Control | Grouped by | The action |
|---|---|---|
| `sca` | package | upgrade this dependency |
| `images`, when you build it | package | upgrade it in your image |
| `images`, when somebody else builds it | image | take a newer image |
| `images`, OS layer past end of life | operating system release | move the base |
| `secrets` | file | remove the credential |
| `iac` | rule | apply one fix across N files |
| `infrastructure` | check | one cluster setting |

Only where the fix genuinely is one fix. Twelve benchmark checks against one cluster are twelve
things to change, and folding them together because they share a prefix would hide eleven of them.

**Grouping is a rendering.** `--group none` lists every finding on its own row, and the report
files always carry them separately — an auditor reading `results.sarif` sees one record per
finding whichever way the console was asked to show them.

## Ranking is by the worst thing an action clears

Actions are ordered by the highest priority among their findings, and only then by how many they
clear. An action clearing one P1 outranks one clearing forty P4s.

Volume never promotes: a P1 is not something to trade away for a bigger number.

## Two descriptor fields change what is recommended

Some findings are true and not yours to act on. Telling somebody to change a file on a control
plane they cannot reach, or to upgrade a library inside an image they do not build, is advice
they cannot take — at the top of a list called *fix first*, which teaches them the list is not
worth reading.

Draugr cannot work out which case it is looking at. Whether a cluster is managed, or an image is
somebody else's, is a fact about a contract rather than something visible in what a scanner reads
— the same argument that puts `exposure` and `criticality` in the descriptor.

### `operatedBy` — who runs this infrastructure

```yaml
infrastructure:
  - kind: kubernetes
    ref: prod-cluster
    operatedBy: provider     # self (default), or provider
```

On `provider`, findings about the parts a managed platform runs are reported and counted but
never presented as work to do: the API server, etcd, the controller manager, and kube-proxy —
which every managed platform runs as a DaemonSet it owns.

**It narrows deliberately.** The kubelet stays yours, because node pool settings usually reach it.
So do RBAC, Pod Security and network policy, which are yours whoever runs the cluster underneath —
and are usually the findings that matter.

### `builtBy` — who publishes this image

```yaml
images:
  - image: registry.example.com/vendor/redis:8.2.2
    builtBy: upstream        # self (default), or upstream
```

On `upstream`, every finding in the image becomes one action — *take a newer image* — instead of
one row per vulnerable library. Nobody can upgrade a package inside an image they do not build;
the fix is a newer image, or a wait for whoever publishes it.

On `self` (the default), a package inside the image is yours, and the rows say to upgrade it.

### Why both default to `self`

A descriptor written by hand describes what a team builds and runs. One written by
[`draugr survey`](../reference/cli.md#draugr-survey) describes a cluster full of things they only
run, and that is the case worth declaring.

The default is also the safe direction. Marking something as somebody else's when it is yours
hides work you could have done; the reverse costs a row you skip.

## What is left out of the list, and where it goes

- **Not yours to fix** — reported, counted, and named on its own line rather than ranked among
  the work.
- **No fix published anywhere** — including an operating system past end of service life, where
  the release itself is the action.
- **Nothing at all** — a control that could not run says so; it found nothing by looking at
  nothing, and a component whose whole surface went unscanned reports `ERROR` rather than `pass`.

## Reading a row

```
P1  Upgrade Jinja2 2.10  sca · 6 findings
    fixed in 2.10.1, 3.1.6, 3.1.5 and 3 other releases — take the latest
```

The target version appears only when every advisory agrees on one. Where they disagree, Draugr
does not choose: version ordering belongs to the ecosystem — `5.10` is above `5.9` in most schemes
and below it as a string — and naming the wrong release as sufficient reads as *do this and you
are done* while leaving findings behind.

Each row names one rule identifier, linked to whatever the scanner published about it, and counts
the rest. To read what a check means and how to fix it:

```bash
draugr explain kube-bench/cis/4.3.1
```

That prints the remediation the scanner published, so understanding a finding does not depend on
searching for its identifier.
