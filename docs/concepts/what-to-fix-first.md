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
WHAT TO DO  <n> actions clear <m> findings
  <band>  <the action>
          <the scanner's description of the rule, when the action names one>
          <each scanner and the rules it flags the line with, for a line of code>
          component <component, when there are several> · control <control> · <n> findings ·
          <upstream, when not yours> · <where it applies> ·
          <the rule it names, and how many more it clears>
```

A schematic rather than a scan, because the shape is what this page is about and a pasted run
carries package names and counts that go stale without anything noticing. `draugr scan .` prints
the real thing.

## Rows are actions, not findings

One remediation usually clears many findings. Eight vulnerabilities in one library are one
upgrade; the same misconfiguration in three Dockerfiles is one habit. Listing those as eight and
three rows makes the repetitive work crowd out everything else.

| Control | Grouped by | The action |
|---|---|---|
| `sca` | component, package and installed version | upgrade this dependency |
| `images`, when you build it | component, package and installed version | upgrade it in your image |
| `images`, when somebody else builds it | image | take a newer image |
| `images`, OS layer past end of life | operating system release | move the base |
| `secrets` | rule | remove the credential and rotate it |
| `licenses`, when somebody else builds it | image or repository | review the licenses it carries |
| `licenses`, in your own dependencies | package and license | replace the package or accept its license |
| `sast` | component, repository, file and line | change that line of code |
| `iac` | rule | apply one fix across N files |
| `kubernetes` | check | one cluster setting |

Only where the fix genuinely is one fix. Twelve benchmark checks against one cluster are twelve
things to change, and folding them together because they share a prefix would hide eleven of them.

Several rules often flag the same line. Those findings are one row, because one change clears them.
A shell command built from request input, flagged by Bandit's B602 and three Semgrep rules, is one
row that clears four findings. A rule that flags ten lines is ten rows, because each line is its
own edit.

A dependency action belongs to one component and one installed version. Two components carrying
the same library are two owners, and a second copy at another version needs its own target, so
each is its own row. The row lists the manifests, lockfiles and copies its findings were in, each
named with its repository when there is more than one. A copy of the library committed to the tree
is marked `vendored`, because bumping the lockfile leaves that file as it was.

**Grouping is opt-in for now.** `draugr scan --view actions` turns it on; the default lists one
finding per row.

Not because the list is the better view, but because grouping is only right once a descriptor says
which images the team builds and which infrastructure it operates. Without that, an action row
states a fix nobody can apply. *upgrade this library*, inside an image somebody else publishes,
where a finding row merely reports something true that a reader can look up. Stating wrong advice is
worse than listing a fact, so the annotations come first and the default follows them.

**Grouping is a rendering either way.** The report files always carry findings separately, an
auditor reading `results.sarif` sees one record per finding whichever way the console was asked to
show them.

## In the findings list, what you can act on comes first

This is the order of `--view findings`, one finding per row. Priority decides it. Where two
findings share a band, the one somebody can act on is listed first, a package with a fix, then a release that can be moved, then one with no published fix, and
last the ones that belong to a provider.

**This does not change the priority itself.** Priority feeds the gate, so demoting a finding because
nobody here can fix it would weaken a build gate as a side effect of annotating a descriptor, and
the risk is unchanged either way: a vulnerable control plane is exactly as dangerous whether or not
the fix is yours to apply. Deciding that a finding is acceptable is what
[exclusions](../reference/saga-schema.md) are for, and they record who decided.

So `operatedBy` and `builtBy` change what is *recommended* and in what order, never what a finding
is worth.

## How the list is ordered

To order two rows, compare them key by key from the top. The first key where they differ decides.

1. **Priority.** The highest band among the findings the action clears. An action clearing one P1
   outranks one clearing forty P4s, and an action with no band comes after every action with one.
2. **Exploitation.** An action clearing a finding on CISA's Known Exploited Vulnerabilities (KEV)
   catalog comes first in its band, then one clearing a finding that EPSS, a daily estimate of how
   likely a flaw is to be exploited in the next 30 days, raised past its threshold. Both apply only
   where [`config.exploitability`](prioritization.md#exploitability-kev-and-epss) turns them on.
3. **Severity.** The highest severity among its findings, after adjustment:
   - the severity KEV or EPSS raised it to, where one did;
   - else the severity reachability analysis lowered it to, where the vulnerable code is never
     called;
   - else the scanner's own rating.
4. **Count.** How many findings it clears.
5. **The step within the policy.** Of the two steps of one package's upgrade, the one within the
   component's [`fixes.upgrade`](../reference/saga-schema.md#configfixes) comes first, because the
   other presumes it. Both steps rank together, by what either clears, so they sit side by side.

Where two rows match on all five, the one whose most urgent finding comes first in
`--view findings` comes first, and that list ends on component, repository, location and rule. The
same findings therefore produce the same list on every run.

**Count breaks ties only.** It depends on how a scanner splits what it reports. One that reports a
finding per advisory per package counts an old base image in hundreds, and ranked on volume that
image would outrank a single flaw on KEV.

**Where each key comes from.** The band, the escalation naming `kev` or `epss` with the date its data
was fetched, and the severity with what adjusted it are on each finding in `report.json` and
`results.sarif`. `fixes.upgrade` is in the descriptor. To check why one row sits above another,
compare those values on the findings each row clears.

## Two descriptor fields change what is recommended

Some findings are true and not yours to act on. Telling somebody to change a file on a control plane
they cannot reach, or to upgrade a library inside an image they do not build, is advice they cannot
take, at the top of a list called *fix first*, which teaches them the list is not worth reading.

Draugr cannot work out which case it is looking at. Whether a cluster is managed, or an image is
somebody else's, is a fact about a contract rather than something visible in what a scanner reads,
the same argument that puts `exposure` and `criticality` in the descriptor.

### `operatedBy`. Who runs this infrastructure

```yaml
clusters:
  prod-cluster:
    operatedBy: provider     # self (default), or provider
```

Declared on the cluster, once, so every component on it agrees.

On `provider`, findings about the parts a managed platform runs are reported and counted but never
presented as work to do: the API server, etcd, the controller manager, and kube-proxy, which every
managed platform runs as a DaemonSet it owns.

**It narrows deliberately.** The kubelet stays yours, because node pool settings usually reach it.
So do RBAC, Pod Security and network policy, which are yours whoever runs the cluster underneath,
and are usually the findings that matter.

### `builtBy`, who publishes this image

```yaml
images:
  - image: registry.example.com/vendor/redis:8.2.2
    builtBy: upstream        # self (default), or upstream
```

On `upstream`, every vulnerability in the image becomes one action. *take a newer image*, instead of
one row per vulnerable library. Nobody can upgrade a package inside an image they do not build; the
fix is a newer image, or a wait for whoever publishes it. Its licenses become a second action, a
review of what the image carries, because a newer image carries the same licenses.

On `self` (the default), a package inside the image is yours, and the rows say to upgrade it.

### Why both default to `self`

A descriptor written by hand describes what a team builds and runs. One written by
[`draugr survey`](../reference/cli.md#draugr-survey) describes a cluster full of things they only
run, and that is the case worth declaring.

The default is also the safe direction. Marking something as somebody else's when it is yours
hides work you could have done; the reverse costs a row you skip.

## What is left out of the list, and where it goes

- **Not yours to fix**, reported, counted, and named on its own line rather than ranked among
  the work.
- **No fix published anywhere**, including an operating system past end of service life, where
  the release itself is the action.
- **Nothing at all**. A control that could not run says so; it found nothing by looking at
  nothing, and a component whose whole surface went unscanned reports `ERROR` rather than `pass`.

## Reading a row

| The row carries | What it is |
|---|---|
| the band | the highest band among the findings this one action clears |
| the action | what to do, naming the thing and the version in hand |
| the summary | the scanner's description of the rule, under an action that names a rule |
| the rules | under an action for a line of code, the rules that flag it, by scanner and starting with the rule the title quotes, and a count of those that do not fit |
| the component | which component the action belongs to, named when the list spans more than one |
| the control | which control the findings came from |
| the count | how many findings this action clears |
| `upstream` | present only where the component is somebody else's to fix |
| `major · beyond policy minor` | the size of an upgrade step and the component's [`fixes.upgrade`](../reference/saga-schema.md#configfixes) it exceeds |
| the locations | the files its findings are in, up to two named and the rest counted as `and N more`; `--view findings` lists every one. Each names its repository when the action's findings span more than one, and an action for a line of code names it once the list spans several |

An upgrade names its target version after an arrow. The target is the lowest release that clears
every finding the row counts, ordered by the package's own ecosystem, so advisories naming several
releases of one library become one release to move to. Where the ecosystem is not one Draugr can order, the target
appears only when every advisory names the same release. `5.10` is above `5.9` in most schemes and
below it as a string, and naming the wrong release as sufficient reads as *do this and you are done*
while leaving findings behind.

A component can cap the step an upgrade proposes with
[`fixes.upgrade`](../reference/saga-schema.md#configfixes). A package whose findings need more than
the cap allows gets a second action for the step past it, carrying the findings only that step
clears, listed with the first and ranked by the worse band of the two. Where versions are not
semantic, as a distribution's are, the action stays whole, and a line under the heading counts
those actions by ecosystem.

An action for a line of code is titled with one scanner's description of the flaw, in quotes.
Draugr takes it from the finding with the worst band, then the highest severity, then the highest
score. Among findings that rank alike, it takes the longest description that fits the title uncut,
then the lowest rule id. The title is the same on every run. A description too long for the title
is cut inside the quotation marks. A line that one rule flags, with a description too long for the
title, is titled with the rule's name, and the description is on the line under it.

Each row names one rule identifier, linked to whatever the scanner published about it, and counts
the rest. A row for a line of code names the rules that flag it, by scanner, and counts those that
do not fit. To read what a check means and how to fix it:

```bash
draugr explain kube-bench/cis/4.3.1
```

That prints the remediation the scanner published, so understanding a finding does not depend on
searching for its identifier.
