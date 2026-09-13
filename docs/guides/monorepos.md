---
title: Scan a monorepo
description: One repository, many teams. How to carve it into components, give each team a pipeline that covers its own code, and keep two scans of one commit from erasing each other.
section: Guides
order: 19
---

# Scan a monorepo

A scanner's usual model is one repository, one application, one owner, one verdict. A monorepo
breaks all four at once, and the breakages compound: one repository is many applications, so a
single verdict describes nothing anybody owns; one application is many subtrees, so a scan scoped
to one cannot see the rest; one flaw is many findings, because a shared library is imported by
everything; and one commit produces many scans, which the platforms receiving them mostly assume
it does not.

Draugr's descriptor is built around the first of those. The rest of this page is what to do about
the other three.

## Decide first: one project, or several

This is the decision everything else follows from, and it is not about the repository's shape. **It
is about who gates.**

**One pipeline over the whole tree is one project.** One `draugr.saga.yaml`, components inside it,
one verdict, one team answering for it. A platform team that owns CI while feature teams own code
is this shape.

**Each team gating its own slice is several projects.** A Saga per team, each with its own
`project:`, each with its own pipeline. They can live in the same repository and read the same
files. [Splitting a Saga across files](saga-fragments.md) shows the mechanics, written there for
several products and identical for several teams.

The second shape gets a few things for nothing: each team's gate blocks only its own merges, the
control plane files each under its own project, and the code-scanning categories are already
distinct. Take it where teams genuinely gate independently.

The rest of this page is the first shape, which is the harder one.

## Carve the tree into components

A component is a part of the application, and `paths:` is what makes it a part of one repository
rather than all of it:

```yaml
project: acme
release: { version: "4.2.0" }

components:
  - name: storefront
    exposure: public
    criticality: important
    labels: { team: web }
    repositories:
      - url: .
        paths: [services/storefront]

  - name: ledger
    exposure: internal
    criticality: critical
    labels: { team: payments }
    repositories:
      - url: .
        paths: [services/ledger]
```

`paths:` is a sparse checkout, so a scanner pointed at `storefront` sees that subtree and nothing
else. Three things follow.

**A finding says which component it belongs to**, so a report over one repository is still a report
about parts of it. **The band is the component's**, because `exposure` and `criticality` are
declared per component, so the same CVE is P1 in the public storefront and P3 in something
restricted. And **a flaw in one component is not attributed to another**, including where two
components ship the same vulnerable package, which is two findings with two owners rather than one.

**What it costs is analysis across the boundary.** A taint flow that starts in `services/storefront`
and ends in `libs/shared` is invisible to a scanner that was handed only the first, and nothing in
the output says so. That is the price of carving by ownership, and it is worth naming because no
tool that carves this way avoids it. A component that needs the whole tree analyzed together is one
component with a wider `paths:`.

## Give each team a pipeline that covers its own code

`--labels` selects components by what they are:

```bash
draugr scan draugr.saga.yaml --labels team=web
```

```console
DRAUGR  FAIL  draugr-demo 1.0  (scope: 1 of 3 components; sca)  2.818s

 P1 4 P2 4 P3 1 P4 0

CONTROLS
  sca  FAIL   P1 4 P2 4 P3 1

COMPONENTS
  storefront  FAIL   P1 4 P2 4 P3 1
  api         not scanned
  platform    not scanned
```

The team's pipeline is about the team's code, so its pull-request comment is too. Use a label rather
than `--components`: a team knows the label it files under, and a list of component names in a
pipeline file goes stale the first time somebody adds a component.

`--exposure` and `--criticality` select the same way over Draugr's own vocabulary, for the run that
is about a property rather than an owner:

```bash
draugr scan draugr.saga.yaml --exposure public --criticality critical
```

**A selector that matches nothing is an error.** A typo, or a label somebody moved, would otherwise
scan nothing and pass. See [the CLI reference](../reference/cli.md#scoping-a-run) for what the
messages say.

## Two scans of one commit do not erase each other

This is the failure worth knowing about before it happens, because nothing about it looks wrong.

GitHub code scanning replaces whatever it last received under the same tool and category. Two
pipelines uploading against one commit therefore keep only whichever finished last, and both runs
report success. A reader cannot tell a product with no findings from one whose findings were
deleted by the next job.

Draugr gives each run a category from the descriptor's `project:` and from what the run was narrowed
to:

| The run | The category |
|---|---|
| `project: acme`, all of it | `acme` |
| `--labels team=web`, which resolves to one component | `acme/components:storefront` |
| `--components api,web --controls sca` | `acme/components:api,web/controls:sca` |

So each team's pipeline, and each leg of a matrix, keeps its own alerts. [Publishing to code
scanning](code-scanning.md#two-products-in-one-repository) has the mechanics.

The same property makes a **partial scan safe**, which is the other half. A tool that uploads part
of a repository under one category resolves everything it did not look at as fixed, and a resolved
alert is a positive claim that somebody fixed something.

## Scanning the same tree repeatedly stays cheap

A job scoped with `paths:` is cached against the content of its own subtree rather than the
repository's commit, which matters here because a monorepo takes a commit every few minutes.

Measured on a two-component tree, twelve `sca` jobs:

| | hits | scans |
|---|---|---|
| a warm run, nothing changed | 12 | 0 |
| a commit touching one component | 9 | 3 |

The three that re-scan belong to the component that changed. See [caching and
performance](caching-and-performance.md#one-repository-several-components) for what keeps the
commit instead, which is a job that reads the repository's history and a repository Draugr clones
from a URL.

## Gate a pull request on what it introduced

A monorepo has a backlog. Gating on all of it blocks every merge, so the gate gets turned off within
a week and stops being a gate.

[Gating on new findings](pr-diff.md) is the answer and needs no monorepo-specific setup: the diff is
between two scans of the same descriptor, so a team scoped to its own components diffs its own
components. Scope the base scan the same way as the head scan, or the diff reports everything the
base covered and the head did not as fixed.

## Answer "whose is this" where there are many of them

Every finding carries its component's labels into `results.sarif`, so a platform holding many
components can narrow a list to the ones somebody is answerable for.

They are deliberately absent from the console, the Markdown report and pull-request comments. Those
answer what to fix, for a reader who already knows the work is theirs, and a column repeating the
same team on every row of their own pull request is noise. Filtering is a question asked where there
is a fleet.

## What this page does not solve

- **Analysis across a component boundary**, as above. Carving by ownership and analyzing the whole
  tree together are different requests.
- **A component nobody has classified.** An undeclared component reads as public and critical, which
  is the safe direction and not a useful one at scale. `draugr classify` asks the two questions per
  component.
- **Knowing which components exist.** Draugr scans what the descriptor declares. A subtree nobody
  wrote a component for is a subtree nobody scans, and `draugr doctor` reports surfaces the
  descriptor declares that no control examines rather than surfaces nobody declared.
