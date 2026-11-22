---
title: Check each commit with pre-commit
description: Run Draugr as a pre-commit hook that fails a commit adding a finding HEAD does not have, leaked credentials by default.
section: Guides
order: 31
---

# Check each commit with pre-commit

The `draugr` hook for [pre-commit](https://pre-commit.com) fails a commit that adds a security
finding the last commit does not have. A commit that only carries findings already in the
repository passes, so the hook can go into a repository with a backlog on the first day. By default
it checks for leaked credentials, with Gitleaks.

## Before you start

- Install Draugr and put it on your `PATH`, as in [Install](../getting-started/install.md). The hook
  runs the `draugr` it finds there and installs nothing.
- Install Gitleaks, the scanner behind the `secrets` control:

  ```bash
  draugr tools install gitleaks
  ```

- Install pre-commit 3.2.0 or later.

## Add the hook

In `.pre-commit-config.yaml` at the root of your repository:

```yaml
repos:
  - repo: https://github.com/draugr-dev/draugr
    rev: v0.187.0
    hooks:
      - id: draugr
```

Then install the Git hook:

```bash
pre-commit install
```

`rev` picks the version of the hook definition, not of Draugr: the scan is run by the `draugr` on
your `PATH`. `pre-commit autoupdate` moves `rev` to the newest release.

## What a commit sees

The hook runs two scans, the same two you could run by hand:

```bash
draugr scan --controls secrets --no-publish --no-gate -o "$base"
draugr scan --controls secrets --no-publish --working-tree --base "$base/results.sarif" --fail-on-new P4
```

The first scans `HEAD`, the commit yours will follow, into a temporary directory the hook removes
afterwards. The second scans the files on disk and compares them with the first. Any finding the
second reports and the first does not is new, and a new finding at `P4` or above, which takes in
every band, fails the commit. A credential in a commit stays in the history after the file is
fixed, and has to be rotated, so the hook stops all of them.

A commit that adds a Stripe key to `billing.py`, in a repository whose `legacy.py` already holds
one, fails on the new key alone:

```console
DRAUGR  FAIL  repo  681ms

 new        1 P1 0 P2 0 P3 0 P4
 unchanged  1 P1 0 P2 0 P3 0 P4
 whole run  2 P1 0 P2 0 P3 0 P4
 Change since bcd5329 · 1 new · fails on P4
 Scoped to the secrets control.

MEASURED AGAINST
  secrets  gitleaks 8.30.1 · workingTree: true

CHANGED  1, by priority
  Change  Priority  Severity  Rule                 Scanner   Location
  + new   P1        high      stripe-access-token  gitleaks  billing.py:1
          stripe-access-token has detected secret for file billing.py.

TRY
  --view compact                     one line each, to see how much there is
  --view actions                     the same findings as a list of things to do
  config.exclude                     set aside; findings stay, suppressed
    - rules: [<full rule id>]
      paths: [<file without :line>]
      reason: <why it is set aside>
      expires: <YYYY-MM-DD>
  draugr explain <rule>              what a rule means and how to fix it, from .draugr/out
draugr: fails on P4: 1 new finding since bcd5329
```

With `billing.py` taken out of the commit, the same repository passes, and the key in `legacy.py`
is counted as unchanged:

```console
DRAUGR  PASS  repo  677ms

 unchanged  1 P1 0 P2 0 P3 0 P4
 whole run  1 P1 0 P2 0 P3 0 P4
 Change since bcd5329 · nothing new · fails on P4
 Scoped to the secrets control.

MEASURED AGAINST
  secrets  gitleaks 8.30.1 · workingTree: true
```

On Draugr's own repository, about 2,600 files, the two scans take under four seconds together,
the scan of `HEAD` a little over half of it.

pre-commit sets aside changes you have not staged before the hook runs, so a tracked file is scanned
as you are committing it. It leaves untracked files where they are, and Draugr reads every untracked
file Git does not ignore, so a credential in a file you have not added fails the commit too. Add the
file to `.gitignore`, or delete it.

In a repository with no commits yet, the scan of `HEAD` finds nothing, and every finding in the
first commit is new.

## Choose the descriptor, the controls and the gate

The hook reads the descriptor (`*.saga.yaml`) in the root of the repository when there is one, and
otherwise scans the repository as `draugr scan` does with no descriptor. `args` replaces the hook's
arguments, and they reach both scans, so name everything you want:

```yaml
      - id: draugr
        args: [.draugr/app.saga.yaml, --controls, "secrets,sast"]
```

- **The descriptor.** A path as the first argument. Every repository it declares has to be a local
  path, because `--working-tree` reads files on disk and a remote repository has none.
- **The controls.** `--controls` takes a comma-separated list. Leave it out to run every control
  the descriptor enables, which costs what a full scan costs, twice, on every commit.
- **The gate.** `--fail-on-new` with a band (`P1`–`P4`) or a severity (`critical`, `high`,
  `medium`, `low`) replaces the hook's `P4`. The hook sets the gate on the command line, so it
  replaces `config.gate.failOnNew` from the descriptor; repeat the descriptor's value here to keep
  it.

## When a finding does not apply

A finding that is a test fixture or an example is set aside in the descriptor with
[`config.exclude`](../reference/saga-schema.md#configexclude), as the `TRY` lines show, so the
decision and its reason are reviewed with the code. A repository without a descriptor gets one from
`draugr init`.

pre-commit's own `SKIP` variable skips the hook for one commit, `SKIP=draugr git commit`, and
nothing records why.

See [gate pull requests on new findings](pr-diff.md) for the same comparison on a pull request, and
[gating on new findings](../reference/cli.md#gating-on-new-findings) for the flags.
