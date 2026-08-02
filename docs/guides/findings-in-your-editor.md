---
title: See findings in your editor
description: Open a Draugr scan as inline diagnostics in VS Code or JetBrains, and jump from the terminal to the offending line.
section: Guides
order: 35
---

# See findings in your editor

A finding you have to go looking for is a finding you fix later. Draugr writes standard
**SARIF 2.1.0**, which every major editor can read, so a scan can land as squiggles on the
lines that caused it — no Draugr-specific extension required.

There are three places a finding can reach you. Pick whichever matches where you work:

| Where | What you get | What it needs |
| --- | --- | --- |
| **Your editor** | Inline squiggles, a Problems list, click-to-line | `results.sarif` + a SARIF viewer extension |
| **A pull request** | Annotations on the diff, in the Security tab | The [`github` publisher](code-scanning.md) |
| **Your terminal** | `path:line` you can click, a linked rule id | Nothing — it's the default output |

## Produce the SARIF

```bash
draugr scan draugr.saga.yaml -o .draugr-out
```

That writes `.draugr-out/report.json` and `.draugr-out/results.sarif`. Add `.draugr-out/` to
your `.gitignore` — it's build output, not source.

If you only want the SARIF, ask for that one format:

```bash
draugr scan draugr.saga.yaml --format sarif > results.sarif
```

## VS Code

Install Microsoft's **[SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)**
extension, then open `results.sarif`. Findings appear in the Problems panel and as inline
markers on the offending lines; selecting one jumps to the file and line.

Draugr emits the metadata the viewer needs to do this well:

- Paths are **repo-relative**, and the run declares `%SRCROOT%` as their base, so the viewer
  resolves them against your open workspace instead of asking you to locate each file.
- Each rule carries the scanner's own **description, remediation help and documentation link**,
  so a rule id like `DS-0002` is one click from what it actually means.
- Each finding keeps its **priority** (P1–P4) and numeric severity in its property bag.

## JetBrains (IntelliJ, GoLand, PyCharm)

JetBrains IDEs read SARIF through the **Qodana** plugin: install it, then
*Tools → Qodana → Open SARIF report* and pick `results.sarif`. Findings land in the Problems
tool window with the same click-to-line behaviour.

## Neovim and other editors

Any tool that speaks SARIF will work. `results.sarif` is plain JSON with no Draugr-specific
extensions, so a quickfix-list converter is a short script — the fields you want are
`runs[].results[].locations[].physicalLocation` and `ruleId`.

## From the terminal

The `Location` column in the console's ranked findings table prints `path:line`. VS Code's integrated
terminal, JetBrains' terminal and most modern terminal emulators detect that pattern and make
it clickable, opening the file at the line — provided you run `draugr` from the repository root,
since the paths are relative to it.

The rule id in the same table is a **hyperlink** to the rule's documentation wherever the
scanner published one (and to NVD or GitHub Advisories for `CVE-`/`GHSA-` ids). Terminals
without hyperlink support show the id as ordinary text, so nothing is lost.

## One flag to avoid here

`draugr scan --compact` strips rule descriptions and remediation text from the SARIF to save
bytes for scripts and agents. Those are exactly the fields a viewer shows you beside a finding,
so leave it off when producing SARIF for your editor. See
[compact output](reports-and-publishers.md#compact-output-for-tools-and-agents).

## A caveat worth knowing

Repository scans run against a **clean checkout of the committed revision**, not your working
tree — a local path is cloned just like a URL. Line numbers therefore match what's committed. If
you have uncommitted edits above a finding, its marker will sit a few lines off; if the edits
*are* the thing you wanted scanned, they aren't in the report at all. Draugr warns when it scans
a repository with uncommitted changes. Commit, then re-scan. See
[URLs and paths](../reference/saga-schema.md#where-a-repository-comes-from-urls-and-paths).

## Related

- [Publish to GitHub code scanning](code-scanning.md) — the same findings, annotated on a PR diff.
- [Reports & publishers](reports-and-publishers.md) — every output format and where it can go.
- [Editor support for the Saga schema](../reference/saga-schema.md) — autocomplete and validation
  while you write the descriptor itself.
- [Prioritization](../concepts/prioritization.md) — what P1–P4 mean on each finding.
- [Use Draugr from an AI coding assistant](ai-agents-mcp.md) — the same answers, via MCP.
