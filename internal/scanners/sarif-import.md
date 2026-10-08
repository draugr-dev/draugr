---
title: "sarif-import"
description: "Reads a SARIF file another tool wrote into one of Draugr's controls, so its findings are ranked and gated with the rest."
section: Scanners
order: 90
---

# Scanner: `sarif-import` (reads a SARIF file another tool wrote)

- **Control:** the control each import names in [`components[].imports`](../../docs/reference/saga-schema.md#componentsimports)
- **Tool:** none. Draugr reads a file; the tool that wrote it ran somewhere else.
- **Target:** file (a SARIF 2.1.0 log)
- **Effects:** none
- **Status:** ✅ implemented

## What it does

Reads a SARIF file a component imports and adds its findings to the control the descriptor names,
as though one of that control's scanners had produced them. Each finding then takes the component's
exposure and criticality into its priority, counts toward the gate, and appears in the fix list and
every report beside the findings Draugr's own scanners made.

The file is read as SARIF 2.1.0:

- **Severity** comes from each result's numeric `security-severity` property, the convention GitHub
  code scanning reads, inherited from its rule where the result has none. A result without one
  falls back to its `level`, mapped as every other SARIF level is: `error` to high, `warning` to
  medium, `note` to low.
- **Package and fix** come through only where the file carries them in the properties Draugr reads.
  Without them a finding becomes a "Fix <rule>" action rather than an upgrade.
- **The tool** is the file's own `tool.driver`, so a finding says which product found it.

## What the report says about the file

Draugr did not run the tool, so the report states what it knows about the file instead, under
**Measured against** and in `results.sarif`:

| Field | Value |
|---|---|
| `tool` | the tool's name and version, as the file states them |
| `file` | the path the descriptor gave |
| `written` | when the file says its run ended (`invocations[].endTimeUtc`), or else the file's modification time |
| `severity` | where severities came from: `security-severity`, `SARIF level`, or a count of each |
| `commit` | the commit the file was checked against, or `not stated` |
| `component` | the component that imports it |
| `sha256` | the file's content, so a run can be checked against the file it read |

## Commit

A file left from an old run reads exactly like a current scan. Where the file names the commit it
scanned, in `runs[].versionControlProvenance`, Draugr holds it to the commit this run reads:

- **The same commit:** the file is read, and `commit` names it.
- **A different commit:** the run stops with an error naming both. Run the tool again on this
  commit, or remove the import.
- **No commit stated:** the file is read and listed under **Caveats** as `unbound`.
  [`config.gate.failOnCaveats: [unbound-imports]`](../../docs/reference/saga-schema.md#configgate)
  makes that fail the run.

A component with one repository is held to it whatever address the file gives, because a tool
records the remote it saw and the descriptor may name the same repository by a local path. With
several, the address has to name one of them.

## Errors

A file that is missing, unreadable, empty, not SARIF, a SARIF version other than 2.1.0, or a log
with no runs stops the run as a scanner that could not run does, and `--allow-scan-errors` accepts
it. A valid file with no results is a clean result.

## License & terms

No third-party tool is executed or bundled, so the scanner carries only Draugr's own license. The
file is the reader's; its tool's terms governed whoever produced it, before Draugr read it.

## Data

Nothing. The scan reads the file the descriptor names, on the machine running Draugr, and resolves
the component's repository revision with `git`, locally for a path and with `git ls-remote` for a
remote.
