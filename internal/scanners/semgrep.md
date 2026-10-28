---
title: "semgrep"
description: "Polyglot static analysis with no build step. The default for the sast control."
section: Scanners
order: 150
---

# Scanner: `semgrep` (static analysis)

- **Control:** [`sast`](../controllers/sast.md)
- **Tool:** **Semgrep**, https://semgrep.dev (repo https://github.com/semgrep/semgrep)
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`), checked out at the scanned revision
- **License / terms:** **LGPL-2.1** (copyleft). **exec only, do not bundle or import**.
  Semgrep Pro and some registry rules are separate/commercial; Draugr uses the OSS CLI with
  OSS/user-provided rules.

## What it does

Checks out the component's repository, then runs
`semgrep scan --sarif --json-output <file> --verbose --max-target-bytes 1000000 --timeout-threshold 3 --no-error --metrics=off --config p/default <dir>`
to analyze the project's **own source code** for security bugs (injection, unsafe APIs, etc.). See
the [SAST glossary entry](../../docs/reference/glossary.md#sast-static-application-security-testing).

- `--json-output` writes the same results as JSON to a temporary file, which Draugr reads for the
  rule metadata the SARIF leaves out (see [Severity](#severity)) and then removes. It needs
  Semgrep 1.70.0 or later; an earlier Semgrep refuses the option and the scan reports the error.
- `--verbose` makes the JSON report list the files Semgrep skipped, with the reason, which it
  leaves out otherwise. Draugr reads the list for [unread files](#unread).
- `--max-target-bytes 1000000` and `--timeout-threshold 3` are Semgrep's defaults, passed so the
  reason an unread file is given states the limits the run applied.
- `--no-error` keeps the process successful when findings exist (findings live in the SARIF
  report, not the exit code; the [`sast`](../controllers/sast.md) controller judges severity).
- `--metrics=off` avoids sending scan telemetry to the Semgrep registry.
- `--config p/default` is the OSS default rule pack. Semgrep's `auto` config is not used: it
  refuses to run with metrics disabled.

## Links

- CLI reference: https://docs.semgrep.dev/cli-reference
- Rule registry: https://semgrep.dev/r

## Notes

- Integration mode: **exec** over a local checkout; Semgrep + `git` must be on `PATH`.
- Semgrep's SARIF puts each finding's level in the **rule's** `defaultConfiguration.level`
  (not on the result). Draugr's SARIF parser resolves a result's level from its rule, so
  ERROR/WARNING/INFO map through to error/warning/note correctly. The severity comes from the
  rule's rating where it states one (see [Severity](#severity)).
- **A `config` path on disk resolves against the directory Draugr runs in** and reaches Semgrep as
  an absolute path, so it names the same file for every repository, including one scoped by
  `paths`.
- **Rules on disk are reported under the id their file declares.** With `config` set to a rules
  file or directory, Semgrep prefixes each rule id with the directory it loaded the rule from, so
  `no-eval` in `/home/alice/rules/x.yaml` arrives as `home.alice.rules.no-eval`. Draugr removes the
  part that comes from the configured path, and the rule is `no-eval` on every machine. A rule in a
  subdirectory of a configured directory keeps the subdirectory (`nested.no-eval`). Exclusions and
  `draugr diff` match on this id.

## Unread

Semgrep finishes with exit 0 and reports findings only from the files it checked. Draugr reads two
gaps from the JSON report and lists each file as an `unread-files` caveat on the
[`sast`](../controllers/sast.md#unread) control:

- **A file over 1 MB**, which Semgrep lists under `paths.skipped` with the reason
  `exceeded_size_limit` and does not scan: `over 1 MB, not scanned`. Semgrep applies the limit
  before it matches files to rule languages, so Draugr lists the file only where a configured rule
  reads its language, by extension, file name or `#!` line. A ruleset Semgrep fetches cannot be
  read beforehand and is taken to read every file; `p/default` holds `regex` and `generic` rules,
  which do.
- **A rule that timed out on a file**, an entry in `errors` of type `Timeout`: `1 rule timed out:
  "x"`. When three rules time out on one file, Semgrep runs no further rule on it, and the reason
  ends `rest not run`.

A file Semgrep was told to skip, by `.semgrepignore`, `.gitignore` or a component's `ignore:`, is
not listed.

## Severity

A result's severity comes from its rule's `impact` and `likelihood`, each `LOW`, `MEDIUM` or
`HIGH`, by the table below. Semgrep publishes both in the rule's metadata, with a `confidence` and a
`subcategory` of `vuln`, `audit` or `secure default`. Its SARIF keeps only the confidence, as a tag,
and gives most of the default pack the level `error` or `warning` whatever the rule finds, so Draugr
reads the metadata from the JSON report the same run writes.

| impact \ likelihood | `LOW` | `MEDIUM` | `HIGH` |
|---|---|---|---|
| `HIGH` | medium | high | critical |
| `MEDIUM` | low | medium | high |
| `LOW` | low | low | medium |

- **One band lower**, never below low, for a rule with confidence `LOW` or subcategory `audit`, and
  one band where it is both. Semgrep defines a `LOW` confidence rule as one that expects a fair
  amount of false positives, and an audit rule as one for code auditors.
- **No change** for confidence `MEDIUM` or `HIGH`, or subcategory `vuln` or `secure default`.
- **The level** for a rule that does not state both impact and likelihood, which a rule written by
  hand usually does not, with `error` as high, `warning` as medium and `note` as low.

The cells are the overall-severity table of the
[OWASP Risk Rating Methodology](https://community.owasp.org/OWASP_Risk_Rating_Methodology), with
its lowest cell, Note, read as low. Semgrep says a registry rule's severity is assigned from its
likelihood and impact, and publishes no table for the combination.

The report prints the rating on the finding's evidence line, `impact high · likelihood high`, with
`confidence low` or `subcategory audit` added where either applies, so a line without them is the
table's cell. `results.sarif` keeps the level Semgrep wrote and adds the result property
`draugr/rating`, which holds the severity, that line, and each of the four fields the rule states,
with Semgrep's value.

A result a `nosemgrep` comment suppressed has no entry in the JSON report, so it takes the rating of
another result of the same rule, and keeps its level where there is none.

## Data

The **rule pack**, from `semgrep.dev`. `p/default` is resolved on **every** invocation: there is
no local cache to warm, so a run contacts the registry once per job rather than once, and a
machine with no network cannot run this scanner on the default pack.

`--config` against rules on disk is the way to run it without the registry.

Under `--offline`, Semgrep does not run on a ruleset it would fetch, and the `sast` control reports
an error naming the setting:

```
  sast  ERROR  did not run
        semgrep: cannot run offline: config.controls.sast.semgrep.config is unset, and Semgrep fetches
          its default, p/default, from semgrep.dev; set it to a rules file or directory on disk
```

Semgrep fetches the ruleset when `config` is unset, a registry id (`p/…`, `r/…`, `s/…`), `auto`, a
product name such as `code`, or a URL. A rules file or directory on disk runs as normal.
