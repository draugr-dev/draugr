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
`semgrep scan --sarif --quiet --no-error --metrics=off --config p/default <dir>` to analyze
the project's **own source code** for security bugs (injection, unsafe APIs, etc.). See the
[SAST glossary entry](../../docs/reference/glossary.md#sast-static-application-security-testing).

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
- Semgrep's SARIF puts each finding's severity in the **rule's** `defaultConfiguration.level`
  (not on the result). Draugr's SARIF parser resolves a result's level from its rule, so
  ERROR/WARNING/INFO map through to error/warning/note correctly.
- **A `config` path on disk resolves against the directory Draugr runs in** and reaches Semgrep as
  an absolute path, so it names the same file for every repository, including one scoped by
  `paths`.
- **Rules on disk are reported under the id their file declares.** With `config` set to a rules
  file or directory, Semgrep prefixes each rule id with the directory it loaded the rule from, so
  `no-eval` in `/home/alice/rules/x.yaml` arrives as `home.alice.rules.no-eval`. Draugr removes the
  part that comes from the configured path, and the rule is `no-eval` on every machine. A rule in a
  subdirectory of a configured directory keeps the subdirectory (`nested.no-eval`). Exclusions and
  `draugr diff` match on this id.

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
