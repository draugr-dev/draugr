---
title: "gosec"
description: "Go-specialized static analysis, type-aware and deep on Go idioms. Opt-in alongside Semgrep."
section: Scanners
order: 50
---

# Scanner: `gosec` (Go static analysis)

- **Control:** [`sast`](../controllers/sast.md)
- **Tool:** **gosec**, https://github.com/securego/gosec
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`), checked out at the scanned revision
- **License / terms:** **Apache-2.0** (permissive). Exec only, do not bundle or import.

## What it does

A **Go-specialized** static analyzer that complements the polyglot [Semgrep](semgrep.md) with
deeper Go-specific rules (AST/SSA). Checks out the component's repository and runs
`gosec -fmt sarif -no-fail -track-suppressions <module>/...` **once per Go module**, for every
directory holding a `go.mod` outside `vendor/` and `testdata/`. A module below the root and a
module nested inside another are each analyzed, and each finding is located under its own
module's directory. A tree with no `go.mod` is reported as analyzed by nothing, never as clean.

- `-no-fail` keeps the process successful when findings exist (findings live in the SARIF
  report, not the exit code; the [`sast`](../controllers/sast.md) controller judges severity).
- `-track-suppressions` keeps a `#nosec` result in the report, marked, carrying the text after
  the `--` as its justification. Without it gosec removes the result, and a finding somebody
  excluded reads as a finding nobody ever made.
- `-quiet` is deliberately **not** used: it suppresses all output on a clean scan, which would
  leave no SARIF to parse.

## What a `#nosec` becomes

gosec reports it as a SARIF suppression of kind `inSource`, which Draugr keeps and marks with
[`origin: tool`](../../docs/reference/saga-schema.md#configexclude). It is the weakest of the three
origins and counted apart from them: a comment beside the line was written by whoever was editing
the file, and nothing about it went past a second person.

```go
/* #nosec G204 -- the name is a constant in this program, reviewed 2026-09-22 */
_ = exec.Command("sh", "-c", name)
```

## Opt-in

gosec is Go-only, so it doesn't run by default. Select it per the `sast` control's scanner set:

```yaml
config:
  controllers:
    sast:
      enabled: true
      scanners: [semgrep, gosec]   # default: [semgrep]
```

The same key works as a per-component override. Only enable gosec for Go components. It errors
on repositories with no Go packages.

## Saga options

```yaml
controllers:
  sast:
    gosec:
      enabled: true
      exclude: [G104]        # rules that do not apply to this codebase
      tags: [integration]    # code behind a build tag gosec does not build, it does not analyze
```

| Option | What it does |
|---|---|
| `include` | Run only these rule IDs (`-include`). |
| `exclude` | Skip these rule IDs (`-exclude`). |
| `tags` | Go build tags to compile with (`-tags`). |

gosec's `-severity` and `-confidence` floors are deliberately not exposed. Both drop findings
inside the tool, where Draugr cannot mark them suppressed or record who accepted them. A finding
you have judged belongs in `config.exclude`, which keeps it in the report with your reason; what
should fail a build is the gate's decision. Selecting rules is a different statement. That a
check does not apply to this codebase at all.

## Notes

- Integration mode: **exec** over a local checkout; `gosec` + `git` must be on `PATH`
  (`draugr tools install gosec` provisions a pinned, SHA-256-verified copy).
- gosec signs its releases with a **key-based** cosign bundle; Draugr's identity-based signature
  verification (used for Trivy) doesn't cover that yet, so `tools install` verifies gosec by
  SHA-256 only for now.

## Data

Nothing. gosec's rules are compiled into its binary.
