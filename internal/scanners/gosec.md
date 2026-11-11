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
deeper Go-specific rules (AST/SSA). Checks out the component's repository and runs gosec **once
per Go module**, for every directory holding a `go.mod` outside `vendor/` and `testdata/`. A module
below the root and a module nested inside another are each analyzed, and each finding is located
under its own module's directory. A tree with no `go.mod` is reported as analyzed by nothing, never
as clean.

gosec is given the directory of each package in the module, as `go list ./...` lists them with
gosec's build tags:

```
gosec -fmt sarif -no-fail -track-suppressions -concurrency 2 -out <file> -stdout -verbose json <package directory>…
```

That is every package the go command builds as part of the module, including one whose directory
name contains `vendor`, such as `vendorhash/`, and every package of a module in a directory
such as `vendor-api/`. These are not analyzed:

- the module's `vendor/` directory, a copy of other modules' code
- `testdata/` directories, and directories whose names start with `.` or `_`
- a module nested inside it, which has a run of its own
- a directory holding only `_test.go` files, and a file behind a build tag not in `tags`

gosec writes its SARIF report to a temporary file and the same findings as JSON to its output. The
JSON names each file by its full path, which Draugr uses to locate each SARIF finding under its
module.

Each module's run stands on its own:

- **A module with no Go package**, such as a documentation site built with Hugo that has its own
  `go.mod`, is one `go list` lists no package of, and gosec does not run over it. Its `go.mod` is an
  `unread-files` caveat with the reason `no Go packages`, and the findings from the other modules
  are kept. The control is not in error because of it.
- **A module whose run fails for any other reason** puts the control in error and the run is
  incomplete, with the module named in the error, as `run gosec over tools/go.mod: exit status 1: …`.
  The findings from the modules gosec did read are kept in the report beside the error.
- **A module the go command cannot load** puts the control in error with the go command's message:

  ```
  run gosec over go.mod: go list -e -deps ./... cannot load the module, so gosec did not run: exit status 1: go: go.mod requires go >= 1.99 (running go 1.26.10; GOTOOLCHAIN=local)
  ```

  Draugr runs that `go list` in the module, with gosec's environment and build tags, before gosec,
  because gosec skips a package it cannot load and exits 0. The findings from the other modules are
  kept. A problem inside one package, such as an import that does not resolve, does not stop the
  load, and gosec reports on the rest.
- **A module in a `go.work` workspace** is loaded as the workspace builds it, from a copy of the
  `go.work` outside the read-only checkout, so a repository that commits `go.work` without a
  complete `go.work.sum` is analyzed in full. A module the `go.work` does not list runs with
  `GOWORK=off`. [govulncheck](govulncheck.md) runs with the same environment and describes the
  copy, a vendored workspace, and a `GOWORK` you set yourself.

A component scoped by `paths` to part of a module shares an analysis of the whole module, and keeps
only the findings in its own files. [Scoping a
repository](../../docs/reference/saga-schema.md#scoping-a-repository) has the rule for shared code
no component names.

- `-no-fail` keeps the process successful when findings exist (findings live in the SARIF
  report, not the exit code; the [`sast`](../controllers/sast.md) controller judges severity).
- `-track-suppressions` keeps a `#nosec` result in the report, marked, carrying the text after
  the `--` as its justification. Without it gosec removes the result, and a finding somebody
  excluded reads as a finding nobody ever made.
- `-quiet` is deliberately **not** used: it suppresses all output on a clean scan, which would
  leave no SARIF to parse.
- `-concurrency 2` loads two packages at once, each building with `-p` at half of the
  [parallelism bound](../../docs/reference/cli.md#draugr-scan-sagayaml--dir) n, rounded down, so
  the compile processes of both loads together stay within n. Where n is 1, gosec loads one
  package at a time. A `-p` already in your `GOFLAGS` is kept.

## Severity

gosec rates each rule `HIGH`, `MEDIUM` or `LOW`, and a finding's severity is that rating: high,
medium or low. gosec writes SARIF level `error` for `HIGH` and `MEDIUM` rules alike and records the rating as
a tag on the rule, so Draugr reads the tag rather than the level. A rule without a rating tag keeps
the level gosec wrote.

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

gosec is Go-only, so it doesn't run by default. Enable it under the `sast` control, where it runs
beside Semgrep:

```yaml
config:
  controls:
    sast:
      enabled: true
      gosec:
        enabled: true
```

The same key works as a per-component override. Only enable gosec for Go components: a repository
whose every module holds no Go package is a caveat for each `go.mod` and nothing analyzed.

## Saga options

```yaml
config:
  controls:
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
- gosec loads a module's packages with `go`, so Go must be on `PATH` too. Without it gosec exits 0
  having analyzed nothing, and the scan fails the control with ``gosec needs Go, and no `go` is on
  PATH`` rather than reporting the module clean. A tree holding no module runs nothing and needs no
  Go.
- gosec and govulncheck take turns loading Go packages across the whole run, so this scanner's
  job can wait for another load to end; the wait is in `stats.orderWaitsMs`.
- gosec signs its releases with a **key-based** cosign bundle; Draugr's identity-based signature
  verification (used for Trivy) doesn't cover that yet, so `tools install` verifies gosec by
  SHA-256 only for now.

## Data

Nothing. gosec's rules are compiled into its binary.
