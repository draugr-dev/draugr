# Scanner: `gosec` (Go static analysis)

- **Control:** [`sast`](../controllers/sast.md)
- **Tool:** **gosec** — https://github.com/securego/gosec
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`) — checked out via `internal/git`
- **License / terms:** **Apache-2.0** (permissive) — exec only, do not bundle or import.

## What it does

A **Go-specialized** static analyzer that complements the polyglot [Semgrep](semgrep.md) with
deeper Go-specific rules (AST/SSA). Checks out the component's repository and runs
`gosec -fmt sarif -no-fail ./...` **with the checkout as the working directory** (gosec loads
Go packages relative to the cwd, so the target is the relative `./...` pattern).

- `-no-fail` keeps the process successful when findings exist (findings live in the SARIF
  report, not the exit code; the [`sast`](../controllers/sast.md) controller judges severity).
- `-quiet` is deliberately **not** used: it suppresses all output on a clean scan, which would
  leave no SARIF to parse.

## Opt-in

gosec is Go-only, so it doesn't run by default. Select it per the `sast` control's scanner set:

```yaml
config:
  controllers:
    sast:
      enabled: true
      scanners: [semgrep, gosec]   # default: [semgrep]
```

The same key works as a per-component override. Only enable gosec for Go components — it errors
on repositories with no Go packages.

## Saga options

```yaml
controllers:
  sast:
    gosec:
      enabled: true
      exclude: [G104]        # rules that do not apply to this codebase
      tags: [integration]    # code behind a build tag gosec does not build, it does not analyse
```

| Option | What it does |
|---|---|
| `include` | Run only these rule IDs (`-include`). |
| `exclude` | Skip these rule IDs (`-exclude`). |
| `tags` | Go build tags to compile with (`-tags`). |

gosec's `-severity` and `-confidence` floors are deliberately not exposed. Both drop findings
inside the tool, where Draugr cannot mark them suppressed or record who accepted them. A finding
you have judged belongs in `config.exclude`, which keeps it in the report with your reason; what
should fail a build is the gate's decision. Selecting rules is a different statement — that a
check does not apply to this codebase at all.

## Notes

- Integration mode: **exec** over a local checkout; `gosec` + `git` must be on `PATH`
  (`draugr tools install gosec` provisions a pinned, SHA-256-verified copy).
- gosec signs its releases with a **key-based** cosign bundle; Draugr's identity-based signature
  verification (used for Trivy) doesn't cover that yet, so `tools install` verifies gosec by
  SHA-256 only for now.
