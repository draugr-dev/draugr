# Controller: `sast` (Static Application Security Testing)

- **Industry term:** Static Application Security Testing
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`semgrep`](../scanners/semgrep.md) (default), [`gosec`](../scanners/gosec.md)
  (opt-in, Go-only)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository × selected scanner (each repo is checked out and analyzed for
security bugs in the project's **own source code** — not its dependencies), then aggregates +
deduplicates findings into a per-control result with a severity summary.

The scanner set is chosen with `controllers.sast.scanners` (default `[semgrep]`); a Go
component can opt into gosec alongside Semgrep with `scanners: [semgrep, gosec]`.

The SAST scanners report per-rule severity, so findings are counted as reported (unlike
`secrets`, which escalates everything to error).

## Links

- Glossary: [SAST](../../docs/glossary.md#sast--static-application-security-testing)
- Saga reference: [`docs/saga-reference.md`](../../docs/saga-reference.md)

## Notes

- Distinct from [`sca`](sca.md) (third-party dependencies) and `images` (built containers) —
  `sast` analyzes first-party source.
- Semgrep's ruleset is `--config p/default` today (see [`semgrep.md`](../scanners/semgrep.md));
  per-component custom rules are a natural follow-up.
