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

Semgrep runs by default. Each scanner is configured under its own key in
`controllers.sast.<scanner>`, with an optional `enabled` flag plus that scanner's options; a Go
component opts into gosec alongside Semgrep with `controllers.sast.gosec.enabled: true`. Point
Semgrep at your own ruleset with `controllers.sast.semgrep.config` (a registry ref such as
`p/owasp-top-ten` or a path/URL to a rules file; defaults to `p/default`).

The SAST scanners report per-rule severity, so findings are counted as reported (unlike
`secrets`, which escalates everything to error).

## Links

- Glossary: [SAST](../../docs/reference/glossary.md#sast--static-application-security-testing)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Distinct from [`sca`](sca.md) (third-party dependencies) and `images` (built containers) —
  `sast` analyzes first-party source.
- Semgrep's ruleset is `--config p/default` today (see [`semgrep.md`](../scanners/semgrep.md));
  per-component custom rules are a natural follow-up.
