# Controller: `sast` (Static Application Security Testing)

- **Industry term:** Static Application Security Testing
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`semgrep`](../scanners/semgrep.md)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and analyzed for
security bugs in the project's **own source code** — not its dependencies), then aggregates +
deduplicates findings into a per-control result with a severity summary.

Semgrep reports per-rule severity, so findings are counted as reported (unlike `secrets`,
which escalates everything to error).

## Links

- Glossary: [SAST](../../docs/glossary.md#sast--static-application-security-testing)
- Saga reference: [`docs/saga-reference.md`](../../docs/saga-reference.md)

## Notes

- Distinct from [`sca`](sca.md) (third-party dependencies) and `images` (built containers) —
  `sast` analyzes first-party source.
- Ruleset is `--config auto` today; per-component custom rules are a natural follow-up.
