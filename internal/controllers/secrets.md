# Controller: `secrets` (Secret detection)

- **Industry term:** Secret detection
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`gitleaks`](../scanners/gitleaks.md)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for
leaked credentials), then aggregates + deduplicates findings into a per-control result.

**Every finding is escalated to `error` severity.** A leaked secret should fail the gate
regardless of how the scanner rated it, so the controller normalizes severity rather than
trusting the scanner's own level (Gitleaks, in fact, emits none).

## Links

- Glossary: [Secret detection](../../docs/reference/glossary.md#secret-detection)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Working-tree scan today. Full **git-history** scanning (`gitleaks git`) is a natural
  follow-up.
