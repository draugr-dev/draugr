# Controller: `secrets` (Secret detection)

- **Industry term:** Secret detection
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`gitleaks`](../scanners/gitleaks.md)
- **Resource:** a component's `repositories:`

## Scope

**The working tree at the scanned revision.** Repositories are cloned shallow, so this control
reports secrets present in the code as it stands — which is the state that gets deployed, and the
one a pull request changes.

A credential that was committed and later removed stays in git history and stays exposed, so
removing it from the tip is not remediation: it needs rotating. That is true of every repository
regardless of what scans it, and it is worth a periodic sweep of full history with a
history-aware tool alongside whatever runs per-commit.

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
