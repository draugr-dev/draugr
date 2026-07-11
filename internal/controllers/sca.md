# Controller: `sca` (Software Composition Analysis)

- **Industry term:** Software Composition Analysis
- **Scope:** component
- **Status:** ✅ implemented (dependency vulnerabilities)
- **Scanners:** [`trivy-fs`](../scanners/trivy-fs.md) (OSV-Scanner planned — #49)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for
dependency vulnerabilities), then aggregates + deduplicates findings into a per-control
result with a severity summary.

## Links

- Glossary: [SCA](../../docs/glossary.md#sca--software-composition-analysis)
- Saga reference: [`docs/saga-reference.md`](../../docs/saga-reference.md)

## Notes

- Dependency **vulnerabilities** today; **license** findings are a follow-up (#49).
