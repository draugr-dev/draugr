# Controller: `sca` (Software Composition Analysis)

- **Industry term:** Software Composition Analysis
- **Scope:** component
- **Status:** ✅ implemented (dependency vulnerabilities)
- **Scanners:** [`trivy-fs`](../scanners/trivy-fs.md) (license findings planned — [#120](https://github.com/draugr-dev/draugr/issues/120))
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for
dependency vulnerabilities), then aggregates + deduplicates findings into a per-control
result with a severity summary.

## Links

- Glossary: [SCA](../../docs/reference/glossary.md#sca--software-composition-analysis)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Dependency **vulnerabilities** today; **license** findings are a follow-up ([#120](https://github.com/draugr-dev/draugr/issues/120)).
