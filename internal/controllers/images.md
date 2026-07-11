# Controller: `images` (container image scanning)

- **Industry term:** Container image scanning
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`trivy`](../scanners/trivy.md)
- **Resource:** a component's `images:`

## What it does

Plans one scan per image declared on a component, runs the image scanner(s), and
aggregates + deduplicates findings into a per-control result with a severity summary.

## Links

- Glossary: [Container image scanning](../../docs/glossary.md#container-image-scanning)
- Saga reference: [`docs/saga-reference.md`](../../docs/saga-reference.md)
