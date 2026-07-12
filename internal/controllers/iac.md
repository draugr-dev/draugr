# Controller: `iac` (Infrastructure as Code)

- **Industry term:** IaC / misconfiguration scanning
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`trivy-config`](../scanners/trivy-config.md) (Checkov optional — [#52](https://github.com/draugr-dev/draugr/issues/52))
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for
insecure Infrastructure as Code — Terraform, Kubernetes manifests, Dockerfiles, Helm, …),
then aggregates + deduplicates findings into a per-control result with a severity summary.

Trivy reports per-check severity, so findings are counted as reported.

## Links

- Glossary: [IaC scanning](../../docs/glossary.md#iac-scanning--infrastructure-as-code)
- Saga reference: [`docs/saga-reference.md`](../../docs/saga-reference.md)

## Notes

- Distinct from [`images`](images.md) (vulns in a built container) — `iac` finds insecure
  *definitions* before anything is deployed.
