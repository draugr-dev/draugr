# Controller: `iac` (Infrastructure as Code)

- **Industry term:** IaC / misconfiguration scanning
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`trivy-config`](../scanners/trivy-config.md)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for insecure
Infrastructure as Code, Terraform, Kubernetes manifests, Dockerfiles, Helm, …), then aggregates +
deduplicates findings into a per-control result with a severity summary.

Trivy reports per-check severity, so findings are counted as reported.

With `trivyConfig.checks` set and `namespaces` unset, the control derives the namespaces from the
checks' `package` lines when it plans, and `draugr validate` refuses a check it cannot derive one
from. [`trivy-config`](../scanners/trivy-config.md) has the rules.

## Unread

A Terraform file is **unread** when it calls a module `trivy-config` could not load. The resources
that module defines were not checked, and the report lists the calling file under **Caveats** as
`unread`, with the module names as the reason:

```
CAVEATS  do not fail the run
  Component  What                Caveat  Why
  infra      infra/mod/main.tf   unread  module "sg" not loaded (iac)
  infra      infra/prod/main.tf  unread  modules "vpc", "eks" not loaded (iac)
```

A module whose `source` is a local path loads when the path is in the checkout. A module from a
registry or a git host loads only when Trivy can download it, which `--offline` prevents; see
[`trivy-config`](../scanners/trivy-config.md#data). Vendor the module into the repository, or let
the run reach its host.

`report.json` carries every unread file under `dependencyFiles`, see the
[report schema](../../docs/reference/report-schema.md).

## Links

- Glossary: [IaC scanning](../../docs/reference/glossary.md#iac-scanning-infrastructure-as-code)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Distinct from [`images`](images.md) (vulns in a built container), `iac` finds insecure
  *definitions* before anything is deployed.
