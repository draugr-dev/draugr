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
`unread-files`, with the module names as the reason:

```
CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  Component  What                Caveat        Why
  infra      infra/mod/main.tf   unread-files  module "sg" not loaded (iac)
  infra      infra/prod/main.tf  unread-files  modules "vpc", "eks" not loaded (iac)
```

A module whose `source` is a local path loads when the path is in the checkout. A module from a
registry or a git host loads only when Trivy can download it, which `--offline` prevents; see
[`trivy-config`](../scanners/trivy-config.md#data). Vendor the module into the repository, or let
the run reach its host.

A Terraform root module whose module calls Trivy did not all evaluate gets an `unread-files`
caveat on its directory, with how many calls it makes and how many were checked. The resources in
the skipped calls are not checked:

```
CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  Component  What   Caveat        Why
  infra      infra  unread-files  32 of 33 module calls checked; "zbad" skipped (iac)
```

Split the root module, or group its calls into fewer modules. To fail the run on the caveat, set
`config.gate.failOnCaveats: [unread-files]`, or pass `--fail-on-caveats unread-files` for one run.
[`trivy-config`](../scanners/trivy-config.md#what-it-does) has how Trivy evaluates module calls.

`report.json` carries every unread file under `dependencyFiles`, see the
[report schema](../../docs/reference/report-schema.md).

## Links

- Glossary: [IaC scanning](../../docs/reference/glossary.md#iac-scanning-infrastructure-as-code)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Distinct from [`images`](images.md) (vulns in a built container), `iac` finds insecure
  *definitions* before anything is deployed.
