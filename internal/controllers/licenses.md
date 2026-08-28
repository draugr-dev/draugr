# Controller: `licenses` (dependency license compliance)

- **Industry term:** license compliance / open-source license risk
- **Scope:** component
- **Status:** ✅ implemented (0.43.0)
- **Scanners:** [`trivy-license`](../scanners/trivy-license.md)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository declared on a component, then aggregates the findings. Reports
the licenses in the dependency tree that carry an **obligation** — copyleft, forbidden, and
unidentified — and stays quiet about the rest.

Permissive licenses are **inventory, not findings**. Every dependency has a license, so listing
them all buries the handful that matter under dozens that don't; on Draugr's own repository that
is the difference between 77 rows saying "MIT is fine" and none. The inventory question is what
[`config.sbom`](../../docs/reference/saga-schema.md) answers, with a license per package.

## Why it isn't part of `sca`

Both read the dependency tree, so folding this into [`sca`](sca.md) would be the obvious move.
It's the wrong one:

- **License risk is not a vulnerability.** The exposure is legal and commercial — a blocked
  acquisition, a customer's legal review — not a breach.
- **A different team owns the policy**, and it changes on a different cadence.
- **It needs its own threshold.** `config.gate.controls` can hold `licenses: error` while
  vulnerabilities stay at `warning`. *"Fail on a forbidden license but only warn on a medium
  CVE"* is a coherent position that one shared threshold cannot express.

## Policy

`deny` and `warn` name SPDX ids directly and **beat Trivy's category**, because whether a license
is acceptable depends on what you do with your software — something Trivy cannot know and the
team always does.

```yaml
config:
  controllers:
    licenses:
      enabled: true
      deny: ["AGPL-3.0-only", "GPL-3.0-only"]
      warn: ["MPL-2.0"]
```

Project and component lists **union** rather than override. This is the one place the licenses
control deliberately departs from the deep-merge every other controller uses: under deep-merge a
component that added one denied license would silently discard the organization's list, and a
component quietly opting out of an organization's license policy is precisely what a license gate
exists to prevent. So a component can only **tighten**. Loosening has exactly one route —
`config.exclude`, which requires a reason and leaves the finding in the report, suppressed and
auditable, rather than deleted.

## Links

- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)
- Scope and disclaimer: [license findings are not legal advice](../../docs/trust-and-operations/disclaimer.md)
- Learn: [Software licenses](https://www.draugr.dev/learn/software-licenses/)

## Notes

- Findings are **not** legal advice. Trivy's categories are a starting point for a conversation;
  whether an obligation applies depends on whether you distribute, how you link, and which
  jurisdiction governs.
- Copyleft is a **warning** by default rather than an error, because the obligation is usually
  triggered by distribution — which the descriptor doesn't state. Teams that ship binaries should
  set `deny`.
