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

## Depth, and who published it

The two questions readers arrive with, and neither has the answer they expect.

**"It is a dependency of a dependency — does that reduce our responsibility?"** No. No open-source
license conditions its terms on how many edges lie between a component and the code you wrote. A
copyleft library three levels down carries the same obligation as one you imported directly, if the
same facts hold about how it is combined and whether you convey it.

What varies with depth is the *probability* that those facts hold, which is why the opposite is so
often repeated. Deeper packages are more often build- or test-only, more often reached through a
wrapper rather than linked in, and more often replaceable without touching your code. That makes
depth a reasonable way to **order** the work and a bad way to **excuse** it, and the difference is
the whole reason this section exists.

The direction of the standards is against depth as an excuse. CISA's SBOM Minimum Elements dropped
the 2021 *Depth* element — top-level dependencies only — in favor of *Coverage*, which asks for all
components including transitive ones with no minimum depth, and made a component's license a
minimum element in the same revision.

**"Somebody else publishes that repository — is it their obligation?"** Also no.
[`builtBy: upstream`](../../docs/reference/saga-schema.md) does not widen what this control
accepts, deliberately. If you ship or serve the result, the obligation is yours whoever assembled
the tree; a declaration about who authored something cannot move a policy line.

What `builtBy` changes is the **action**. A denied license in a repository you do not publish is not
one you can swap out by editing code, so the fix list stops telling you to — it names the component
to replace or to raise with its publisher. Routing, not relief.

What actually decides an obligation is elsewhere: whether you distribute or convey the result,
whether users reach it over a network (which is what AGPL-3.0 §13 is for), how the code is
combined, and whether the package ships at all. A copyleft formatter that never reaches your
artifact carries no distribution obligation however alarming the row looks. The descriptor states
none of those, which is why copyleft warns rather than fails by default.

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
- **Depth is not reported as a mitigation, and never will be.** Ranking a transitive license lower
  would state something the licenses do not say, on a page somebody might rely on.
