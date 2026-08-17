# Draugr — Naming & Terminology

Status: **living document**. Captures naming decisions so they don't drift.
Legend: ✅ locked / implemented · 🔶 proposed (not yet committed) · 💤 deferred until it earns a name.

---

## The name: Draugr

A *draugr* is the undead guardian of a treasure hoard in a burial mound (*haugr*) in
Norse mythology — immensely strong, never sleeps, and protects what is its own.

It fits the product: a tireless guardian standing watch over your software. We lean into
the Norse theme deliberately and consistently.

- Org: `github.com/draugr-dev`
- Domain: `draugr.dev`

---

## Core architecture terms

| Term | Status | Meaning |
|------|--------|---------|
| **Scanner** | ✅ | A plugin that wraps a security tool (Trivy, Semgrep, gosec, Gitleaks…) and runs one kind of scan. Normalizes output to **SARIF**. We use "scanner" because it is the word the whole industry already uses. |
| **Controller** | ✅ | Orchestrates one or more scanners for a single **security control** (e.g. the `sast` controller runs `semgrep` by default and `gosec` when opted in). Bound to a scope: `project` or `component`. |
| **Surveyor** | ✅ | A discovery plugin that inspects an environment and *reports back what exists* — e.g. all container images in a k8s cluster, all exposed endpoints, all repos in a GitHub org / ADO project. Surveyors auto-populate the descriptor so developers don't have to write it by hand. Chosen over "explorer": more distinctive, and "a surveyor maps the terrain before you build" is apt. |

**Naming rule — public vs. code:** "Scanner" is both the public/marketing word and the
code term. For the others, the code terms above are canonical; marketing copy may use
plainer phrasing (e.g. "discovery" for surveyors) where it aids first-time understanding.

---

## Security controls (taxonomy)

Control IDs use **recognized industry terms** so Draugr is easy to learn and respected by
security professionals. These are the values under `config.controllers.<id>` in the Saga.
Each is defined in [`glossary.md`](../reference/glossary.md).

Status: ✅ shipped · 🗺️ planned. The [integrations catalog](../reference/catalog.md) tracks the
scanners and issue links for the planned ones.

| Control ID | Industry term | What it assesses | Status |
|------------|---------------|------------------|:------:|
| `sast` | Static Application Security Testing | Your own source code | ✅ |
| `sca` | Software Composition Analysis | Known vulnerabilities in third-party/OSS dependencies | ✅ |
| `licenses` | License compliance | Dependency licenses that carry an obligation | ✅ |
| `secrets` | Secret detection | Leaked credentials/keys in code | ✅ |
| `images` | Container image scanning | OS/library vulns in container images | ✅ |
| `iac` | Infrastructure-as-Code scanning | Misconfigurations in Terraform/K8s/Dockerfiles | ✅ |
| `headers` | HTTP security headers | Response security headers | ✅ |
| `dast` | Dynamic Application Security Testing | A running app/endpoint | ✅ |
| `tls` | TLS/certificate assessment | TLS config and certificates of endpoints | ✅ |
| `threats` | Threat intelligence | Reputation of hosts/URLs (malware, phishing) | 🗺️ |
| `infrastructure` | CIS benchmarks / posture | Cluster hardening and policy (e.g. kube-bench) | ✅ |

**`sbom` is deliberately not on this list.** An SBOM is an inventory, and every row above means
"checked, and here is the verdict" — a control that never looks for anything would always read
`pass`. It ships as evidence under `config.sbom` instead, and never affects the verdict.

History: `sca` was formerly `opensource`, and `tls` was `certificates`; renamed to the standard
terms. License findings were once part of `sca` and are now the separate `licenses` control,
because license risk is legal rather than technical and warrants its own gate threshold.
`images` maps to the Saga's `images:` resource.

---

## Draugr-flavored names (Norse theme)

Names we adopt for major concepts. Use sparingly — over-naming is a cognitive tax, so
only concepts that genuinely benefit from a memorable handle get one. The rest stay
plain (`draugr scan`, `draugr report`).

| Concept | Name | Status | Rationale |
|---------|------|--------|-----------|
| **The descriptor / manifest** | **Saga** | ✅ | A saga *is an account of* something. `draugr.saga.yaml` = "the account of your app": where the repos are, what images it builds, what endpoints it exposes, what infra it runs on. Intuitive, ownable, on-theme. **Doc-facing:** keep the name, but introduce it as "the descriptor (your `draugr.saga.yaml`)" on first mention per page so newcomers aren't taxed. |
| **Surveyors, collectively (the discovery subsystem)** | **Surveyor** (plain) | ✅ | Deliberately unnamed. "The Ravens" (Odin's Huginn & Muninn, who fly the world and report back) was a good fit for what surveyors do, but it was carried alongside the plain term rather than instead of it — every page said "Surveyors (the Ravens)", which is two names for one thing and a tax on the reader for no gain. **Doc-facing:** **Surveyor**, everywhere. |
| **Reporting / evidence engine** | **Skald** | ✅ | A skald is the poet who records and recounts deeds. `pkg/skald` renders scan results to JSON + merged SARIF evidence (human formats live in `pkg/report`). **Code-internal only** — user docs say "report" / "reporting". |
| **Policy / pass-fail gate** | **Norn** | ✅ | The Norns decide fate. `pkg/norn` decides a release's fate. **Code-internal only** — user docs say "the gate" / "verdict". |
| **Plugin marketplace / registry** | **the Hoard** | 🔶 | The treasure a draugr guards. A registry of community scanners, controllers, and surveyors. |

**In use today:** `draugr.saga.yaml` (descriptor), **Skald** (`pkg/skald`), and **Norn**
(`pkg/norn`). **the Hoard** stays reserved until the plugin registry lands.

**Doc-facing vs. code-internal.** `Norn` and `Skald` are **code vocabulary** (`pkg/norn`,
`pkg/skald`) and stay out of user-facing docs — a reader shouldn't have to learn a Norse
name to describe Draugr to a colleague. Published pages use the plain terms: **the gate** /
**verdict** for the Norn, **report** / **reporting** for the Skald. The Norse names live only
in the code and in these `contributing/` architecture docs (`pipeline.md`, `architecture.md`).
`Saga` is the exception that stays user-facing, because it *is* the descriptor's name and
format — glossed as "the descriptor" on first mention.

The test a candidate name has to pass: **does it replace a plain term, or sit next to one?**
A name that replaces (`Saga`, for the thing whose file extension is `.saga.yaml`) earns its
place. A name that sits alongside the plain term leaves the reader carrying both, and the
plain one is what they'll say to a colleague anyway.

---

## Interchange format

**SARIF** (Static Analysis Results Interchange Format, OASIS standard, v2.1.0) is the
JSON standard for security findings. Every Draugr scanner normalizes its output to
SARIF (plus a compliance-evidence superset where needed). Benefits:

- Plugins interoperate for free.
- Results can be pushed straight into GitHub / Azure DevOps / GitLab security dashboards.

Think of it as the USB-C of security findings: one connector, many tools.
