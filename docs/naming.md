# Draugr — Naming & Terminology

Status: **living document**. Captures naming decisions so they don't drift.
Legend: ✅ locked · 🔶 proposed (not yet committed) · 💤 deferred until it earns a name.

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
| **Scanner** | ✅ | A plugin that wraps a security tool (Trivy, SonarQube, Snyk, ZAP…) and runs one kind of scan. Normalizes output to **SARIF**. We use "scanner" because it is the word the whole industry already uses. |
| **Controller** | ✅ | Orchestrates one or more scanners for a single **security control** (e.g. the `sast` controller may run SonarQube and/or Horusec). Bound to a scope: `project` or `component`. |
| **Surveyor** | ✅ | A discovery plugin that inspects an environment and *reports back what exists* — e.g. all container images in a k8s cluster, all exposed endpoints, all repos in a GitHub org / ADO project. Surveyors auto-populate the descriptor so developers don't have to write it by hand. Chosen over "explorer": more distinctive, and "a surveyor maps the terrain before you build" is apt. |

**Naming rule — public vs. code:** "Scanner" is both the public/marketing word and the
code term. For the others, the code terms above are canonical; marketing copy may use
plainer phrasing (e.g. "discovery" for surveyors) where it aids first-time understanding.

---

## Draugr-flavored names (Norse theme)

Names we adopt for major concepts. Use sparingly — over-naming is a cognitive tax, so
only concepts that genuinely benefit from a memorable handle get one. The rest stay
plain (`draugr scan`, `draugr report`).

| Concept | Name | Status | Rationale |
|---------|------|--------|-----------|
| **The descriptor / manifest** | **Saga** | ✅ | A saga *is an account of* something. `draugr.saga.yaml` = "the account of your app": where the repos are, what images it builds, what endpoints it exposes, what infra it runs on. Intuitive, ownable, on-theme. |
| **Surveyors, collectively (the discovery subsystem)** | **the Ravens** (**Huginn & Muninn**) | ✅ | Odin's ravens, Thought & Memory, fly across the world and report back what they see — exactly what surveyors do. "The Ravens found 12 images in this cluster." |
| **Reporting / evidence engine** | **Skald** | 🔶 | A skald is the poet who records and recounts deeds. The engine that turns scan results into pass/fail evidence and reports. |
| **Policy / pass-fail gate** | **Norn** | 🔶 | The Norns decide fate. The gate decides a release's fate. "The Norns ruled: this release fails on 2 critical findings." |
| **Plugin marketplace / registry** | **the Hoard** | 🔶 | The treasure a draugr guards. A registry of community scanners, controllers, and surveyors. |
| **Commercial control plane (multi-team hub)** | **cloud** (repo) / **Yggdrasil** (feature) | 💤 | The world-tree connecting the nine realms — the hub connecting all teams, scanners, and clusters. Repo is plainly `cloud`; `Yggdrasil` reserved for a user-facing feature name. |

**Locked for MVP:** `draugr.saga.yaml` (descriptor) and **the Ravens** (surveyors).
Everything else stays plain until it earns its name.

---

## Interchange format

**SARIF** (Static Analysis Results Interchange Format, OASIS standard, v2.1.0) is the
JSON standard for security findings. Every Draugr scanner normalizes its output to
SARIF (plus a compliance-evidence superset where needed). Benefits:

- Plugins interoperate for free.
- Results can be pushed straight into GitHub / Azure DevOps / GitLab security dashboards.

Think of it as the USB-C of security findings: one connector, many tools.
