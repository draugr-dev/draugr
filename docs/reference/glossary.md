---
title: Security glossary
description: Plain-language definitions of the security categories Draugr orchestrates.
section: Reference
order: 40
---

# Security glossary

Plain-language definitions of the security categories Draugr orchestrates, so the whole
team shares the vocabulary. Each maps to a **control** (see the taxonomy in
[`naming.md`](../contributing/naming.md)).

## SCA — Software Composition Analysis

*Go deeper: [SCA](/learn/sca/) in Learn.*

**What it is:** analysis of the **third-party / open-source dependencies** your software
pulls in — *not* your own code. Modern apps are mostly other people's code (often 80%+ by
line count, deep transitive trees), so this is where a large share of real risk lives.

**What an SCA scanner does:**
1. **Builds the dependency inventory** — reads lockfiles/manifests (`go.mod`/`go.sum`,
   `package-lock.json`, `requirements.txt`, `pom.xml`, `Cargo.lock`, …) to resolve the full
   tree, including **transitive** dependencies.
2. **Finds known vulnerabilities** — matches each package + version against vulnerability
   databases ([OSV](https://osv.dev/), GitHub Advisories, NVD): e.g. "you use
   `lodash@4.17.15` → CVE-2020-8203."
3. **Checks licenses** — surfaces each dependency's license so a copyleft/GPL library
   doesn't slip into a proprietary product.

**In Draugr:** the **`sca`** control, backed by [Trivy](https://trivy.dev) (filesystem mode),
covers the first two. The third is the separate **`licenses`** control — licence risk isn't a
vulnerability, so it gets its own gate threshold and its own policy. (Implemented today.)
[OSV-Scanner](https://google.github.io/osv-scanner/) as a second SCA scanner is on the roadmap:
[#49](https://github.com/draugr-dev/draugr/issues/49).

**Not to be confused with:**
- **SAST** — analyzes *your* code, not dependencies.
- **Container image scanning** (`images`) — finds vulns in the OS packages + libraries
  *inside a built image*; overlaps with SCA but operates on the image, not the source tree.
- **SBOM** — the *inventory artifact* SCA produces/consumes; not a pass/fail check itself.

## SAST — Static Application Security Testing

*Go deeper: [SAST](/learn/sast/) in Learn.*

Analyzes your **own source code** (without running it) for security bugs — injection,
unsafe APIs, hardcoded logic flaws. In Draugr: **`sast`** via
[Semgrep](https://semgrep.dev), with opt-in **[gosec](https://github.com/securego/gosec)** for
Go components (`controllers.sast.scanners`). (Implemented today.)

## DAST — Dynamic Application Security Testing

*Go deeper: [DAST](/learn/dast/) in Learn.*

Tests a **running application** from the outside (like an attacker) — probing endpoints
for issues (exposures, misconfigurations, info disclosure, outdated libraries). In Draugr:
**`dast`** via [Nuclei](https://github.com/projectdiscovery/nuclei) (implemented today). A
deeper opt-in engine such as [OWASP ZAP](https://www.zaproxy.org) is a future follow-up.

## Secret detection

*Go deeper: [Secret detection](/learn/secret-scanning/) in Learn.*

Scans code/history for **leaked credentials** — API keys, tokens, private keys. In Draugr:
**`secrets`** via [Gitleaks](https://github.com/gitleaks/gitleaks). (Implemented today.)

## IaC scanning — Infrastructure as Code

*Go deeper: [IaC scanning](/learn/iac-misconfiguration/) in Learn.*

Finds **misconfigurations** in infrastructure definitions (Terraform, Kubernetes manifests,
Dockerfiles, CloudFormation) — open security groups, privileged containers, etc. In Draugr:
**`iac`** via Trivy config (optionally [Checkov](https://www.checkov.io) — [#52](https://github.com/draugr-dev/draugr/issues/52)). (Implemented today.)

## Container image scanning

*Go deeper: [Container image scanning](/learn/container-image-scanning/) in Learn.*

Inspects a **built container image** for known vulns in its OS packages and bundled
libraries. In Draugr: **`images`** via Trivy. (Implemented today.)

## SBOM — Software Bill of Materials

*Go deeper: [SBOM](/learn/sbom/) in Learn.*

A formal, shareable **inventory of everything in your software** (components + versions +
licenses), in a standard format ([SPDX](https://spdx.dev/),
[CycloneDX](https://cyclonedx.org/)). Foundation for SCA, incident response ("am I affected
by X?"), and compliance. In Draugr: `config.sbom` via
[Syft](https://github.com/anchore/syft). (Implemented today.)

Note that it is **not** a control. A control checks something and returns a verdict; an SBOM
is an inventory and has no verdict to give. Draugr treats it as evidence: generated during a
scan, written alongside the other artifacts, and never part of pass or fail.

## Licence compliance

*Go deeper: [Software licences](/learn/software-licences/) in Learn.*

The obligations that come attached to your open-source dependencies. Most licences
(**permissive** — MIT, Apache-2.0, BSD) ask for nothing but attribution. **Copyleft** licences
(GPL, LGPL, AGPL) require you to offer your own source under the same terms *if you distribute*
software that includes them — which is why the same dependency can be fine in a hosted service
and a serious problem in a shipped binary. **File-level copyleft** (MPL, EPL) applies only to the
files you changed.

Nothing here is a vulnerability, and the cost lands somewhere different: a customer's legal
review, or diligence during an acquisition. It is also harder to undo — you fix a CVE by
upgrading, and a licence obligation by removing the dependency and rewriting what it did.

In Draugr: the `licenses` control, backed by [Trivy](https://trivy.dev/latest/docs/scanner/license/).
(Implemented today.) It reports licences that carry an obligation and stays quiet about
permissive ones, which are inventory — the job of an SBOM. Findings are **information, not legal
advice**; see [scope and disclaimer](../trust-and-operations/disclaimer.md).

## HTTP security headers

*Go deeper: [HTTP security headers](/learn/http-security-headers/) in Learn.*

Checks a web endpoint's **response headers** (CSP, HSTS, X-Content-Type-Options, …) that
harden the browser against classes of attack. In Draugr: **`headers`** (native; tuned per host
`type` — browser vs. api). (Implemented today.)

## TLS / certificate assessment

*Go deeper: [TLS / certificate assessment](/learn/tls-assessment/) in Learn.*

Evaluates an endpoint's **TLS configuration and certificates** — protocol versions, certificate
expiry, chain validity, and key/signature strength. In Draugr: **`tls`**, using a native probe
(no external tool). (Implemented today.) Deeper protocol auditing via
[testssl.sh](https://testssl.sh) is a planned opt-in.

## Threat intelligence

*Go deeper: [Threat intelligence](/learn/threat-intelligence/) in Learn.*

Checks the **reputation** of hosts/URLs against known-bad feeds (malware, phishing,
command-and-control). In Draugr: **`threats`** via URLhaus (+ optional VirusTotal).
Roadmap: [#59](https://github.com/draugr-dev/draugr/issues/59).

## CIS benchmarks / posture

*Go deeper: [CIS benchmarks / posture](/learn/infrastructure-cis-benchmarks/) in Learn.*

Audits infrastructure and runtime against hardening baselines — e.g. the **CIS Kubernetes
Benchmark**, a published set of checks covering how a cluster is installed and how it is
configured for the workloads on it.

Unlike the other controls this one assesses a *platform* rather than an artifact, which is why
its findings are located at a cluster rather than a file, and why a cluster can sensibly be a
component with no code of its own.

In Draugr: the **`infrastructure`** control. (Implemented today.) By default it reads the
benchmark's **policies** section — RBAC, service accounts, Pod Security Standards, network
policies, secrets usage — straight from the Kubernetes API, which needs no tool installed and
takes seconds on a large cluster.

That section is the benchmark's *advisory* one: CIS marks every check in it manual, so a clean
result there is a list of things to review rather than a measured pass. The **scored** checks
cover how the nodes and control plane were installed, are read from a node's own filesystem, and
need kube-bench running inside the cluster — which
[`kubeBenchJob`](catalog.md) does, as a short-lived privileged Job that runs only once its
effects are accepted in the descriptor.

A component can also declare the **namespaces** it owns, so a team on a shared cluster is
assessed on its own workloads rather than everybody's.

---

## Cross-cutting terms

- **SARIF** — Static Analysis Results Interchange Format; the OASIS-standard JSON that every
  Draugr scanner normalizes to, so results interoperate and flow into GitHub/GitLab/ADO.
- **CVE** — Common Vulnerabilities and Exposures; a public ID for a specific known vuln.
- **VEX** — Vulnerability Exploitability eXchange; a statement that a given CVE is/isn't
  actually exploitable in your context (used to cut false-positive noise).
- **DevSecOps** — building security into the software delivery pipeline rather than bolting
  it on afterward.
