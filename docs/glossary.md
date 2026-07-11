# Security glossary

Plain-language definitions of the security categories Draugr orchestrates, so the whole
team shares the vocabulary. Each maps to a **control** (see the taxonomy in
[`naming.md`](naming.md)).

## SCA — Software Composition Analysis

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
   doesn't slip into a proprietary product (see `planning/third-party-tool-licensing.md`).

**In Draugr:** the **`sca`** control, backed by [Trivy](https://trivy.dev) (filesystem
mode) and [OSV-Scanner](https://google.github.io/osv-scanner/). Roadmap: draugr#49.

**Not to be confused with:**
- **SAST** — analyzes *your* code, not dependencies.
- **Container image scanning** (`images`) — finds vulns in the OS packages + libraries
  *inside a built image*; overlaps with SCA but operates on the image, not the source tree.
- **SBOM** — the *inventory artifact* SCA produces/consumes; not a pass/fail check itself.

## SAST — Static Application Security Testing

Analyzes your **own source code** (without running it) for security bugs — injection,
unsafe APIs, hardcoded logic flaws. In Draugr: **`sast`** via
[Semgrep](https://semgrep.dev). Roadmap: draugr#50.

## DAST — Dynamic Application Security Testing

Tests a **running application** from the outside (like an attacker) — crawling endpoints
and probing for issues (XSS, injection, misconfig). In Draugr: **`dast`** via
[OWASP ZAP](https://www.zaproxy.org). Roadmap: draugr#54.

## Secret detection

Scans code/history for **leaked credentials** — API keys, tokens, private keys. In Draugr:
**`secrets`** via [Gitleaks](https://github.com/gitleaks/gitleaks). Roadmap: draugr#51.

## IaC scanning — Infrastructure as Code

Finds **misconfigurations** in infrastructure definitions (Terraform, Kubernetes manifests,
Dockerfiles, CloudFormation) — open security groups, privileged containers, etc. In Draugr:
**`iac`** via Trivy config / [Checkov](https://www.checkov.io). Roadmap: draugr#52.

## Container image scanning

Inspects a **built container image** for known vulns in its OS packages and bundled
libraries. In Draugr: **`images`** via Trivy. (Implemented today.)

## SBOM — Software Bill of Materials

A formal, shareable **inventory of everything in your software** (components + versions +
licenses), in a standard format ([SPDX](https://spdx.dev/),
[CycloneDX](https://cyclonedx.org/)). Foundation for SCA, incident response ("am I affected
by X?"), and compliance. In Draugr: **`sbom`** via [Syft](https://github.com/anchore/syft).
Roadmap: draugr#57.

## HTTP security headers

Checks a web endpoint's **response headers** (CSP, HSTS, X-Content-Type-Options, …) that
harden the browser against classes of attack. In Draugr: **`headers`** (native). Roadmap: draugr#53.

## TLS / certificate assessment

Evaluates an endpoint's **TLS configuration and certificates** — protocol versions, cipher
strength, expiry, chain validity. In Draugr: **`tls`** via
[testssl.sh](https://testssl.sh). Roadmap: draugr#56.

## Threat intelligence

Checks the **reputation** of hosts/URLs against known-bad feeds (malware, phishing,
command-and-control). In Draugr: **`threats`** via URLhaus (+ optional VirusTotal).
Roadmap: draugr#59.

## CIS benchmarks / posture

Audits infrastructure/runtime against hardening baselines — e.g. the **CIS Kubernetes
Benchmark**. In Draugr: **`infrastructure`** via
[kube-bench](https://github.com/aquasecurity/kube-bench). Roadmap: draugr#55.

---

## Cross-cutting terms

- **SARIF** — Static Analysis Results Interchange Format; the OASIS-standard JSON that every
  Draugr scanner normalizes to, so results interoperate and flow into GitHub/GitLab/ADO.
- **CVE** — Common Vulnerabilities and Exposures; a public ID for a specific known vuln.
- **VEX** — Vulnerability Exploitability eXchange; a statement that a given CVE is/isn't
  actually exploitable in your context (used to cut false-positive noise).
- **DevSecOps** — building security into the software delivery pipeline rather than bolting
  it on afterward.
