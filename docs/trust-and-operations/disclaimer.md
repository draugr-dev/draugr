---
title: Scope and disclaimer
description: What Draugr does and does not promise — no warranty, no guarantee of completeness, and why license output is not legal advice.
section: Trust & operations
order: 30
---

# Scope and disclaimer

Draugr is open-source software provided under the [Apache License 2.0](https://github.com/draugr-dev/draugr/blob/main/LICENSE),
**without warranty of any kind**. Sections 7 and 8 of that license are the binding terms; this
page explains what they mean in practice for a tool of this kind.

## Draugr does not guarantee your software is secure

A passing verdict means **the controls you configured found nothing they were looking for**. It
does not mean your application is secure, free of vulnerabilities, or fit for any purpose.

Concretely, a `PASS` is silent about:

- **Anything your Saga doesn't declare.** Draugr checks the components, repositories, images and
  endpoints you describe. A service nobody wrote down is a service nobody scanned.
- **Controls you didn't enable.** Every control is opt-in per project.
- **What the underlying scanners miss.** Draugr orchestrates third-party tools — Trivy, Semgrep,
  Gitleaks, Nuclei and others. Their coverage, accuracy, and false-negative rate are theirs, not
  ours. A vulnerability none of them detects will not appear in a Draugr report.
- **Anything published after your scan.** A dependency that is clean today may have a CVE
  tomorrow. Scans are a point in time.
- **Whole categories of risk no scanner addresses** — business logic flaws, access-control
  design, insider threat, social engineering, physical security.

Draugr is one input to a security program, not a substitute for one.

## License findings are not legal advice

The `licenses` control reports the licenses of your dependencies and describes the obligations
commonly associated with them. **This is information, not legal advice, and no lawyer has
reviewed it for your situation.**

License interpretation depends on facts Draugr cannot know: whether you distribute your software
and in what form, how you link to a dependency, which jurisdiction governs, and what your other
contractual commitments are. Reasonable lawyers disagree about several of these questions, and
some have been litigated to inconsistent conclusions.

The categories Draugr reports come from its scanner's classification and are a **starting point
for a conversation**, not a determination. If a copyleft dependency is load-bearing in something
you distribute, that is a question for counsel.

Nothing in Draugr's output creates an attorney–client relationship, and neither Draugr nor its
contributors accept liability for decisions made on the basis of it.

## Evidence is a record, not a certification

Draugr produces SARIF reports, SBOMs and pass/fail verdicts that are useful as audit evidence.
They record **what was run and what was found**. They are not a certification, attestation, or
statement of conformance to SOC 2, ISO 27001, PCI DSS, the EU CRA, or any other standard or
regulation. Whether a given artifact satisfies a given auditor is between you and that auditor.

Suppressions declared with `config.exclude` are recorded with the reason you supply. Draugr does
not evaluate whether that reason is adequate.

## Third-party tools carry their own terms

Draugr executes external scanners rather than embedding them. When you run them — whether you
installed them yourself or via `draugr tools install` — you do so under **their** licenses and
terms of use, not Draugr's. Some fetch data from third-party services at scan time (Trivy's
vulnerability database, Nuclei's template repository), which may have their own terms and
privacy implications.

`draugr tools list` names each tool. The [integrations catalog](../reference/catalog.md) links
each one's project and license.

## Scanning things you are allowed to scan

Some controls make network requests to hosts you name. `dast` in particular probes a running
endpoint for vulnerabilities, which in many jurisdictions is lawful only against systems you own
or have written permission to test.

**You are responsible for having that authorization.** Draugr will scan whatever a descriptor
points it at; it cannot tell whether you were entitled to.

## Reporting a problem

Security issues in Draugr itself: [SECURITY.md](https://github.com/draugr-dev/draugr/blob/main/SECURITY.md).
Anything else: [GitHub issues](https://github.com/draugr-dev/draugr/issues).
