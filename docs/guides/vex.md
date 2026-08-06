---
title: Publish a VEX document
description: Emit OpenVEX from a scan so consumers of your SBOM know which vulnerabilities actually affect your product.
section: Guides
order: 45
---

# Publish a VEX document

An SBOM says what you ship. A scanner says which CVEs touch it. Neither answers the question your
customers are actually asking, which is **whether any of it matters** — so they ask by email, one
customer at a time, and someone on your side answers the same question from memory.

**VEX** — Vulnerability Exploitability eXchange — is that answer written once, in a form their
tooling applies without a human reading it.

```bash
draugr scan draugr.saga.yaml -o out/ --report vex     # out/openvex.json
```

## What comes out

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/draugr/ba9c2b93…",
  "author": "Acme Ltd <security@acme.example>",
  "timestamp": "2026-08-05T10:00:00Z",
  "version": 1,
  "tooling": "draugr/0.68.0",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2018-18074" },
      "products": [ { "@id": "pkg:oci/acme/api@2.4.0" } ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "status_notes": "accepted by security@acme.example; expires 2026-12-31"
    }
  ]
}
```

## Where the statements come from

**Your exclusions, mostly.** A suppression in Draugr is not a delete — it keeps the reason, who
accepted it and when the acceptance lapses, because those are what an auditor asks for. They are
also most of a VEX statement, so a project that has been suppressing findings properly already has
the document.

| The finding | Becomes | Carrying |
|---|---|---|
| Nobody has triaged it | `under_investigation` | — |
| Suppressed, no `vex:` block | `affected` | your `reason` as the action statement |
| `vex: {status: not_affected}` | `not_affected` | the vocabulary term, or your `reason` as prose |
| `vex: {status: affected}` | `affected` | your `reason` as the action statement |
| `vex: {status: fixed}` | `fixed` | — |

Only vulnerabilities appear. A hardcoded secret and an open security group are real findings with
no CVE to be unaffected by, and listing them here would describe them as something they are not.

### Why a suppression is not automatically `not_affected`

Because a suppression does not say *why* in a way a machine can read. "Not reachable" and "we are
living with this until Q3" are both perfectly good reasons and they are opposite VEX statuses,
and the only thing separating them is English prose nobody promised was about reachability.

So Draugr publishes `affected` unless you say otherwise. Overstating your exposure costs a
consumer some wasted triage. Understating it tells a customer they are safe when they are not —
in a signed document, over your name. The default goes in the direction where being wrong is
survivable.

To claim `not_affected`, say so:

```yaml
config:
  exclude:
    - rules: ["CVE-2018-18074"]
      reason: "The redirect path that leaks the header is never taken; we pin the host."
      acceptedBy: "security@acme.example"
      expires: "2026-12-31"
      vex:
        status: not_affected
        justification: vulnerable_code_not_in_execute_path
```

## Name yourself and your product

```yaml
release:
  name: acme-api                                 # what you call this internally
  version: "2.4.0"

config:
  vex:
    author: "Acme Ltd <security@acme.example>"   # who is making the claim
    product: "pkg:oci/acme/api"                  # what a consumer matches on
```

Both are optional. Both are worth setting for a document you publish, because the defaults
produce something valid rather than something useful.

### These are two different names for one product

`release` is **what you call this internally** — it names what Draugr is qualifying and heads
your report. `config.vex` is **how the outside world refers to it**.

They are rarely the same string, and the difference matters because of how VEX is consumed. A
statement is applied by **matching the product identifier** against what the consumer's own SBOM
calls the thing they are scanning. Your release is `acme-api 2.4.0`; their SBOM says
`pkg:oci/acme/api@2.4.0`, or a digest, or a CPE. Only you know which.

- **`author`** — Draugr knows a project name. It does not know your legal entity or how to reach
  you, and a consumer with a question about a claim you made needs somebody to ask. Unset, this
  falls back to `release.name`, which is a project rather than a party.
- **`product`** — unset, this becomes `pkg:generic/<release.name>@<release.version>`, synthesised
  from your descriptor. The `pkg:generic/` prefix says so plainly.

**Get `product` wrong and nothing happens — which is the problem.** A consumer cannot tell that a
statement was meant for it, so a mismatched identifier produces no error anywhere. The document
is read, understood, and applied to nothing. Check it against an SBOM a consumer actually holds
before you publish.

### Let the version track your release

A VEX statement is about a *version* of a product. `not_affected` in 2.3 says nothing about 2.4,
which means a product identifier that has gone stale is making a claim about the wrong artifact.

**Leave the version out and Draugr appends `release.version`:**

```yaml
release:  { name: acme-api, version: "2.4.0" }
config:
  vex:
    product: "pkg:oci/acme/api"      # → pkg:oci/acme/api@2.4.0
```

Ship 2.5.0 and the identifier follows. Nothing to remember.

A version you write yourself is left exactly as given, because pinning to something immutable is
often what you want:

```yaml
    product: "pkg:oci/acme/api@sha256:0123…"
```

The cost of that escape hatch is worth knowing: **a literal version does not follow the
release.** Write `pkg:oci/acme/api@2.4.0`, ship 2.5.0, and the document keeps claiming 2.4.0 —
quietly, because it is still a perfectly valid document. Prefer the version-less form unless you
are pinning to a digest.

## Check that it works

Trivy and Grype both consume OpenVEX, so you can confirm a real reader agrees with you rather than
trusting that the JSON looks right:

```bash
trivy image acme/api:2.4.0 --vex out/openvex.json
```

The vulnerabilities you marked `not_affected` drop out of the results. If nothing changes, the
product identifier is the first thing to check — a mismatch there is silent by design, since a
tool cannot know whether a statement was meant for it.

## Keep it in version control

The document is deterministic: the same run renders the same bytes, and its `@id` is a digest of
its own content. So committing `openvex.json` gives you a diff that shows a decision changing
rather than a file being regenerated — and because the `@id` moves with the content, a consumer
caching by identifier cannot serve superseded claims.

## What this does not do yet

**Statements are about the product as a whole, not individual packages.** OpenVEX can narrow a
statement to a subcomponent — *this product, specifically its copy of `requests` 2.19.1* — which
makes matching work in both directions. Draugr does not emit that yet, because the package URL
is not in the SARIF a scanner returns; recovering it means cross-referencing findings against the
generated SBOM.

**OpenVEX only.** CycloneDX VEX and CSAF are the other two dialects. OpenVEX is standalone, so it
works whether or not you generate an SBOM, and it is the one most readily consumed.

## Related

- [`config.exclude`](../reference/saga-schema.md#configexclude) — the suppressions these
  statements come from
- [`config.vex`](../reference/saga-schema.md#vex-configvex) — author and product
- [SBOM generation](../reference/saga-schema.md#sbom-generation) — the document VEX accompanies
- [Reports and publishers](reports-and-publishers.md) — delivering it somewhere
