# `mend-licenses`

Dependency licence reporting by [Mend](https://www.mend.io), for the `licenses` control.

**Opt-in**, and it shares everything with [`mend-sca`](mend-sca.md) — the same tool, the same
credentials, the same upload. Read that document first: the licence, the terms of use, what is
sent, and the `mutate` effect are identical and are stated there.

```yaml
config:
  allowEffects: [mutate]
  controllers:
    licenses:
      mendLicenses:
        enabled: true
        productToken: "…"
      deny: ["GPL-3.0-only"]     # the control's policy, applied by every scanner serving it
```

## One upload, two controls

Mend produces vulnerability and licence data from a single scan. `mend-sca` reads the project's
alerts; this reads its inventory — a different call against the same uploaded project.

The upload belongs to neither. It happens once per repository per run, whichever scanner needs it
first, so enabling both costs one upload rather than two. That is a correctness requirement rather
than a saving: an upload **replaces** a project's inventory, so a second one could land while the
first's results were being read.

It follows that this control works with `sca` disabled, or served by Trivy. Nothing about the
upload is the SCA scanner's to own.

## Licence names are Mend's, not SPDX

The thing to know before enabling it.

Draugr keys a licence finding as `license/<spdx>/<package>`, and a policy is written in SPDX
identifiers. Mend frequently supplies none, and reports its own vocabulary instead:

```
Jinja2     name="BSD 3"       spdxName=""
requests   name="Apache 2.0"  spdxName=""
```

Where Mend gives an SPDX name it is used, and existing policies match. Where it does not, **the
finding carries Mend's name** and the scan warns, listing the identifiers that run produced:

```
WARN  mend reports these licences by its own names rather than SPDX identifiers, so a policy
      written in SPDX will not match them — write rules against these strings, or use the
      licences control's Trivy scanner, which reports SPDX
      licences="Apache 2.0", "BSD 3", "MIT"
```

Draugr does not translate them. A mapping table would be consulted exactly where there is least
evidence — the cases Mend itself declined to map — and a wrong entry applies your policy to the
*wrong* licence, which is worse than a policy that applies to nothing. Reporting what Mend said
and telling you it did leaves the decision where the evidence is.

## It reports only what your policy names

Trivy also carries a licence *category*, so it can flag a copyleft licence a project never listed.
Mend supplies none. This scanner therefore reports exactly the licences named in
`deny` and `warn`, and **nothing at all without a policy**.

That is a real difference between the two scanners on one control. A project running only this one
and expecting category-based flagging would get silence, which is why it is stated here rather
than discovered.

## Tool, licence and terms of use

Identical to [`mend-sca`](mend-sca.md) — the same proprietary Mend CLI, executed and never
distributed, governed by the [Mend Terms of Service](https://www.mend.io/terms-of-service/), and
reported at `external` attestation because you installed it.

## What is sent

Identical to [`mend-sca`](mend-sca.md), because it is the same upload: the resolved dependency
inventory — names, versions, ecosystems, checksums, and the absolute paths on the scanning machine
where they were found. See that document for Mend's published position on source code, and for
what their privacy notice does and does not address.
