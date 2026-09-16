---
title: "cosign"
description: "Checks that a container image carries a Sigstore signature from the identity the descriptor expects."
section: Scanners
order: 110
---

# Scanner: `cosign` (signature verification)

- **Control:** [`provenance`](../controllers/provenance.md)
- **Tool:** **Sigstore cosign**, https://github.com/sigstore/cosign
- **Status:** ✅ implemented
- **Target:** a component's `images:` (`ImageTarget`)
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**. No account, no key and no
  terms to accept: verification reads what the registry and the public Sigstore instances already
  publish.

## What it does

Runs `cosign verify` against each image, with the issuer and identity the
[`provenance`](../controllers/provenance.md) controller resolved for it, and turns the outcome
into at most one finding, plus what it observed either way.

```
cosign verify --output json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/acme/ci/.github/workflows/build.yml@refs/tags/v3 \
  ghcr.io/acme/payments@sha256:9c8f…
```

The verdict is cosign's. Draugr decides what to expect and passes it in; it never reads a
signature back with a permissive pattern and then compares the subject itself. A pattern loose
enough to match anything accepts a signature from anybody, and putting the guarantee behind a
string comparison in Draugr would be the same weakness one layer further in.

### Signatures and attestations answer differently

An artifact can carry a bare cosign **signature** or an **attestation**, and cosign reports on the
two in different ways. A GitHub artifact attestation pushed to the registry with
`push-to-registry: true` is the second kind, which makes it the common case rather than the
exotic one.

For an **attestation**, cosign exits 1 and explains, naming the identity it found in the same
sentence. So a refusal carrying both `no matching attestations` and `failed to verify certificate
identity` is an unexpected signer, and the identity is read out of that message rather than by
asking a second time. Every other reason for exit 1 stays an error: reading them all as a mismatch
would turn a registry nobody could reach into a finding about somebody's artifact.

An attestation's identity is also absent from the payload a successful read prints, so discovery
asks for it separately, by naming an identity no certificate can carry and reading the one cosign
names instead. Without that, the images most likely to carry provenance are the ones discovery
says nothing about.

### What the exit code means

For a **signature**, cosign distinguishes its failures with exit codes it defines, and this scanner
reads only those. Observed against cosign 3.1.1:

| Code | Meaning | Finding |
|---|---|---|
| 0 | verified | none |
| 10 | no signature on the image | `provenance-unsigned` |
| 11 | the reference does not exist | `provenance-unsigned` |
| 12 | signed, by none of the expected identities | `provenance-unexpected-identity` |
| 13 | signed, no certificate on the signature | `provenance-unexpected-identity` |
| anything else | cosign could not answer | the control reports an error |

The last row is the one that matters. cosign returns 1 for everything it has no specific code for,
which includes a registry it could not reach and a transparency log that did not answer. Reading
that as "unsigned" would turn an unreachable registry into a finding somebody triages, and reading
it as a pass would turn it into nothing at all.

On code 12 the image is read back a second time with a permissive identity pattern, to say **who**
did sign it. That read never produces a pass; it only supplies a name for a finding that has
already been made.

## Rules

| Rule | Level | When |
|---|---|---|
| `provenance-unexpected-identity` | error | a signer was expected and the artifact is signed by a different workload |
| `provenance-unsigned` | error | a signer was expected and no signature is in the registry |
| `provenance-not-covered` | warning or error | no signer covers this image, it carries no signature, and `unmatched` is `warn` or `fail` |

An image no signer covers produces **no finding** under the default `unmatched: observe`. What was
found is recorded in the control's account of the run instead: the identity on each signed image,
and a count of the ones carrying none.

A note per image would be the obvious alternative and is the wrong shape. Most of what a project
runs is published by somebody else, so an inventory of fourteen images becomes fourteen rows about
nothing anybody can fix. And a Sigstore identity runs to about ninety-five characters where the
console gives a finding's message ninety-six, so the one part worth copying is the part that would
be cut.

## Saga options

None yet. The expectation belongs to the control, so it is declared once under
`config.controls.provenance.signers` and applies to every scanner serving it. See the
[`provenance` controller](../controllers/provenance.md).

## Digests and tags

An image declared with a `digest:` is verified against that digest. One declared with only a tag
is verified against whatever the tag resolves to at scan time, and the report says how many images
were checked that way under **Measured against**.

Verifying a tag establishes less than verifying a digest, because a tag can be repointed after the
check. It establishes a great deal more than not looking, and refusing would withhold the control
from exactly the descriptors most likely to carry an unexpected signer. What it may not do is go
unsaid.

## Notes

- Integration mode: **exec**. cosign must be on `PATH`; `draugr tools install cosign` provisions
  the pinned build.
- `--insecure-ignore-tlog` is never passed. Without the transparency log there is nothing to
  establish that the signing certificate was valid **when it signed** rather than valid now, and a
  certificate that lives ten minutes is the whole design. cosign 2.x had a vulnerability
  (GO-2026-4529) in exactly that combination.
- A signature establishes where an artifact came from. It does not establish that the artifact is
  safe, and this scanner's findings never relax another control's.

## Data

**Sigstore trust root**, from `tuf-repo-cdn.sigstore.dev`. cosign keeps it under `~/.sigstore`,
and Draugr warms it once per run with `cosign initialize` so a component with fourteen images does
not open fourteen concurrent requests for one file.

A runner that cannot reach it verifies against a copy instead: point
`config.controls.provenance.trustRoot` at a trusted-root JSON file, which becomes
`cosign --trusted-root`. Without either, verification reports an error rather than a pass.

## What is sent

The digest of each image checked, to the registry holding it, and to the Sigstore transparency log
where a signature carries no inclusion proof of its own. Most signatures made in the last few
years carry one, and cosign then verifies the log entry offline and contacts nothing.

No source, no manifest and no credential leaves the machine. The registry already knows which
digests you pull; the transparency log is public, and an entry looked up there is an entry anybody
can already read.

## Links

- cosign: https://github.com/sigstore/cosign
- Verifying signatures: https://docs.sigstore.dev/cosign/verifying/verify/
- OIDC identities in Fulcio certificates: https://github.com/sigstore/fulcio/blob/main/docs/oidc.md
