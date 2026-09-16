---
title: "notation"
description: "Checks that a container image carries a Notary Project signature from a certificate the descriptor trusts."
section: Scanners
order: 115
---

# Scanner: `notation` (Notary Project signature verification)

- **Control:** [`provenance`](../controllers/provenance.md)
- **Tool:** **Notary Project notation**, https://github.com/notaryproject/notation
- **Status:** ✅ implemented
- **Target:** a component's `images:` (`ImageTarget`)
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**. No account and no key:
  verification reads the signature in the registry and certificates already on this machine.

## What it does

The X.509 half of the provenance control. Sigstore identifies a signer by a short-lived
certificate tied to a workload; this identifies one by a certificate chaining to roots somebody
holds. Azure Pipelines signs this way with a key in Azure Key Vault, and so does any organization
with its own certificate authority.

A signer selects it by declaring `x509:` rather than `keyless:`:

```yaml
config:
  controls:
    provenance:
      signers:
        - name: acme-pki
          images: ["acme.azurecr.io/*"]
          x509:
            trustStore: .draugr/truststore/acme-ca.pem
            subject: "C=US, ST=WA, O=Acme, CN=Acme Release Signing"
```

## The trust policy is generated

notation takes its trust policy and trust store from a configuration directory rather than from
flags. Draugr writes one per job from what the descriptor declared: a policy scoped to the
repository being verified, at verification level `strict`, naming the subject as its only trusted
identity, and a trust store holding the roots the signer named.

Generated rather than asked for. A policy file beside the descriptor would be a second place
stating who may sign, and two places that have to agree are one place that drifts. It also keeps
the scope honest: a policy written for one image cannot decide another, because the only scope in
it is the repository of the image in front of it.

The directory is created per job and removed afterwards. A shared one would have concurrent scans
overwriting each other's policy, and a policy left behind is a trust decision outliving the run
that made it.

## How a failure is classified

notation exits **1 for everything**: a missing signature, a wrong certificate and a registry it
could not reach share one code. So the outcomes that mean something are recognized by what it
said, observed against notation 1.3.2:

| What notation says | Finding |
|---|---|
| `no signature is associated with` | `provenance-unsigned` |
| `does not match the X.509 trusted identities` | `provenance-unexpected-identity` |
| `has no applicable trust policy statement` | an error: the scope Draugr wrote did not match the image it was built from |
| anything else | an error the control reports |

Reading a message is weaker than reading an exit code, and it is what this tool offers. It fails in
the safe direction: wording that changes upstream turns a finding into an error rather than into a
pass, so a run says it could not answer instead of saying nothing is wrong.

## Rules

| Rule | Level | When |
|---|---|---|
| `provenance-unexpected-identity` | error | the artifact is signed by a certificate that is not the declared subject, or does not chain to the declared roots |
| `provenance-unsigned` | error | no Notary Project signature is in the registry |

There is no discovery mode here. Reading back an unknown signer needs no prior trust, which is
true of Sigstore and not of X.509: without a trust store there is nothing for a certificate to
chain to. An image no signer covers is handled by [`cosign`](cosign.md) instead. To find the
subject string to declare, run `notation inspect` against the image and copy the `issued to:` line
verbatim.

## Saga options

None. The expectation belongs to the control, declared once under
`config.controls.provenance.signers`. See the [`provenance` controller](../controllers/provenance.md).

## Notes

- Integration mode: **exec**. notation must be on `PATH`; `draugr tools install notation`
  provisions the pinned build.
- Verification is by digest where the descriptor pins one. notation warns when given a tag and
  resolves it itself, which is the same weaker check the control reports under **Measured
  against**.
- A signature establishes where an artifact came from. It does not establish that the artifact is
  safe, and this scanner's findings never relax another control's.

## Data

Nothing. Trust comes from the certificates the descriptor names, and a Notary Project signature is
verified against them rather than against a transparency log, so there is no reference data to
fetch and nothing to warm. That is also what makes this the workable path on a runner with no
egress beyond its own registry.

## What is sent

The digest of each image checked, to the registry holding it. No third party is contacted: no
transparency log, no certificate authority, no timestamp service unless the signature carries one
and the descriptor's trust store holds its root.

No source, no manifest and no credential leaves the machine. The registry already knows which
digests you pull.

## Links

- notation: https://github.com/notaryproject/notation
- Trust store and trust policy: https://github.com/notaryproject/specifications/blob/main/specs/trust-store-trust-policy.md
- Signing in Azure Pipelines: https://learn.microsoft.com/en-us/azure/security/container-secure-supply-chain/articles/notation-ado-task-sign
