---
title: Verify where an image came from
description: Read the identity your builds sign with, declare it, and move from observing signatures to requiring them.
section: Guides
order: 95
---

# Verify where an image came from

The `provenance` control asks one question per image: **can this be shown to come from where it
claims?** It runs [cosign](https://github.com/sigstore/cosign) against each image a component
declares and compares the signature against the identity you expect.

It does not answer whether the image is safe. A build platform that has been compromised signs
what it is told to. Provenance is about origin.

## Contents

- [Where a signature lives](#where-a-signature-lives)
- [Discovery](#discovery)
- [Declare a signer](#declare-a-signer)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Azure Pipelines and an in-house PKI](#azure-pipelines-and-an-in-house-pki)
- [What a failure looks like](#what-a-failure-looks-like)
- [Requiring coverage](#requiring-coverage)
- [Digests](#digests)
- [A runner with no egress](#a-runner-with-no-egress)

## Where a signature lives

Nothing is read out of the image. A Sigstore signature is a **separate artifact in the same
registry**, named after the image's digest:

```console
$ cosign tree cgr.dev/chainguard/static:latest
📦 Supply Chain Security Related artifacts for an image: cgr.dev/chainguard/static:latest
└── 💾 Attestations for an image tag: cgr.dev/chainguard/static:sha256-bf639cba...96e6b82.att
   ├── 🍒 sha256:a359663b7dfccf0971cbf9c6aada1c71b4e428b7f851c6e7ede4ba42301121f8
   ├── 🍒 sha256:54124f51bf99b7ddbeb7a6624cefd15d610699a8e3ec51732414135aad97874b
   └── 🍒 sha256:84be16de40bfd936a936c91e742006a10467d388c1fedc602afe92f95631c47e
└── 🔐 Signatures for an image tag: cgr.dev/chainguard/static:sha256-bf639cba...96e6b82.sig
   └── 🍒 sha256:3170452cf30566399ec7dc0128e04791ec3c990acd6f6a61c5ef481342f4bf97
```

Two artifacts, both named after the image's digest and neither part of it. The `.sig` is the
signature; the `.att` is an attestation, which says something *about* how the image was built.

That artifact holds the signature and a short-lived **certificate issued by Fulcio**. When a build
signs, it presents an OIDC token from its CI platform, and Fulcio issues a certificate whose subject
is the workload that asked: a workflow file at a ref, a GitLab project, a service account. The
identity Draugr checks against is that subject, and the issuer is the platform that vouched for it.

So an image tells you nothing about who signed it. The signature beside it does, and only because
a certificate authority wrote the identity down at the moment of signing.

Three consequences worth knowing:

- **A signature can be added or replaced without the image changing.** The image digest stays the
  same; the artifact next to it does not. This is why the check is worth re-running rather than
  recording once.
- **An image can carry several**, as above. Different signers, or a signature and an attestation,
  sit side by side under the same digest.
- **Deleting the signature makes an image unsigned**, and looks like an image that was never signed.
  That is what `unmatched: warn` and `unmatched: fail` exist to notice.

### It is verified, not read

Draugr never parses a certificate and compares strings. It asks cosign to verify, and believes the
exit code:

```bash
cosign verify --certificate-identity <what you declared> \
              --certificate-oidc-issuer <who you declared> <image>
```

Verifying means the signature checks out against the certificate, the certificate chains to
Fulcio's root, and the entry is in the [Rekor](https://docs.sigstore.dev/logging/overview/)
transparency log. The log is what establishes that the certificate was valid **when it signed**
rather than valid now. A Fulcio certificate lives about ten minutes, so without it a signature would
stop verifying almost immediately, and `--insecure-ignore-tlog` is never passed.

Reading the certificate back with a permissive pattern and matching the subject in Go would put the
whole guarantee behind one string comparison, and a pattern loose enough to match anything is the
documented way this mechanism gets bypassed. Draugr decides *what* to expect and cosign decides
whether it holds.

## Discovery

Turn the control on with no policy at all.

```yaml
config:
  controls:
    provenance:
      enabled: true
```

```console
$ draugr scan
DRAUGR  PASS  acme 1.0.0  1.787s

CONTROLS
  provenance  pass   no findings

MEASURED AGAINST
  provenance  cosign · coverage: 0 of 2 images checked, 1 observed, 1 unsigned · scope: no
              signers declared

No findings. ✓
```

Nothing fails. `observed` counts the images signed by somebody this descriptor has not named, and
`unsigned` the images carrying no signature at all. Together those are how much of the inventory a
policy would have to cover.

The identities themselves are in `--format sarif`, under `draugr/provenance`, which is what to
copy from when writing a signer:

```console
$ draugr scan --format sarif | jq '.runs[].properties["draugr/provenance"][].detail'
{
  "cgr.dev/chainguard/static:latest identity": "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main",
  "cgr.dev/chainguard/static:latest issuer": "https://token.actions.githubusercontent.com"
}
```

Both halves, because an identity is only an expectation together with who issued it. They are also
the two fields a `keyless:` signer is written from.

### Or let the survey write them

`draugr survey provenance` performs the same read and writes the signers straight into the
descriptor, which saves copying two long URLs per image by hand:

```console
$ draugr survey provenance -o draugr.saga.yaml

signers adopted from what signs these images today, not confirmed. Read them before you rely on them:
  chainguard-images
    https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
    read from the signature on cgr.dev/chainguard/static:latest
```

It writes the exact identity and the exact image, never a pattern, and groups images sharing an
identity under one signer. An unsigned image produces no signer and is not an error.

**Read what it proposes before you rely on it.** A signer derived from what signs an image today
cannot fail the check it was derived from. That is what makes it useful, because it is a tripwire
for the signature changing rather than proof that today's is right, and it is worth exactly what the
first observation was worth. The command says what it adopted and writes the same note beside each
value in the descriptor, so the reasoning is where the review happens.

## Declare a signer

A signer says which images it covers and how to recognize whoever signed them.

```yaml
config:
  controls:
    provenance:
      enabled: true
      signers:
        - name: our-ci
          images: ["ghcr.io/acme/*"]
          keyless:
            issuer: https://token.actions.githubusercontent.com
            identity: https://github.com/acme/ci-workflows/.github/workflows/build-image.yml@refs/tags/v3
```

`*` matches any run of characters, including `/`. An image no signer covers stays observed.

There is no default signer. A rule that applies only under a prefix is a scoped rule, so the scope
is written on the signer rather than inferred from anything else about the image.

**Two signers matching one image is refused.** Requiring more than one signature on an artifact is
a real thing to want and a different one; ask for it rather than arriving at it through
overlapping patterns. Use `signedBy` on the image to pick one:

```yaml
components:
  - name: payments
    images:
      - image: ghcr.io/acme/payments
        signedBy: our-ci
```

## GitHub Actions

Two things about the identity are easy to get wrong, and both fail as a mismatch rather than as a
syntax error.

Fulcio derives the identity from **the workflow that ran**. A job that calls a shared workflow is
signed as that workflow's repository, not as the calling repository, so the obvious value is the
wrong one. And the identity is a URL with a path inside it, where a missing separator reads
correctly and matches nothing.

The shorthand writes it for you:

```yaml
- name: our-ci
  images: ["ghcr.io/acme/*"]
  github:
    repository: acme/ci-workflows          # whose workflow signs, not whose code is built
    workflow: .github/workflows/build-image.yml
    ref: refs/tags/v3
```

`draugr validate` prints what it expands to, so the generated pattern is readable before a scan
depends on it:

```console
$ draugr validate
✓ draugr.saga.yaml is valid
  · provenance: signer "our-ci" expects
    https://github.com/acme/ci-workflows/.github/workflows/build-image.yml@refs/tags/v3
    issued by https://token.actions.githubusercontent.com
```

**Set `push-to-registry: true` on the attest step.** `actions/attest` defaults it to `false`, which
writes the attestation to GitHub's attestations API and nowhere else. Draugr reads the registry, so
an image attested that way reports as unsigned.

With it on, the attestation is written to the registry as an OCI referrer and Draugr checks it like
any other signature. Nothing else changes: the same `github:` signer covers both, because the
identity in the certificate is the same one either way.

## GitLab CI

The issuer is your instance, and the identity is the project URL followed by `//` and the config
file. The double slash is not a typo.

```yaml
- name: our-ci
  images: ["registry.gitlab.com/acme/*"]
  keyless:
    issuer: https://gitlab.com
    identity: https://gitlab.com/acme/payments//.gitlab-ci.yml@refs/heads/main
```

For a self-managed instance the issuer is that instance's URL.

## Azure Pipelines and an in-house PKI

Sigstore is not the only way an image gets signed. Azure Pipelines signs with the `Notation@0` task
and a certificate in Azure Key Vault, and an organization with its own certificate authority signs
the same way. That is a different trust model, not a different string: a certificate chaining to
roots you hold, rather than a short-lived identity tied to a workload.

Declare `x509:` instead of `keyless:` and Draugr verifies with `notation`:

```yaml
- name: acme-pki
  images: ["acme.azurecr.io/*"]
  x509:
    trustStore: .draugr/truststore/acme-ca.pem
    subject: "C=US, ST=WA, O=Acme, CN=Acme Release Signing"
```

`subject` has to match the certificate exactly, as a comma-separated distinguished name. Run
`notation inspect <image>` against something you have signed and copy the `issued to:` line.

Which verifier runs is decided per image by the signer that matched, so a project signing some
images with Sigstore and others with a certificate declares both and needs no flag.

Draugr writes notation's trust policy itself, scoped to the image in front of it. There is no
policy file to keep beside the descriptor, and nothing contacts a transparency log, so this path
works wherever the registry is reachable.

## What a failure looks like

An image signed by a workload no signer names reports `provenance-unexpected-identity`, at
critical severity. Its message leads with the identity found and closes with the one expected,
because that is the comparison a reader is making and the console gives a message 96 characters:

    Signed by acme-forks/payments/.github/workflows/release.yml@refs/heads/main, not our-ci.

An image a signer covers and that carries no signature at all reports `provenance-unsigned`.

Both land at the band the component earns. On a component declared public and critical that is P1;
the same finding on an internal supporting one lands lower. The priority model folds in what the
descriptor says about the component, and this control adds no ranking of its own.

## Requiring coverage

Once the inventory has been worked through, an image no signer covers is a gap rather than a fact
about the ecosystem.

```yaml
config:
  controls:
    provenance:
      unmatched: fail     # observe (the default) | warn | fail
```

Do not start here. Among the two thousand most-downloaded npm packages, the ones publishing from
GitHub Actions with provenance enabled are a small minority, and container images are no further
ahead. A control that fails on every third-party image is a control somebody switches off in its
first week.

## Digests

An image declared with a `digest:` is verified against that digest. One declared with only a tag is
verified against whatever the tag resolved to at scan time, and the run says how many were checked
that way.

```yaml
images:
  - image: ghcr.io/acme/payments
    digest: sha256:9c8f…
```

Verifying a tag establishes less, because a tag can be repointed after the check. It establishes
far more than not looking. `draugr survey` records the digest each image in a cluster resolved to,
which is the shortest route to a descriptor that pins everything.

## A runner with no egress

Verification reaches the Sigstore trust root, and a signature with no inclusion proof of its own
reaches the transparency log. A runner that can reach neither verifies against a cached root:

```yaml
config:
  controls:
    provenance:
      trustRoot: .draugr/sigstore-root.json
```

Produce the file on a machine with a network (`cosign initialize` populates `~/.sigstore`) and
carry it across. Without it, a runner that cannot reach the log reports an error rather than a
pass: a check that could not run has not passed.

## Links

- [`provenance` control](../../internal/controllers/provenance.md)
- [`cosign` scanner](../../internal/scanners/cosign.md)
- [Artifact provenance](../reference/glossary.md#artifact-provenance)
- [Running air-gapped](air-gapped.md)
