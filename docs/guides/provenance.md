---
title: Verify where an image came from
description: Find the identity your builds sign with, declare it, and move from observing signatures to requiring them.
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

- [Start by looking](#start-by-looking)
- [Declare what you found](#declare-what-you-found)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Azure Pipelines and an in-house PKI](#azure-pipelines-and-an-in-house-pki)
- [What a failure looks like](#what-a-failure-looks-like)
- [Requiring coverage](#requiring-coverage)
- [Digests](#digests)
- [A runner with no egress](#a-runner-with-no-egress)

## Start by looking

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
  provenance  cosign · policy: no signers declared, observed only · pinning: 2 of 2 images
              verified by tag, not digest · cgr.dev/chainguard/static:latest:
              https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/h…

No findings. ✓
```

Nothing fails. What comes back is an inventory of who signs what you run: each image that carries
a signature, the identity on it, and a count of the ones that carry none.

A Sigstore identity runs to about 95 characters, so a narrow terminal cuts the tail. `draugr scan
--format json` carries every one in full, which is what to copy from.

## Declare what you found

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

For a self-managed instance the issuer is that instance's URL. Read both back from a discovery run
rather than assembling them by hand.

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
