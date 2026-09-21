# Surveyor: `provenance-signers`

- **Discovers:** the Sigstore identity that signed each image the descriptor declares
- **Status:** ✅ implemented
- **Provides:** `config.controls.provenance.signers` → a Saga fragment
- **Auth:** none. It reads public signature material from the registry holding each image.
- **License / terms:** execs `cosign` (**Apache-2.0**), the same binary the `provenance` control
  uses. No account, no API key, and no terms beyond the registry's own for reading an image's
  signature.

## What it does

Reads the signature on every image in the descriptor at `--output` and writes the `signers:` that
would accept it.

```bash
draugr survey provenance -o draugr.saga.yaml
```

Every other surveyor discovers from a system you name, a cluster or an organization. This one
discovers from the descriptor, because the images are the question, so it reads `--output` before
running rather than only writing to it. A descriptor that does not exist yet, or declares no
images, is an error saying so rather than an empty result.

## Why it exists

Writing a signer by hand means already knowing the identity a build signs with, and there are two
situations where nobody does.

A job that calls a **reusable workflow** is signed as that workflow's repository, not as the
caller. So the obvious value is the wrong one, and it fails later as a mismatch rather than as a
syntax error. The descriptor is accepted, the scan runs, and the finding says an unexpected
identity signed an image that your own pipeline signed correctly.

A **third-party image** can only be pinned to whatever actually signed it, and that is not written
down anywhere you control.

Both are the same job: read the signature that is on the image, and turn it into a signer.

## What it writes

The **exact identity and the exact image**, never a pattern.

```yaml
config:
  controls:
    provenance:
      signers:
        - images:
            - cgr.dev/chainguard/static:latest
          keyless:
            identity: https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
            issuer: https://token.actions.githubusercontent.com
          name: chainguard-images   # read from the signature on cgr.dev/chainguard/static:latest
```

Generating a pattern would mean guessing how broad to be, and one that is too broad accepts
signatures from people the reader did not mean to trust. That passes validation: the schema can
refuse a signer that recognizes nobody and cannot refuse one that recognizes too many. So what it
writes is the narrowest thing that works, and widening it is a deliberate act rather than a default
somebody has to notice and undo.

Images sharing an identity become **one signer with several entries under `images:`**, which is
grouping a reader can check against what it found rather than a pattern they have to evaluate.

## It proposes a policy, so it says so twice

Every other surveyor writes facts. A signer is a **statement about who is trusted**, and one
derived from what currently signs an image cannot fail the check it was derived from.

That is still the right thing to write, because the value was never confirming today's signature.
It is noticing when tomorrow's is different, which is the same bargain an SSH host key makes. And
it is worth exactly as much as the first observation was, so the first observation is made loudly:

```
signers adopted from what signs these images today, not confirmed. Read them before you rely on them:
  chainguard-images
    https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main
    read from the signature on cgr.dev/chainguard/static:latest
```

And again beside the value in the file, because the terminal scrolls and the review happens later,
in an editor, by somebody who may not have run the command. A surveyed signer and a chosen one look
identical in a descriptor.

## What it will not do

**An unsigned image produces no signer, and is not an error.** Most of what a project runs is
published by somebody else and carries no signature. A signer proposed for an image nobody signed
is a policy that can only fail.

**A signature whose identity cannot be read produces no signer either.** "Signed by somebody" is
not something to check against.

**Nothing is inferred about `unmatched`.** Whether an uncovered image is a gap or a fact about the
ecosystem is a judgment belonging to whoever answers for the verdict, and moving from observing to
requiring is a decision rather than a discovery.

**One unreadable image does not discard the rest**, and is warned about by name. A registry that
did not answer is not an image nobody signed, so a run where *none* of them could be read is a
failure rather than an empty answer, because otherwise "nothing here is signed" and "nothing here
could be reached" arrive looking the same.

## Scope

**Sigstore only**, and it says so. A Notary Project signature records nothing observable through
this path; reading a certificate subject with `notation inspect` is its own step rather than a
variation on this one.

An organization running its own Sigstore passes `--trust-root`, the same file
`config.controls.provenance.trustRoot` names. Without it the read would find nothing for exactly
the organizations whose signers are least guessable.

## Data

Reads from the registry holding each image, and from the Sigstore trust root and transparency log,
by way of `cosign`:

| Host | What | When |
|------|------|------|
| the registry holding each image | the signature or attestation attached to it | every survey |
| `tuf-repo-cdn.sigstore.dev` | the Sigstore trust root | first use, then cached under `~/.sigstore` |

It sends the digest of each image to the registry holding it, and, where a signature carries no
inclusion proof, to the transparency log. The same disclosure the `provenance` control makes,
because it is the same read.
