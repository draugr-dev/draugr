# Controller: `provenance` (artifact provenance)

- **Industry term:** Artifact provenance / image signature verification
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`cosign`](../scanners/cosign.md)
- **Resource:** a component's `images:`

## What it does

Answers one question per image: **can this be shown to come from where it claims?** An image is
verified against the identity the descriptor expects, and the finding is the gap between the two.

What it does not answer is whether the image is safe. A signature binds an artifact to a builder,
and a builder that has been compromised signs what it is told to. This control never relaxes
another one.

## Signers

A signer says which images it covers and how to recognize whoever signed them. There is no default
signer and no notion of an image being "ours": a rule that applies only under a prefix is a scoped
rule, and the scope belongs on the thing it scopes.

```yaml
config:
  controls:
    provenance:
      enabled: true
      signers:
        - name: our-ci
          images: ["ghcr.io/acme/*"]
          github:
            repository: acme/ci-workflows
            workflow: .github/workflows/build-image.yml
            ref: refs/tags/v3

        - name: chainguard
          images: ["cgr.dev/chainguard/*"]
          keyless:
            issuer: https://token.actions.githubusercontent.com
            identityRegexp: ^https://github\.com/chainguard-images/images/\.github/workflows/release\.yaml@refs/heads/main$
```

| Setting | What it does |
|---|---|
| `signers` | Who is expected to have signed what. |
| `unmatched` | What an image no signer covers is worth: `observe` (the default), `warn` or `fail`. |
| `trustRoot` | A Sigstore trusted-root JSON file, for a runner that cannot reach the transparency log. |

A component may add signers of its own. They are added to the project's rather than replacing
them, the way the [`licenses`](licenses.md) policy is unioned: a component that declared one signer
and thereby discarded the organization's would stop checking most of what it runs, and the
descriptor would still read as a policy.

### `keyless` or `github`

`keyless` is the general form and maps onto cosign's flags one for one: an `issuer`, and either an
exact `identity` or an `identityRegexp`.

`github` is the same thing written as its parts, for GitHub Actions. It exists because the literal
identity has two traps and neither fails loudly. It is a URL with the workflow path inside it, so a
missing or doubled separator reads correctly and matches nothing. And Fulcio derives the identity
from the **workflow that ran**, so a job calling a shared workflow is signed as that workflow's
repository rather than as the caller's: somebody writing their own repository there is writing the
one place it is not.

`draugr validate` prints what the shorthand expands to, so a generated pattern is readable before a
scan depends on it.

## Which signer covers an image

1. An image's `signedBy:` names one, whatever the patterns say. The exception, for the one image
   that came from somewhere else.
2. Otherwise, the signer whose `images` patterns match. `*` matches any run of characters,
   including `/`.
3. An image no signer matches is **observed**: the identity found is reported and nothing is
   checked. `unmatched` decides what that absence is worth.

Two signers matching one image is a validation error. Requiring more than one signature on an
artifact is a real thing to want and a different one; it should be asked for rather than arrived at
through overlapping patterns.

## Starting from nothing

Run the control with no signers declared and it records the issuer and identity of everything it
finds, in its account of the run. That is the answer to *what do I put in `identity`*, and it is
more reliable than constructing one by hand. `draugr scan --format json` carries each identity in
full, which is what to copy from.

```yaml
config:
  controls:
    provenance:
      enabled: true
```

Nothing fails. What comes back is an inventory of who signs what you run, which is the step before
a policy exists.

## What `builtBy` has to do with it

Nothing, deliberately. It would be the obvious field to key on, and it misreads a surveyed
cluster: `draugr survey` records images with no `builtBy`, which resolves to `self`, so an
organization's own signer would be expected on every sidecar and base image in the namespace. The
patterns are declared, and a declared thing cannot be inherited by accident.

`builtBy` keeps its own job, which is deciding whether a vulnerable package inside an image is the
reader's to upgrade.

## Links

- Glossary: [Artifact provenance](../../docs/reference/glossary.md#artifact-provenance)
- How-to: [`docs/guides/provenance.md`](../../docs/guides/provenance.md)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)
