# Controller: `secrets` (Secret detection)

- **Industry term:** Secret detection
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`gitleaks`](../scanners/gitleaks.md)
- **Resource:** a component's `repositories:`

## Scope

**The working tree at the scanned revision, and its history when you ask for it.**

By default repositories are cloned shallow and this control reports secrets present in the code as
it stands — the state that gets deployed, and the one a pull request changes. That is the fast
path, and it is the right default for a gate that runs on every change.

A credential that was committed and later removed stays in git history and stays fetchable by
anyone who can clone, so removing it from the tip is not remediation: it needs rotating. To find
those, ask for the history:

```yaml
config:
  controllers:
    secrets:
      gitleaks:
        history: true
```

That adds a second pass over the commit history, and switches the clone to a full one — slower on
a large repository, which is why it is opt-in. The clone and the pass are decided together on
purpose: `gitleaks git` over a shallow clone walks a single commit and reports clean, which reads
exactly like a repository whose history is genuinely empty.

**The tree is still scanned as well, and that is not redundant.** A history pass reports the path
a secret had in the commit that introduced it. If the file has since been renamed, that path no
longer exists — and the finding reads as something already cleaned up, which is exactly backwards
for a credential still sitting in the working tree. So the two passes answer two questions:

```
P1  high  github-pat  secrets  gitleaks  new/scripts/check.ps1:1
P1  high  github-pat  secrets  gitleaks  old/scripts/check.ps1:1
        ↩ found in commit history — this path is as it was then, and may have moved or gone
          since. Still needs rotating: removing it from the tip does not unpublish it.
```

Both are real, and they call for different work: fix the tree, and rotate plus purge the history.
A secret that has genuinely been removed from the tip still appears, marked — because removing it
is not remediation. It remains fetchable by anyone who can clone.

**A good split is history on a schedule, tree on a pull request.** History changes rarely, so a
nightly or weekly deep scan is a backstop rather than a gate, and the per-change scan stays fast.

With `paths:` scoping, the tree is narrowed but the history is not — git history is not
sparse-checkoutable. Findings from outside the scoped subtree are real findings in that
repository; use [`config.exclude`](../../docs/reference/saga-schema.md) if they are not this
component's business, so they stay in the report marked suppressed rather than disappearing.

## Vendor identifiers that authenticate nothing

Product tokens, project tokens, tenant and workspace ids are commonly 64 hex characters, which is
also what an API key looks like. Gitleaks' `generic-api-key` rule reports them, and this control
escalates every finding to `error`, so one of these in a committed descriptor fails the gate.

**The answer is an exclusion, not relocation.** A Mend product token names which product a
component reports into, may differ per component, and grants no access — that is configuration,
and configuration belongs in the file that is committed and reviewed. Moving it somewhere the
scanner cannot see would let a false positive dictate the shape of the descriptor.

```yaml
config:
  exclude:
    - paths: ["draugr.saga.yaml"]
      rules: ["generic-api-key"]
      reason: >-
        The Mend product token identifies a product and authenticates nothing; the user key is
        the credential and never appears in a descriptor. Reported because it is 64 hex characters.
      acceptedBy: "platform-security"
```

The finding stays in the report, marked with that reason. Which is the point: the question an
auditor asks is not "did the scanner run", it is "who decided this was acceptable, and when".

## What it does

Plans one scan per repository declared on a component (each is checked out and scanned for
leaked credentials), then aggregates + deduplicates findings into a per-control result.

**Every finding is escalated to `error` severity.** A leaked secret should fail the gate
regardless of how the scanner rated it, so the controller normalizes severity rather than
trusting the scanner's own level (Gitleaks, in fact, emits none).

## Links

- Glossary: [Secret detection](../../docs/reference/glossary.md#secret-detection)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- History scanning is per-scanner config rather than a control-level or Saga-level switch,
  because it is Gitleaks' clone depth and scan mode that change. A different secrets scanner
  would express the same intent its own way.
