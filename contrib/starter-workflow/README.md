# Code-scanning starter workflow (source)

The canonical source for Draugr's entry in GitHub's **code-scanning "Add tool" gallery**
([actions/starter-workflows](https://github.com/actions/starter-workflows)). Tracked here so the
submission is version-controlled; submitting is a manual PR to that repo (see #180).

## Files → destination in actions/starter-workflows

| File | Goes to |
|------|---------|
| `draugr.yml` | `code-scanning/draugr.yml` |
| `draugr.properties.json` | `code-scanning/properties/draugr.properties.json` |
| `draugr.svg` | `icons/draugr.svg` |

## Submitting

Their contribution rules require actions outside the `actions` org to be **pinned to a specific
SHA**. `draugr.yml` here is kept pinned to a real release rather than a placeholder, so what's in
this repo is exactly what gets submitted and can be reviewed as such.

**Getting the SHA right matters more than it looks.** Our release tags are *annotated*, so the
obvious command returns the tag object, not the commit — and an action pinned to a tag-object SHA
does not resolve, for everyone, forever. Dereference it:

```bash
gh api repos/draugr-dev/draugr/git/refs/tags/vX.Y.Z --jq '.object.sha' \
  | xargs -I{} gh api repos/draugr-dev/draugr/git/tags/{} --jq '.object.sha'
```

Cross-check against `git rev-list -n1 vX.Y.Z` before using it.

Then open a PR to `actions/starter-workflows` adding the three files above. `actions/checkout` and
`github/codeql-action` stay on major-version tags — the accepted Trivy entry does the same, so the
precedent covers `github/` despite it sitting outside the `actions` org. Only `draugr-dev/draugr`
is SHA-pinned.

Refresh the pin when the action's interface changes, not every release: a starter workflow is a
starting point people copy, and churning the SHA gains them nothing.

## Notes

- The workflow sets `tools: true` so the Draugr action provisions the scanners the Saga's controls
  need (Trivy/Gitleaks/gosec + Semgrep) — no per-tool setup steps, keeping the starter simple.
- It assumes the repo has a `draugr.saga.yaml` (as the Trivy starter assumes a Dockerfile). The
  header comment links to the quickstart.
- `draugr.svg` is the brand mark, gold on a dark hexagon with a transparent surround, so it reads
  on both light and dark gallery backgrounds. It replaced a placeholder shield in GitHub's blue
  that was never Draugr's logo.
- `contrib/starter-workflow/` is excluded from our own SAST self-scan. Semgrep's
  `github-actions-mutable-action-tag` rule wants every `uses:` SHA-pinned, which is right for a
  workflow you operate and wrong for a template — and here it would also contradict the accepted
  precedent this file is modelled on. See `.semgrepignore`.
