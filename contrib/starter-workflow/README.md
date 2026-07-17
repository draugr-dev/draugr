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

Their contribution rules require third-party actions to be **pinned to a specific SHA**. Before
submitting, replace `REPLACE_WITH_RELEASE_SHA` in `draugr.yml` with the commit SHA of the release
tag being pinned, keeping the `# vX.Y.Z` comment:

```bash
gh api repos/draugr-dev/draugr/git/refs/tags/vX.Y.Z --jq '.object.sha'
```

Then open a PR to `actions/starter-workflows` adding the three files above. `actions/checkout` and
`github/codeql-action` stay on major-version tags (they're in the `actions`/`github` orgs, matching
the accepted Trivy entry); only `draugr-dev/draugr` is SHA-pinned.

## Notes

- The workflow sets `tools: true` so the Draugr action provisions the scanners the Saga's controls
  need (Trivy/Gitleaks/gosec + Semgrep) — no per-tool setup steps, keeping the starter simple.
- It assumes the repo has a `draugr.saga.yaml` (as the Trivy starter assumes a Dockerfile). The
  header comment links to the quickstart.
