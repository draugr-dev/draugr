# Surveyor: `github-org-repos` (the Ravens)

- **Discovers:** repositories in a GitHub organization
- **Status:** ✅ implemented
- **Provides:** repository targets → one Saga component per repo (clone URL + default branch)
- **Auth:** `GITHUB_TOKEN` (or a token in the scope config)
- **License / terms:** uses the GitHub REST API over HTTPS (stdlib `net/http`). Subject to
  GitHub's API terms + rate limits; a token raises limits.

## What it does

Paginates the org's repositories via the GitHub REST API and returns one Saga component per
repository, so the descriptor writes itself.

## Links

- GitHub REST API (repos): https://docs.github.com/en/rest/repos/repos
- Concepts: [the Ravens](../../docs/concepts/surveyors.md)
