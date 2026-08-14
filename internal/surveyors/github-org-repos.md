# Surveyor: `github-org-repos`

- **Discovers:** repositories in a GitHub organization
- **Status:** ✅ implemented
- **Provides:** repository targets → one Saga component per repo (clone URL + default branch)
- **Auth:** `GITHUB_TOKEN` (or a token in the scope config)
- **Instance:** `GITHUB_API_URL` for GitHub Enterprise Server, including the `/api/v3` path it
  serves under (`https://github.example.com/api/v3`); github.com by default
- **License / terms:** uses the GitHub REST API over HTTPS (stdlib `net/http`). Subject to
  GitHub's API terms + rate limits; a token raises limits.

## What it does

Paginates the org's repositories via the GitHub REST API and returns one Saga component per
repository, so the descriptor writes itself:

```bash
draugr survey github repos --org acme -o draugr.saga.yaml
```

**It follows the same `GITHUB_API_URL` as the publisher.** GitHub Actions sets that variable on an
Enterprise Server runner, so a survey there needs nothing configured; set it by hand to survey an
Enterprise Server instance from a workstation. One variable configures both halves of the GitHub
integration, which is the only arrangement that cannot leave them pointing at different servers.

## Links

- GitHub REST API (repos): https://docs.github.com/en/rest/repos/repos
- Concepts: [surveyors](../../docs/concepts/surveyors.md)
