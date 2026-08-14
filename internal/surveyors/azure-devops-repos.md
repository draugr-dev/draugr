# Surveyor: `azure-devops-repos`

- **Discovers:** Git repositories in an Azure DevOps organization, or in one of its projects
- **Status:** ✅ implemented
- **Provides:** repository targets → one Saga component per repository (clone URL + default branch)
- **Auth:** `AZURE_DEVOPS_EXT_PAT`, else `AZURE_DEVOPS_TOKEN`, else a token in the scope config —
  a personal access token with the **Code (read)** scope, sent as HTTP Basic in the password field
- **Instance:** `AZURE_DEVOPS_URL` for Azure DevOps Server, including its collection
  (`https://tfs.example.com/DefaultCollection`); `https://dev.azure.com` by default
- **License / terms:** uses the Azure DevOps REST API 7.1 over HTTPS (stdlib `net/http`). Azure
  DevOps Services obtained online is governed by the
  [Microsoft Customer Agreement](https://www.microsoft.com/licensing/docs/customeragreement) or the
  Microsoft Online Subscription Agreement where the MCA is unavailable, with data handling under the
  [Microsoft Products and Services Data Protection Addendum](https://www.microsoft.com/licensing/docs/view/Microsoft-Products-and-Services-Data-Protection-Addendum-DPA);
  an Enterprise Agreement governs instead where the organization bought through one.
  [Rate limits](https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits) apply
  per user. Nothing is sent beyond the organization or project name and the token; no repository
  content leaves the machine — this surveyor reads a repository list and clones nothing.

## What it does

Calls `GET /{organization}/{project}/_apis/git/repositories` and returns one Saga component per
repository, so the descriptor writes itself:

```bash
# every project in the organization
draugr survey azure repos --org acme -o draugr.saga.yaml

# one project
draugr survey azure repos --org acme --project Platform -o draugr.saga.yaml
```

**The project is optional, and that is the point.** An Azure DevOps organization holds many
projects. Surveying one describes a team's surface; surveying the organization describes the
estate. Azure DevOps makes the project segment optional for exactly this reason, so Draugr passes
the choice through rather than making it on your behalf.

**The default branch is shortened.** Azure DevOps reports `refs/heads/main` where the other forges
report `main`. Written into a descriptor unchanged it reaches `git clone --branch refs/heads/main`,
which fails — at scan time, in a file a survey generated and that looks correct in review.

**Disabled and empty repositories are skipped, and reported.** A disabled repository cannot be
cloned; one with no commits has nothing to scan and would fail the clone. Each is logged with the
reason, because a component absent for a good reason still looks like one that was missed.

**A tokenless survey warns.** Without a token Azure DevOps answers for public projects and nothing
else. The resulting descriptor is valid, every control is enabled, and the scan passes or fails on
real findings — while every private repository, which is where the interesting code usually is, is
simply not in it. Nobody reading that output has a reason to suspect a gap, so the survey says so
itself.

## Why an auth failure is called out by name

Azure DevOps answers an unauthenticated or under-scoped API request with **HTTP 203
Non-Authoritative Information** and a sign-in page, rather than a 401. Reported as
`unexpected status 203` that is worse than unhelpful: 203 means "this is fine, from a transforming
proxy" to anyone who looks it up, and the actual cause — a token that is missing, expired, or
without the Code (read) scope — is named nowhere. So 203 and 401 both produce an error that says
which of those to check.

A 404 is called out for the neighbouring reason: Azure DevOps returns it for a scope the token
cannot see as well as for one that does not exist, so "not found" alone sends people to check a
spelling when the answer is a permission.

## Links

- Repositories - List API:
  https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-7.1
- Personal access tokens:
  https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
- Concepts: [surveyors](../../docs/concepts/surveyors.md)
- Guide: [use in CI with Azure Pipelines](../../docs/guides/azure-pipelines.md)
