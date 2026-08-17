# Surveyor: `gitlab-group-projects`

- **Discovers:** projects in a GitLab group, subgroups included
- **Status:** ✅ implemented
- **Provides:** repository targets → one Saga component per project (clone URL + default branch)
- **Auth:** `GITLAB_TOKEN` (or a token in the scope config), sent as `PRIVATE-TOKEN`
- **Instance:** `GITLAB_URL`, or the `CI_API_V4_URL` / `CI_SERVER_URL` a runner already sets;
  gitlab.com by default
- **License / terms:** uses the GitLab REST API v4 over HTTPS (stdlib `net/http`). Subject to
  GitLab's [Terms of Use](https://about.gitlab.com/terms/) and its API rate limits, which apply per
  token and per IP. Nothing is sent beyond the group path and the token; no repository content
  leaves the machine — this surveyor reads a project list and clones nothing.

## What it does

Pages through `GET /groups/:id/projects?include_subgroups=true` and returns one Saga component per
project, so the descriptor writes itself:

```bash
draugr survey gitlab projects --group acme -o draugr.saga.yaml
```

**Subgroups are included, and that is not optional.** A GitLab group is a tree. A survey that
stopped at the top level would return a fraction of it and say nothing about the rest, so the
descriptor would look like the whole organization while describing one floor of it.

**Archived and empty projects are skipped, and reported.** An archived project is read-only and
usually nobody's to fix; an empty one has no commits and would fail the clone. Each is logged with
the reason, because a component absent for a good reason still looks like one that was missed.

**A tokenless survey warns.** Without a token GitLab answers with the group's public projects and
nothing else. The resulting descriptor is valid, every control is enabled, and the scan passes or
fails on real findings — while every private project, which is where the interesting code usually
is, is simply not in it. Nobody reading that output has a reason to suspect a gap, so the survey
says so itself.

## Links

- GitLab group projects API: https://docs.gitlab.com/api/groups/#list-a-groups-projects
- GitLab personal access tokens: https://docs.gitlab.com/user/profile/personal_access_tokens/
- Concepts: [surveyors](../../docs/concepts/surveyors.md)
- Guide: [use in CI with GitLab](../../docs/guides/gitlab-ci.md)
