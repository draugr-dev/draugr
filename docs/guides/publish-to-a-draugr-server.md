---
title: Publish runs to a Draugr server
description: Send each scan to a Draugr server, which keeps it beside the runs before it, from sign-up to the first run in the console.
section: Guides
order: 21
---

# Publish runs to a Draugr server

A Draugr server keeps every run a project sends, so its console shows what is new since last week and
what has stood for months. This guide goes from an invitation to the first run in the console.

A server is optional. Without one, your scan's verdict and gate work as before. If your organization
sets rules on the server, such as how strict a project's gate must be, a run that breaks them also
fails the pipeline; [the organization's policy](../reference/cli.md#the-organizations-policy) says
how.

You need Draugr installed and a repository to scan. The steps use the hosted server, app.draugr.dev.
A server you run yourself works the same way at its own address.

## 1. Create your organization

The hosted server, [app.draugr.dev](https://app.draugr.dev), takes sign-ups by invitation for now, and
you can [ask for one](https://draugr.dev/contact/?about=early-access). The invitation is an email with
a code and a link.

Open the link. It opens **Create an organization** with the code filled in. Give the organization a
name, your name, the address the invitation went to and a password, and press **Create
organization**. You are signed in to the new organization.

On a server you run yourself, ask whoever runs it for a code. Where it is open to sign-ups, the same
page asks for none.

## 2. Create a project and its token

A new organization opens on three steps.

1. **Name a project.** Usually the repository's name. Press **Create project**.
2. **Issue its ingest token.** Press **Issue token**. The console shows two values to copy:
   `DRAUGR_API_URL`, the server's address (`https://app.draugr.dev` on the hosted server), and
   `DRAUGR_API_TOKEN`. The token is shown once and not stored, so copy it now. If it is lost, open
   the project, then **Setup**, and issue another there.
3. **Add Draugr to the pipeline.** The console shows `draugr init` for a repository with no Saga,
   and the four lines below with your project's identifier in place of `payments`.

The token is write-only and scoped to this one project.

## 3. Point the Saga at the project

In `draugr.saga.yaml`, set `project:` to the identifier the console shows, and add `- kind: draugr-api`
to `config.publishers`, starting the list where there is none. With no Saga yet, `draugr init` writes
one first. A Saga with nothing else under `config` ends up like this:

```yaml
project: payments          # the project's identifier, as the console shows it
config:
  publishers:
    - kind: draugr-api     # beside any publishers already listed
```

The token decides which project a run goes to. `project:` is optional, and where it is set the
server checks it: a Saga naming another project is refused with `project_mismatch`, naming both, so a
pipeline holding the wrong token fails rather than filing runs under the wrong project. The
[`draugr-api` publisher](reports-and-publishers.md#a-server-that-keeps-your-runs) renders the run
report and its evidence itself, so it needs no format. The token never goes in the Saga.

## 4. Run a scan that publishes

Set the two values in the environment and scan:

```bash
export DRAUGR_API_URL=https://app.draugr.dev
export DRAUGR_API_TOKEN=drgr_ci_…
draugr scan .
```

The scan prints its verdict as usual, and a log line `run published` naming the run, the project and
the verdict the server recorded. With neither variable set the publisher skips, so the same Saga still
runs on a laptop that publishes nowhere. With only one of them set, the scan fails.

In a pipeline, keep the token as the CI system's secret. The [GitHub Actions](github-action.md#server),
[GitLab](gitlab-ci.md#server) and [Azure Pipelines](azure-pipelines.md#server) guides show where each
one keeps it.

## 5. Find the run in the console

Sign in at [app.draugr.dev](https://app.draugr.dev), or your own server's address, and choose the
project from the project list.
The run is listed with its verdict, and its findings carry the
priorities P1 to P4 the scan gave them.

If the run is not there, the scan's output says why: a server that refuses a run answers with an
error code and a reason, and Draugr prints both.

## Related

- [Reports and publishers](reports-and-publishers.md#a-server-that-keeps-your-runs): the publisher's
  settings, the variables it reads and the calls a server answers.
- [Configuration](configuration.md#publish): a machine-wide `publish.apiUrl` instead of the variable.
