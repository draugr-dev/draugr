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

You need [Draugr installed](../getting-started/install.md) and a repository to scan. The steps use
the hosted server, app.draugr.dev. A server you run yourself works the same way at its own address.

## 1. Create your organization

The hosted server, [app.draugr.dev](https://app.draugr.dev), takes sign-ups by invitation for now, and
you can [ask for one](https://draugr.dev/contact/?about=early-access). The invitation is an email with
a code, the date it is good until, and a link.

Open the link. It opens **Create an organization**, and the code travels in the link, so the page
does not ask for it. Give the organization a name, your name, the address the invitation went to and
a password, and press **Create organization**. You are signed in to the new organization at once,
with no confirmation email to wait for.

Give a different address and the press sends a link to it instead. Open the link within a day to
finish creating the organization. A code that has expired or been used is refused; ask whoever
invited you for another.

On a server you run yourself, ask whoever runs it for a code. Where it is open to sign-ups, the same
page asks for none.

## 2. Create a project and its token

A new organization opens on three steps.

1. **Name a project.** Usually the repository's name. Press **Create project**.
2. **Issue its ingest token.** Press **Issue token**. The console shows two values to copy:
   `DRAUGR_API_URL`, the server's address (`https://app.draugr.dev` on the hosted server), and
   `DRAUGR_API_TOKEN`. The token is shown once and not stored, so copy it now. If it is lost, open
   the project, then **Setup**, and issue another there.
3. **Publish a run.** The console shows the install line, `draugr init` for a repository with no
   Saga, the four lines below with your project's identifier in place of `payments`, the two values
   again, and `draugr tools install` and `draugr scan .`. The same two values publish a run from a
   laptop as from a pipeline.

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
draugr tools install   # once per machine: the scanners this scan runs
draugr feeds update    # KEV, EPSS and Go advisory data, for a Saga with config.exploitability
draugr scan .
```

The scan prints its verdict as usual, and ends with a **Published** block naming the run and the
project it went to: the address of the run's page where the server gives one, and otherwise the run's
id and the server.

```console
PUBLISHED
  https://app.draugr.dev/#/projects/payments/runs/7f3c2a  payments · 7f3c2a
```

The HTML report says the same at its foot. A retried job publishes the same run again: the server
keeps the first copy, and the block says the run was recorded by an earlier attempt. With neither variable set the publisher skips, so the same
Saga still runs on a laptop that publishes nowhere. With only one of them set, the scan fails.

In a pipeline, keep the token as the CI system's secret. The [GitHub Actions](github-action.md#server),
[GitLab](gitlab-ci.md#server) and [Azure Pipelines](azure-pipelines.md#server) guides show where each
one keeps it.

## 5. Find the run in the console

Open the address the **Published** block printed. Where it printed an id and no address, sign in at
[app.draugr.dev](https://app.draugr.dev), or your own server's address, open the project the block
named, and find that id in its **Runs** list, where the run's row shows its verdict as an icon. Open
the row: the run's page says the verdict in words, lists each control that failed the
gate, and counts its findings by the priorities P1 to P4 the scan gave them.

If the run is not there, the scan's output says why: a server that refuses a run answers with an
error code and a reason, and Draugr prints both.

On app.draugr.dev a new organization is on the free plan. It keeps each run's findings and counts.
Each limit, and what happens at it:

- **200 runs a month.** A run is one scan published to the server: a scan that does not publish is
  not counted, and the runs of a project you delete still count for the month. Owners see a notice
  in app.draugr.dev at 160 and get an email at 200. Past 200, the server refuses runs until the
  month resets and says the date, and a pipeline that publishes fails with that message.
- **30 runs a minute on average, and up to 60 in a burst.** A run past that is refused with the time
  to wait, and re-running the job publishes it.
- **10 projects.** An eleventh is refused. An archived project counts until you delete it.
- **5 members.** A sixth is refused until somebody is removed.
- **10,000 findings in one run.** A run with more is refused. Narrow the scan, or split the Saga
  into components.
- **No scanner output.** A run's SARIF is deleted within a day, and the run's page says so.
- **Email for accounts and urgent warnings.** Sign-up, invitations and password resets are emailed,
  and so are the warnings that need action soon, such as the run limit running out. Every other
  notice is shown in app.draugr.dev.

When app.draugr.dev reaches its storage limit, it stops accepting runs from a free organization
until there is room. Scans and their gates still run, but publishing is refused, and a pipeline that
publishes fails with the reason, as it does at the run limit. The console's **Settings › Usage**
shows how much of each limit is used, and under **Capacity** whether runs are accepted; re-running
the job publishes once they are.

## Related

- [Reports and publishers](reports-and-publishers.md#a-server-that-keeps-your-runs): the publisher's
  settings, the variables it reads and the calls a server answers.
- [Configuration](configuration.md#publish): a machine-wide `publish.apiUrl` instead of the variable.
