---
title: "prowler"
description: "Checks a live Google Cloud project against the CIS benchmark by running Prowler."
section: Scanners
order: 95
---

# Scanner: `prowler` (cloud accounts)

- **Control:** [`cloud`](../controllers/cloud.md)
- **Tool:** **Prowler**, https://github.com/prowler-cloud/prowler
- **Status:** ✅ implemented (Google Cloud)
- **Target:** a cloud account (`AccountTarget`)
- **License / terms:** **Apache-2.0** (permissive), the tool and its check metadata. Run via
  **exec**. The command-line tool has no terms of use of its own; Prowler's hosted service, which
  this scanner does not use, has separate terms.

## What it does

Runs `prowler gcp` against the project an account names, limited to one compliance framework,
`cis_5.0_gcp` unless `compliance` says otherwise, and reads its OCSF output. A failed check becomes
a finding at the resource Prowler names; a passed one counts as decided.

Three things happen around the run, each because Prowler's output alone would mislead:

1. **The framework's checks are listed first**, with `prowler gcp --list-checks-json`, so the
   coverage figure counts the checks the installed Prowler runs.
2. **A permission preflight.** Before Prowler runs, the scanner lists the permissions the checks
   need and asks Google's `testIamPermissions` which of them the credentials hold. A denied read
   gives a pass, a fail or no result, depending on the check. A check reading a service with a
   missing permission is reported unread and its result discarded. Credentials holding none of the permissions, or that cannot see the project, are an
   error.
3. **The log is read for denials the preflight did not foresee**, and the services it names are
   treated the same way. Prowler also reads organization settings, log sinks and essential contacts
   where the credentials reach that far. A denial there is outside the declared project and leaves
   no check unread; the measured-against line names it, as `organization: not read, denied
   logging.sinks.list`.

Findings in a component's claimed regions are kept, matching zones of a region; a component that
claims the whole account gets every finding, including those with no region.

## Mapping

| Prowler | SARIF |
|---|---|
| `status_code: FAIL` | a result; `PASS` is decided, `MANUAL` neither |
| `severity` critical, high | `error`, score 9.5, 8.0 |
| `severity` medium | `warning`, score 5.5 |
| `severity` low, informational | `note`, score 2.0, 0 |
| `metadata.event_code` | rule `prowler/<check>` |
| `resources[0].uid` | the location |
| `remediation.desc`, `references[0]` | the rule's description and help link |
| `unmapped.compliance["CIS-5.0"]` | the rule's taxa |

`resources[].data` is never read: it carries what a service returned, which can include secrets
such as function keys.

## Installation

Draugr does not distribute Prowler. Install it with `pip install prowler` (Python 3.10 to 3.13), or
run the `prowlercloud/prowler` container image with `prowler` on `PATH`. `draugr doctor` names both.

## Permissions

Prowler documents `roles/viewer` and `roles/serviceusage.serviceUsageConsumer` on the project, plus
`storage.buckets.getIamPolicy`, which Viewer lacks. A narrower grant works, and what it cannot read
is reported unread rather than passed. Credentials of a person rather than a service account need a
quota project: `gcloud auth application-default set-quota-project <project>`.

## Links

- Prowler: https://github.com/prowler-cloud/prowler
- OCSF output: https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/reporting/
- `testIamPermissions`: https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions

## Notes

- Integration mode: **exec**. `prowler` must be on `PATH`, and the Application Default Credentials
  must reach the project.
- Prowler's version is read with its update check unable to connect: `prowler --version` otherwise
  asks api.github.com for the newest release on every scan.
- Prowler sends no telemetry. Its integrations with a hosted dashboard, Shodan and Slack are opt-in,
  and this scanner turns none of them on.

## Data

Nothing fetched. The checks ship with Prowler; the scan reads the project through Google's APIs,
`cloudresourcemanager.googleapis.com` for the preflight and each service's API for its checks,
which are the target rather than a data source.
