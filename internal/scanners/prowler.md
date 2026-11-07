---
title: "prowler"
description: "Checks a live Google Cloud project or AWS account against the CIS benchmark by running Prowler."
section: Scanners
order: 95
---

# Scanner: `prowler` (cloud accounts)

- **Control:** [`cloud`](../controllers/cloud.md)
- **Tool:** **Prowler**, https://github.com/prowler-cloud/prowler
- **Status:** ✅ implemented (Google Cloud, AWS)
- **Target:** a cloud account (`AccountTarget`)
- **License / terms:** **Apache-2.0** (permissive), the tool and its check metadata. Run via
  **exec**. The command-line tool has no terms of use of its own; Prowler's hosted service, which
  this scanner does not use, has separate terms.

## What it does

Runs `prowler gcp` against the project a Google Cloud account names, or `prowler aws` against an AWS
account, limited to one compliance framework, and reads its OCSF output. A failed check becomes a
finding at the resource Prowler names; a passed one counts as decided.

| Provider | Framework by default | Scoped by |
|---|---|---|
| `gcp` | `cis_5.0_gcp` | `--project-id` |
| `aws` | `cis_7.0_aws` | the credentials' account, confirmed first, and `--region` when the component claims regions |

`compliance` replaces the default for the accounts of the cloud its suffix names, `_gcp` or `_aws`.

The framework's checks are listed first, with `prowler <gcp|aws> --list-checks-json`, so the
coverage figure counts the checks the installed Prowler runs.

### Google Cloud

1. **A permission preflight.** Before Prowler runs, the scanner lists the permissions the checks
   need and asks Google's `testIamPermissions` which of them the credentials hold. A denied read
   gives a pass, a fail or no result, depending on the check. A check reading a service with a
   missing permission is reported unread and its result discarded. Three reads are checked on each
   dataset and bucket rather than on the project, `bigquery.tables.list`, `bigquery.tables.get` and
   `storage.buckets.getIamPolicy`, and a project never reports them held, so their denials come
   from the log. Credentials holding none of the permissions, or that cannot see the project, are an
   error.
2. **The log is read for denials the preflight did not foresee**, and the services it names are
   treated the same way. Prowler also reads organization settings, log sinks and essential contacts
   where the credentials reach that far. A denial there is outside the declared project and leaves
   no check unread; the measured-against line names it, as `organization: not read, denied
   logging.sinks.list`.

### AWS

1. **The caller is confirmed.** Before Prowler runs, the scanner asks STS `GetCallerIdentity` which
   identity the credentials are. Prowler checks whichever account the credentials reach, so an
   identity in another account is an error naming both accounts.
2. **The mutelist is emptied.** Given none, Prowler mutes the resources AWS Control Tower creates.
   The scanner passes a mutelist holding `Mutelist: {}`, so every finding reaches the report, where
   Draugr's excludes suppress one with a reason.
3. **No permission preflight yet.** A check whose reads are denied counts as whatever Prowler made
   of it: a pass, a fail or no result. The measured-against line says `permissions: not checked`,
   and the report holds what Prowler could read.

Findings in a component's claimed regions are kept, matching zones of a region; a component that
claims the whole account gets every finding, including those with no region. On AWS, Prowler files a
finding about the account itself under the first region it audited, so the IAM, account and
Organizations checks and the CloudWatch metric-filter alarms (`cloudwatch_log_metric_filter_*`,
`cloudwatch_changes_*`) go to the component claiming the whole account, whatever region they carry.
CloudTrail's findings stay in the trail's home region.

## Mapping

| Prowler | SARIF |
|---|---|
| `status_code: FAIL` | a result; `PASS` is decided, `MANUAL` neither |
| `severity` critical, high | `error`, score 9.5, 8.0 |
| `severity` medium | `warning`, score 5.5 |
| `severity` low, informational | `note`, score 2.0, 0 |
| `metadata.event_code` | rule `prowler/<check>` |
| `resources[0].uid` | the location: an ARN on AWS |
| `remediation.desc`, `references[0]` | the rule's description and help link |
| `unmapped.compliance["CIS-5.0"]`, `["CIS-7.0"]` | the rule's taxa |

`resources[].data` is never read: it carries what a service returned, which can include secrets
such as function keys.

## Installation

`draugr tools install` does not fetch Prowler. Install it with `pip install prowler` (Python 3.10 to 3.13), or
run the `prowlercloud/prowler` container image with `prowler` on `PATH`. `draugr doctor` names both.

## Permissions

**Google Cloud.** Prowler documents `roles/viewer` and `roles/serviceusage.serviceUsageConsumer` on
the project, plus `storage.buckets.getIamPolicy`, which Viewer lacks. A narrower grant works, and
what it cannot read is reported unread rather than passed. Credentials of a person rather than a
service account need a quota project: `gcloud auth application-default set-quota-project <project>`.

**AWS.** Prowler documents the `SecurityAudit` and `ViewOnlyAccess` managed policies, plus its own
`prowler-additions-policy`. A narrower grant is not detected: what it cannot read is reported as
Prowler reported it.

## Links

- Prowler: https://github.com/prowler-cloud/prowler
- OCSF output: https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/reporting/
- `testIamPermissions`: https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions
- `GetCallerIdentity`: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
- Prowler's AWS permissions: https://docs.prowler.com/user-guide/providers/aws/authentication

## Notes

- Integration mode: **exec**. `prowler` must be on `PATH`, and the credentials must reach the
  account: Application Default Credentials on Google Cloud, the AWS SDK's default chain on AWS
  (`AWS_PROFILE`, the shared config and credentials files, an SSO session, or an instance or task
  role).
- The caller check uses the AWS SDK for Go v2 (Apache-2.0), linked into Draugr. It reads the same
  credential chain Prowler does and calls STS alone.
- Prowler's version is read with its update check unable to connect: `prowler --version` otherwise
  asks api.github.com for the newest release on every scan.
- Prowler sends no telemetry. Its integrations with a hosted dashboard, Shodan and Slack are opt-in,
  and this scanner turns none of them on.

## Data

The checks ship with Prowler. The scan reads the account through the provider's APIs, which are the
target rather than a data source: on Google Cloud, `cloudresourcemanager.googleapis.com` for the
preflight and each service's API for its checks; on AWS, `sts.<region>.amazonaws.com` for the caller
and each service's endpoint for its checks.

Some AWS checks contact other hosts on every scan. None of them is in a CIS framework, so a scan on
the default framework contacts the AWS APIs alone, and a `compliance` framework holding these
checks contacts these hosts too:

| Host | Check | What it reads |
|---|---|---|
| `github.com`, `gitlab.com` | `codepipeline_project_repo_private` | whether a pipeline's source repository answers an anonymous request |
| `ip-ranges.amazonaws.com` | `route53_dangling_ip_subdomain_takeover` | the address ranges AWS publishes |
| `*.s3.<region>.amazonaws.com` | the Lambda and ECR checks that read function code or image layers | the presigned link the API returns |
