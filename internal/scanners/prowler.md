---
title: "prowler"
description: "Checks a live Google Cloud project, AWS account or Azure subscription against the CIS benchmark by running Prowler."
section: Scanners
order: 95
---

# Scanner: `prowler` (cloud accounts)

- **Control:** [`cloud`](../controllers/cloud.md)
- **Tool:** **Prowler**, https://github.com/prowler-cloud/prowler
- **Status:** ✅ implemented (Google Cloud, AWS, Azure)
- **Target:** a cloud account (`AccountTarget`)
- **License / terms:** **Apache-2.0** (permissive), the tool and its check metadata. Run via
  **exec**. The command-line tool has no terms of use of its own; Prowler's hosted service, which
  this scanner does not use, has separate terms.

## What it does

Runs `prowler gcp` against the project a Google Cloud account names, `prowler aws` against an AWS
account, or `prowler azure` against an Azure subscription, limited to one compliance framework, and
reads its OCSF output. A failed check becomes a finding at the resource Prowler names; a passed one
counts as decided.

| Provider | Framework by default | Scoped by |
|---|---|---|
| `gcp` | `cis_5.0_gcp` | `--project-id` |
| `aws` | `cis_7.0_aws` | the credentials' account, confirmed first, and `--region` when the component claims regions |
| `azure` | `cis_6.0_azure` | `--subscription-id` |

`compliance` replaces the default for the accounts of the cloud its suffix names, `_gcp`, `_aws` or
`_azure`.

The framework's checks are listed first, with `prowler <gcp|aws|azure> --list-checks-json`, so the
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
   where the credentials reach that far. A denial there is outside the declared project, and the
   measured-against line names it, as `organization: not read, denied logging.sinks.list`. It leaves
   no check unread, except the essential-contacts check, which reads nothing else. An API the
   project has not enabled is named as that, `essentialcontacts.googleapis.com disabled`, as Google
   answers it with the same 403.

### AWS

1. **The caller is confirmed.** Before Prowler runs, the scanner asks STS `GetCallerIdentity` which
   identity the credentials are. Prowler checks whichever account the credentials reach, so an
   identity in another account is an error naming both accounts.
2. **A permission preflight, where the credentials may make one.** The scanner asks IAM `GetRole`
   for the ARN, with its path, of the role the session assumed, then `SimulatePrincipalPolicy`
   which of the actions Prowler's services call the role's policies allow. A resource's own policy
   is not weighed, so the log catches those. Credentials that may not call either, as a read-only
   role commonly may not, leave the log alone to name the denials, and neither case is an error.
   The measured-against line says which ran, `permissions: simulated before the scan, then read
   from Prowler's log` or `permissions: read from Prowler's log`.
3. **The log is read for denied calls**, after a preflight too. A denied call is one a service
   module logged as failing with `AccessDenied`, `AccessDeniedException`, `AuthorizationError`
   (SNS) or `UnauthorizedOperation` (EC2), and a throttled call is not one. The reason is the
   action the error names, `denied kms:DescribeKey`, or the call where it names none, `denied the
   GetEventSelectors call`.
4. **A denial is judged per check.** Prowler starts a service by making every call its module
   makes, so a denied call leaves every check of the service in doubt, and is often one some of
   them do not need. A check of a denied service with no pass or fail is unread, and its result
   discarded. A check with one keeps its findings, is marked partly read, and is not counted as
   decided.
5. **The mutelist is emptied.** Given none, Prowler mutes the resources AWS Control Tower creates.
   The scanner passes a mutelist holding `Mutelist: {}`, so every finding reaches the report, where
   Draugr's excludes suppress one with a reason.

A service with no known action is left out of the simulation, and its denials come from the log
alone.

### Azure

1. **The credential is chosen from the environment**: the three service principal variables, then
   `IDENTITY_ENDPOINT`, then the `az login` session, as [the control](../controllers/cloud.md) lists
   them. The scanner's own requests use the same credential as Prowler.
2. **The subscription is confirmed.** Before Prowler runs, the scanner asks Azure Resource Manager for
   the subscription. One the credentials cannot read, or one that does not exist, is an error naming it.
3. **A permission preflight.** The scanner lists `Microsoft.Authorization/permissions` on the
   subscription and compares it with the actions Prowler's services call. Deny assignments are outside
   that answer. Credentials holding none of the actions are an error: Azure lets them see the
   subscription and answers with an empty list, Prowler logs no refusal, and the checks that look for
   something absent fail. A refused list is no error, and the measured-against line says so:
   `permissions: read from Prowler's log; Azure refused the preflight`. Otherwise it reads
   `permissions: listed before the scan, then read from Prowler's log`. Prowler's Azure base class
   discards what its worker threads raise, so a denial there may leave no log line, and the preflight
   carries more weight than on the other clouds.
4. **The log is read for refused and failed reads**, at `WARNING` rather than the `ERROR` the other clouds
   use. A refused read is `AuthorizationFailed`, a `Forbidden` code, or a 403 from Microsoft Graph, in a
   line from a service module. A failed read ended with no answer: a dropped connection, named as
   `read failed, RemoteProtocolError`, or a 429 or 5xx from Microsoft Graph, named as
   `read failed, HTTP 503`. Its service's checks are treated as a denied service's are, because the same
   login may get a different answer on the next run. Prowler logs a Key Vault data-plane read that failed
   as a warning, `has no access policy configured for keyvault`, for any HTTP error, and the scanner
   reads it as a denial of the `keyvault-data` group. `LOG_LEVEL` in the environment overrides
   `--log-level`, so `ERROR` or `CRITICAL` hides those warnings, and the measured-against line says so.
5. **A denial is judged per check**, as on AWS. Only `keyvault_key_rotation_enabled` reads the Key Vault
   data plane, so a locked vault leaves that check partly read and the service's others alone. That
   check fails each key whose rotation policy it could not read, so a failure on a key in a locked
   vault says nothing about the key.
6. **A `MANUAL` result is not a verdict.** Prowler's Azure checks return it when a read failed. A check
   with no pass or fail as well is unread, with the reason `Prowler could not evaluate it`.
7. **Some checks never run**, and the measured-against line names each as `not run`:
   - `--excluded-service app` is on every run. Prowler's App service reads function host keys and
     application settings in its constructor whenever any `app_*` check runs, and those are secrets the
     scan has no need of. `cis_6.0_azure` holds no `app_*` check. A `compliance` framework that does
     reports those checks with no result.
   - `--excluded-service entra` is on every run. Prowler's Entra service reads every user in the
     tenant, and each one's MFA registration, whichever subscription the scan names: a row per person
     in the organization, from a scan pointed at one subscription. The five `entra_*` checks in
     `cis_6.0_azure` are listed as not run, and the tenant's directory is not read.
   - `--excluded-check network_public_ip_shodan` is on every run. Given a Shodan key in Prowler's own
     configuration, that check sends each of the subscription's public IP addresses to Shodan, so it
     never runs, whichever framework selects it. `cis_6.0_azure` holds it and the five `entra_*` checks,
     so that framework's coverage reads six short of its check list at most.

A service with no action the preflight can ask about is left out, and its denials come from the log
alone: `keyvault-data`, and the auto provisioning settings of `defender`.

Findings in a component's claimed regions are kept, matching zones of a region; a component that
claims the whole account gets every finding, including those with no region. On AWS, Prowler files a
finding about the account itself under the first region it audited, so the IAM, account and
Organizations checks and the CloudWatch metric-filter alarms (`cloudwatch_log_metric_filter_*`,
`cloudwatch_changes_*`) go to the component claiming the whole account, whatever region they carry.
CloudTrail's findings stay in the trail's home region. On Azure, a finding with no location, which
Prowler writes as `global`, goes to the component claiming the whole subscription.

## Mapping

| Prowler | SARIF |
|---|---|
| `status_code: FAIL` | a result; `PASS` is decided, `MANUAL` neither |
| `severity` critical, high | `error`, score 9.5, 8.0 |
| `severity` medium | `warning`, score 5.5 |
| `severity` low, informational | `note`, score 2.0, 0 |
| `metadata.event_code` | rule `prowler/<check>` |
| `resources[0].uid` | the location: an ARN on AWS, or `aws/<account>/<region>` for a region's setting whose ARN names no resource (Security Hub, EBS encryption by default, a Config recorder, a multi-region trail); a resource ID on Azure |
| `remediation.desc`, `references[0]` | the rule's description and help link |
| `unmapped.compliance["CIS-5.0"]`, `["CIS-6.0"]`, `["CIS-7.0"]` | the rule's taxa |

`resources[].data` is never read: it carries what a service returned, which can include secrets
such as function keys.

## Installation

`draugr tools install` does not fetch Prowler. Install it with `pip install prowler` (Python 3.10 to 3.13), or
run the `prowlercloud/prowler` container image with `prowler` on `PATH`. `draugr doctor` names both.

Which checks a denied read leaves unread is decided by tables taken from one Prowler release. With
another release, a check whose reads changed can have its result discarded though it ran, or kept
though a read it needs was denied. `draugr doctor` names the release and the `pip install` that
matches it.

## Permissions

**Google Cloud.** Prowler documents `roles/viewer` and `roles/serviceusage.serviceUsageConsumer` on
the project, plus `storage.buckets.getIamPolicy`, which Viewer lacks. A narrower grant works, and
what it cannot read is reported unread rather than passed. Credentials of a person rather than a
service account need a quota project: `gcloud auth application-default set-quota-project <project>`.

**AWS.** Prowler documents the `SecurityAudit` and `ViewOnlyAccess` managed policies, plus its own
`prowler-additions-policy`. `SecurityAudit` includes `iam:GetRole` and `iam:SimulatePrincipalPolicy`,
which the preflight calls. A narrower grant works, and a check whose read it denies is reported unread
or partly read rather than passed.

**Azure.** Assign `Reader` on the subscription and nothing else. No Graph permission is needed, and
leave out Prowler's `ProwlerRole`: it grants function host key access for checks that do not run. A
Key Vault's keys need a grant on the vault itself, by access policy or a data role, or
`keyvault_key_rotation_enabled` reads as partly read.

## Links

- Prowler: https://github.com/prowler-cloud/prowler
- OCSF output: https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/reporting/
- `testIamPermissions`: https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions
- `GetCallerIdentity`: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
- `SimulatePrincipalPolicy`: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
- Prowler's AWS permissions: https://docs.prowler.com/user-guide/providers/aws/authentication
- Prowler's Azure permissions: https://docs.prowler.com/user-guide/providers/azure/authentication
- Azure permissions: https://learn.microsoft.com/en-us/rest/api/authorization/permissions

## Notes

- Integration mode: **exec**. `prowler` must be on `PATH`, and the credentials must reach the
  account: Application Default Credentials on Google Cloud, the AWS SDK's default chain on AWS
  (`AWS_PROFILE`, the shared config and credentials files, an SSO session, or an instance or task
  role), and on Azure the credential the environment declares.
- Draugr's own AWS calls are STS `GetCallerIdentity` and IAM `GetRole` and
  `SimulatePrincipalPolicy`, made with the same credential chain Prowler reads. Its own Azure calls are
  Azure Resource Manager's subscription read and permissions list, with the credential Prowler is told
  to use.
- Azure's public cloud only. The scanner leaves Prowler's `--azure-region` at `AzureCloud`, and asks
  `management.azure.com`.
- Prowler's version is read with its update check unable to connect: `prowler --version` otherwise
  asks api.github.com for the newest release on every scan.
- Prowler sends no telemetry. Its integrations with a hosted dashboard, Shodan and Slack are opt-in,
  and this scanner turns none of them on.

## Data

The checks ship with Prowler. The scan reads the account through the provider's APIs, which are the
target rather than a data source: on Google Cloud, `cloudresourcemanager.googleapis.com` for the
preflight and each service's API for its checks; on AWS, `sts.<region>.amazonaws.com` for the caller,
`iam.amazonaws.com` for the preflight and each service's endpoint for its checks.

An Azure scan contacts these hosts on every run, and nothing is cached between runs:

| Host | What it reads |
|---|---|
| `login.microsoftonline.com` | the credential's token |
| `management.azure.com` | the preflight, and the service reads of every check |
| `graph.microsoft.com` | the tenant's default domain, which Prowler reads when it starts |
| `*.vault.azure.net` | each key's rotation policy, from the vault that holds it |
| `api.loganalytics.io` | Log Analytics, for checks outside `cis_6.0_azure` |

A `compliance` framework that includes the checks below makes the scan contact these hosts as well.
The default framework includes none of them.

| Host | Check | What it reads |
|---|---|---|
| `github.com`, `gitlab.com` | `codepipeline_project_repo_private` | whether a pipeline's source repository answers an anonymous request |
| `ip-ranges.amazonaws.com` | `route53_dangling_ip_subdomain_takeover` | the address ranges AWS publishes |
| `*.s3.<region>.amazonaws.com` | the Lambda and ECR checks that read function code or image layers | the presigned link the API returns |
