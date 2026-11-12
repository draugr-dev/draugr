# Controller: `cloud` (CIS cloud foundations benchmarks)

- **Industry term:** CSPM / cloud posture
- **Scope:** component
- **Status:** ✅ implemented (Google Cloud, AWS, Azure)
- **Scanners:** [`prowler`](../scanners/prowler.md) (default)
- **Resource:** a component's `cloud:` entry, naming an account declared under `accounts:`

## What it does

Checks the cloud account a component runs in against the provider's CIS foundations benchmark, by
reading the live account through the provider's APIs. Where the [`iac`](iac.md) control reads the
Terraform that describes an account, this one reads what the account is.

**Each account is declared once, under `accounts:`**, with its provider and its identifier there:
`project` for a Google Cloud project, `account` for an AWS account's 12-digit ID, `subscription` for
an Azure subscription's GUID. Components refer to an account by name:

```yaml
accounts:
  shop-prod:
    provider: gcp
    project: shop-prod-4821
  web-prod:
    provider: aws
    account: "123456789012"
  console-prod:
    provider: azure
    subscription: 00000000-0000-0000-0000-000000000000
components:
  - name: platform
    cloud:
      - account: shop-prod
  - name: api
    cloud:
      - account: shop-prod
        regions: [us-central1]
  - name: web
    cloud:
      - account: web-prod
  - name: console
    cloud:
      - account: console-prod
```

**Findings that belong to no region go to the component that declares the whole account.** A
project's IAM policy, its audit logging and its log sinks are about the account, so they are filed
once, against `platform` above. A component that names `regions` gets the findings about resources
in those regions and their zones. A component runs in one account.

On AWS, `regions` also narrows the scan: Prowler reads only those regions. The findings about the
account itself, IAM, the account's contacts, Organizations and the CloudWatch alarms over its trail,
go to the component claiming the whole account, whatever region Prowler files them under.

On Azure, `regions` takes location names such as `eastus` and narrows the findings alone: Prowler reads
the whole subscription.

**The account is reached with the credentials in the environment.**

- **Google Cloud:** the Application Default Credentials every Google client reads,
  `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth application-default login`, or the metadata server
  of the machine the scan runs on. Read access is enough: `roles/viewer` and
  `roles/serviceusage.serviceUsageConsumer` on the project, and `storage.buckets.getIamPolicy`,
  which Viewer lacks, cover every check.
- **AWS:** the default credential chain every AWS SDK reads, `AWS_PROFILE`, the shared config and
  credentials files, an SSO session, or an instance or task role. Attach the `SecurityAudit` and
  `ViewOnlyAccess` managed policies and Prowler's `prowler-additions-policy`. `SecurityAudit`
  includes `iam:GetRole` and `iam:SimulatePrincipalPolicy`, which let the scan check permissions
  before Prowler runs.
- **Azure:** one credential, chosen from the environment. `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and
  `AZURE_CLIENT_SECRET` together are a service principal. `IDENTITY_ENDPOINT` is a managed identity on
  App Service, Functions, Container Apps or Arc. Otherwise the scan uses the `az login` session, which
  covers a federated sign-in and, on a virtual machine, `az login --identity`, or workload identity
  where `AZURE_FEDERATED_TOKEN_FILE` is set. Assign `Reader` on the subscription. No Microsoft Graph
  permission is needed: the Entra checks, which read the tenant's directory, do not run. Azure's public
  cloud only.

`draugr doctor` checks each declared account: on Google Cloud that the credentials can read the
project, on AWS that they are an identity in the declared account, on Azure that they can read the
subscription and hold an action on it.

## What a run reports

**An account the scan cannot reach fails the run**, as a target not reached, named under **Errors**
as `account gcp/<project>`, `account aws/<id>` or `account azure/<subscription>`: no credentials, a
project or subscription that does not exist or one the credentials hold no role on, Azure credentials
holding none of the actions the checks read, or AWS credentials whose identity is in another account.

**On Google Cloud, a service whose reads are denied leaves its checks unread**, and the run goes on.
Before Prowler runs, the scanner lists the permissions the checks need and asks Google which of them
the credentials hold. Each service missing one is a row under **Caveats**, with the number of checks
that read it and the permission that was missing:

```
CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  unread-checks · api
    compute  16 checks unread · denied compute.instances.list
```

Prowler's result for an unread check is discarded, whatever it was. Prowler does not separate a check
it could not evaluate from one it found clean, so a denied read can come back as a pass.
`report.json` lists every unread check under `unreadChecks[]`.

**On AWS, a denial is judged per check**, and the run goes on. A denied call is one action, which
some checks of the service do not need, so a check that returned results keeps them:

- A check of a denied service with **no pass or fail** is unread, and its result discarded.
- A check **with a pass or a fail** keeps its findings and is **partly read**. It is not counted as
  decided, because the denied read may have held more.

Both are rows under **Caveats**, one per service, with the action that was denied, or the call
where AWS's error does not name the action:

```
CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  unread-checks · web
    account         2 checks unread · denied account:GetContactInformation
    cloudtrail      18 checks unread · 3 checks partly read · denied the GetEventSelectors call
    efs             1 check partly read · denied elasticfilesystem:DescribeAccessPoints
```

The denials come from two places. Before Prowler runs, where the credentials may ask, the scanner
asks IAM's policy simulator which of the actions Prowler's services call the role's policies allow.
After it runs, Prowler's log names the calls that were denied, including those a resource's own
policy refused. The measured-against line says which ran, as `permissions: simulated before the
scan, then read from Prowler's log`, or as `permissions: read from Prowler's log` where the
credentials may not call `iam:GetRole` or `iam:SimulatePrincipalPolicy`; grant both to simulate
before the scan. `report.json` lists the partly read checks under `unreadChecks[].partlyRead`.

Grant the action a row names and scan again: a check clears once none of the services it reads has
a denial. A partly read check keeps its findings, and a pass there can rest on a read that was
refused.

**On Azure, a denial is judged per check, as on AWS.** The measured-against line says where the
denials came from: `permissions: listed before the scan, then read from Prowler's log`, or
`permissions: read from Prowler's log; Azure refused the preflight` where the credentials may not list
them. A Key Vault's keys are granted on the vault, not the subscription, so a refused rotation policy
shows only in the log. It is a row under `keyvault-data`, and the rotation check marks every key in
that vault as partly read.

A read that ended with no answer, such as a dropped connection, is treated as a denial and named
`read failed, RemoteProtocolError`. A check Prowler reports as `MANUAL`, with no pass or fail, is unread
with the reason `Prowler could not evaluate it`. A later run on the same login may answer either one.

Three kinds of check never run on Azure, and the measured-against line names each as `not run`: every
`entra_*` check, every `app_*` check, and `network_public_ip_shodan`. The Entra checks read every user
in the tenant whichever subscription you name. `cis_6.0_azure` holds five Entra checks and the Shodan
check, so its coverage reads six short of its check list at most. [The scanner](../scanners/prowler.md)
says why the other two never run.

**Coverage is stated in the measured-against line**: the framework, how many of its checks were
decided, and the scope.

## Configuration

```yaml
config:
  controls:
    cloud:
      enabled: true
      prowler:
        compliance: cis_4.0_gcp   # optional; cis_5.0_gcp, cis_7.0_aws and cis_6.0_azure by default
```

`compliance` names any framework `prowler <gcp|aws|azure> --list-compliance` prints, and applies to the
accounts of the cloud its suffix names. Accounts on the other clouds are checked against their default.
The framework decides which checks run, and the coverage figure counts them.

## Links

- Prowler: https://github.com/prowler-cloud/prowler
- CIS Google Cloud Platform Foundation Benchmark: https://www.cisecurity.org/benchmark/google_cloud_computing_platform
- CIS Amazon Web Services Foundations Benchmark: https://www.cisecurity.org/benchmark/amazon_web_services
- CIS Microsoft Azure Foundations Benchmark: https://www.cisecurity.org/benchmark/azure

## Notes

- The scanner reports a Prowler check as `prowler/<check>`, with the benchmark's requirement IDs as
  its taxa.
