# Controller: `cloud` (CIS cloud foundations benchmarks)

- **Industry term:** CSPM / cloud posture
- **Scope:** component
- **Status:** ✅ implemented (Google Cloud)
- **Scanners:** [`prowler`](../scanners/prowler.md) (default)
- **Resource:** a component's `cloud:` entry, naming an account declared under `accounts:`

## What it does

Checks the cloud account a component runs in against the provider's CIS foundations benchmark, by
reading the live account through the provider's APIs. Where the [`iac`](iac.md) control reads the
Terraform that describes an account, this one reads what the account is.

**Each account is declared once, under `accounts:`**, with its provider and its identifier there.
Components refer to it by name:

```yaml
accounts:
  shop-prod:
    provider: gcp
    project: shop-prod-4821
components:
  - name: platform
    cloud:
      - account: shop-prod
  - name: api
    cloud:
      - account: shop-prod
        regions: [us-central1]
```

**Findings that belong to no region go to the component that declares the whole account.** A
project's IAM policy, its audit logging and its log sinks are about the account, so they are filed
once, against `platform` above. A component that names `regions` gets the findings about resources
in those regions and their zones. A component runs in one account.

**The account is reached with the credentials in the environment**, the Application Default
Credentials every Google client reads: `GOOGLE_APPLICATION_CREDENTIALS`, `gcloud auth
application-default login`, or the metadata server of the machine the scan runs on. Read access is
enough: `roles/viewer` and `roles/serviceusage.serviceUsageConsumer` on the project, and
`storage.buckets.getIamPolicy`, which Viewer lacks, cover every check. `draugr doctor` checks that
the credentials can read each declared account.

## What a run reports

**An account the credentials cannot read at all fails the run**, as a target not reached: no
credentials, a project that does not exist, or one the credentials hold no role on. It is named
under **Errors** as `account gcp/<project>`.

**A service whose reads are denied leaves its checks unread**, and the run goes on. Before Prowler
runs, the scanner lists the permissions the checks need and asks Google which of them the
credentials hold. Each service missing one is a row under **Caveats**, with the number of checks
that read it and the permission that was missing:

```
CAVEATS  do not fail the run
  Component  What     Caveat  Why
  api        compute  unread  16 checks · denied compute.instances.list
```

Prowler's result for an unread check is discarded, whatever it was. Prowler does not separate a check
it could not evaluate from one it found clean, so a denied read can come back as a pass.
`report.json` lists every unread check under `unreadChecks[]`.

**Coverage is stated in the measured-against line**: the framework, how many of its checks were
decided, and the scope.

## Configuration

```yaml
config:
  controls:
    cloud:
      enabled: true
      prowler:
        compliance: cis_4.0_gcp   # optional; cis_5.0_gcp by default
```

`compliance` names any framework `prowler gcp --list-compliance` prints. The framework decides which
checks run, and the coverage figure counts them.

## Links

- Prowler: https://github.com/prowler-cloud/prowler
- CIS Google Cloud Platform Foundation Benchmark: https://www.cisecurity.org/benchmark/google_cloud_computing_platform

## Notes

- Google Cloud is the provider Draugr checks today, so `provider: gcp` is the one `validate` accepts.
- The scanner reports a Prowler check as `prowler/<check>`, with the benchmark's requirement IDs as
  its taxa.
