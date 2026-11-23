---
title: "kics"
description: "A second misconfiguration scanner for the iac control, Checkmarx KICS, run from its image with no network, beside trivy-config."
section: Scanners
order: 175
---

# Scanner: `kics` (IaC misconfiguration, opt-in)

- **Control:** [`iac`](../controllers/iac.md), opt-in. [`trivy-config`](trivy-config.md) stays the
  default and runs alone unless a descriptor turns this on.
- **Tool:** Checkmarx **KICS** 2.2.1, https://kics.io, run from its container image
  `checkmarx/kics:v2.2.1@sha256:49ccc54b6ae7f5d5fc95e96f8f95c18c57f3bba047ab611a03d80792bdff6757`
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`), checked out at the scanned revision
- **License / terms:** **Apache-2.0**, the `LICENSE` at the root of
  [Checkmarx/kics](https://github.com/Checkmarx/kics) at the v2.2.1 tag, which covers the binary
  and its queries. Run via **exec**, as a container Draugr starts and does not distribute. KICS is a
  tool you run, not a service: there is no account, key or usage tier. The image comes from Docker
  Hub, whose terms govern the pull, which you make yourself.

## What it does

KICS checks Terraform, Kubernetes manifests, Helm charts, CloudFormation, ARM templates, Ansible,
Dockerfiles and more against its own queries, of which the v2.2.1 image holds 1,813. It reads
mostly the same files as Trivy and reports a different set of settings. Over 153 public
repositories holding IaC (https://github.com/draugr-dev/draugr/issues/2165), KICS v2.2.0 reported
25,519 findings Trivy 0.76.1 did not, most of them Kubernetes workload settings such as service
account tokens, namespaces, privilege escalation and seccomp, and Trivy reported 11,935 that KICS
did not. Neither replaces the other, so this scanner runs beside `trivy-config` and the two sets of
findings arrive as one.

```yaml
config:
  controls:
    iac:
      enabled: true
      kics:
        enabled: true      # trivy-config still runs; add `trivyConfig: { enabled: false }` to run KICS alone
```

## Running

Draugr runs the image for each repository, with the checkout mounted read-only and the report on a
mount of its own:

```
docker run --rm --pull never --network none --cap-drop ALL --security-opt no-new-privileges \
  --user <uid>:<gid> \
  --mount type=bind,source=<checkout>,target=/src,readonly \
  --mount type=bind,source=<report dir>,target=/report \
  checkmarx/kics:v2.2.1@sha256:49cc… \
  scan --path /src --output-path /report --output-name results --report-formats json \
  --disable-secrets --exclude-paths /src/.git --exclude-gitignore --no-progress --ci --no-color
```

- **`--network none`.** KICS asks `api.github.com` for its newest release every time it starts a
  scan, and no flag turns that off. With no network, the
  request fails, KICS scans the same, and nothing in the container can send what it read anywhere.
- **`--pull never`.** The scan runs the image this machine already holds at the pinned digest, and
  never downloads one. `draugr doctor` says whether it is there.
- **The digest.** A tag can be pushed again. The digest names one build of KICS and its queries,
  so a result, and a cached result, stands for exactly that build. It is the digest of the
  multi-platform index Checkmarx published for v2.2.1, so the one pin serves amd64 and arm64.
- **`--user`.** KICS writes its report as you, so Draugr can read it and remove it.
- **`--disable-secrets`.** KICS's secret search is a regex pass over every file it reads. That is
  the [`secrets`](../controllers/secrets.md) control's job, and left on it adds findings `iac` does
  not own.
- **`--exclude-paths /src/.git`.** KICS reads `.git` like any other directory.
- **`--exclude-gitignore`.** Despite its name, this turns off KICS's default of skipping what a
  `.gitignore` lists, so KICS reads the files `trivy-config` reads. Skipping a file because a
  `.gitignore` names it is a decision the descriptor did not make.

### Exit codes

KICS exits non-zero when it finds something, with a code for the most severe result, so the exit
code alone does not say whether the run failed. Its documentation, [Exit Status
Code](https://docs.kics.io/latest/results/#exit-status-code), lists:

| Code | KICS documents it as | Draugr |
|---|---|---|
| 0 | no results | success, when the report was written |
| 20, 30, 40, 50, 60 | INFO, LOW, MEDIUM, HIGH, CRITICAL results found | success, when the report was written |
| 70 | remediation error | error |
| 126 | engine error | error |
| 130 | interrupted by a signal | error |

Any other code is an error too, such as Docker's own 125 when it could not start the container. A result
code with no report is an error, so a run that stopped half way cannot pass for one that found
nothing.

## Severity

Each finding takes the severity KICS states for its query, never lower:

| KICS | Draugr's band | SARIF level |
|---|---|---|
| CRITICAL | critical | error |
| HIGH | high | error |
| MEDIUM | medium | warning |
| LOW | low | note |
| INFO, TRACE | low | note |

Draugr has no band below low, so INFO ranks as low, the lowest there is. A severity KICS does not
document ranks high. The row shows KICS's own word, as `severity HIGH`. The priority (P1 to P4) then
comes from the component's exposure and criticality, as for every finding.

## Probes and tags

Every KICS query runs when KICS is turned on, the probe and tag queries included. Of the 25,519
findings in that study, 5,196 were probe checks (liveness and readiness) and 1,405 metadata and tag checks.
They are true and carry less risk than the rest, and each fires once per workload or resource.
Leaving them out by default would set findings aside without a decision in the descriptor, so they
are on, and the descriptor is where you decide otherwise.

They rank as KICS rates them:

| Query | KICS id | KICS severity |
|---|---|---|
| Readiness Probe Is Not Configured (Kubernetes) | `a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3` | MEDIUM |
| Readiness Probe Is Not Configured (Terraform) | `8657197e-3f87-4694-892b-8144701d83c1` | MEDIUM |
| Liveness Probe Is Not Defined (Kubernetes) | `ade74944-a674-4e00-859e-c6eab5bde441` | INFO |
| Liveness Probe Is Not Defined (Terraform) | `5b6d53dd-3ba3-4269-b4d7-f82e880e43c3` | INFO |
| Resource Not Using Tags (Terraform) | `e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10` | INFO |
| Lambda Function Without Tags (CloudFormation, Ansible) | `8df8e857-bd59-44fa-9f4c-d77594b95b46`, `265d9725-2fb8-42a2-bc57-3279c5db82d5` | LOW |
| EFS Without Tags (CloudFormation, Ansible) | `08e39832-5e42-4304-98a0-aa5b43393162`, `b8a9852c-9943-4973-b8d5-77dae9352851` | LOW |
| Cosmos DB Account Without Tags (Terraform, Ansible) | `56dad03e-e94f-4dd6-93a4-c253a03ff7a0`, `23a4dc83-4959-4d99-8056-8e051a82bc1e` | LOW |
| Serverless Function Without Tags (CloudFormation, Serverless) | `a71ecabe-03b6-456a-b3bc-d1a39aa20c98`, `f99d3482-fa8c-4f79-bad9-35212dded164` | LOW |
| Metadata Label Is Invalid (Kubernetes, Terraform) | `1123031a-f921-4c5b-bd86-ef354ecfd37a`, `bc3dabb6-fd50-40f8-b9ba-7429c9f1fb0e` | LOW |

On a public, critical component a readiness probe finding is P2 and a liveness probe finding P3.

They fold. The first screen gives one row to the findings of one rule at one priority in one
repository, so a probe query that fires on every container takes one row, not one per container.
Over two repositories of one component, holding four Deployments and five containers between them,
the readiness query's five findings took two rows, one per repository:

```
  P2  medium    a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3 · 4 findings
      Readiness Probe Is Not Configured
      Deployment "api"
      repository a2165/fold · scanner kics · fix change the infrastructure
      k8s/apps.yaml:16 · severity MEDIUM

  P2  medium    a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3
      Readiness Probe Is Not Configured
      Deployment "web"
      repository a2165/tree · scanner kics · fix change the infrastructure
      k8s/web.yaml:17 · severity MEDIUM
```

To set them aside, say so in the descriptor. They stay in the report, suppressed, with your
reason:

```yaml
config:
  exclude:
    - rules:
        - a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3   # readiness probe, Kubernetes
        - 8657197e-3f87-4694-892b-8144701d83c1   # readiness probe, Terraform
        - ade74944-a674-4e00-859e-c6eab5bde441   # liveness probe, Kubernetes
        - 5b6d53dd-3ba3-4269-b4d7-f82e880e43c3   # liveness probe, Terraform
        - e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10   # resource not using tags
      reason: "Probes and tags are reviewed in the platform checklist, not gated here"
```

## Counted once

Where KICS and Trivy flag the same setting on the same resource, the finding is counted once. Both
stay in the report, each with its own rule id and severity, and the row you act on names the other
tool:

```
  P1  high      KSV-0017
      Privileged
      Container 'web' of Deployment 'web' should set 'securityContext.privileged' to false
      repository a2165/tree · scanner trivy · fix change the infrastructure
      k8s/web.yaml:17 · also found by KICS
```

Where the two disagree, the stronger rating is counted: KICS rates privilege escalation HIGH and
Trivy's `KSV-0001` medium, so the KICS copy is the one counted. An exclusion written against either
copy covers both.

The two tools' rule ids share nothing, a UUID against `KSV-0017`, so the match comes from a table
in Draugr. It names, for each KICS query that
tests the setting a Trivy check tests, that check, and Draugr counts the two findings once when:

- the KICS query and the Trivy check are a pair in the table,
- both are in the same file of the same repository and component, and
- KICS's line falls inside the lines Trivy reported. Trivy reports a Kubernetes container's checks
  at the container's lines and KICS reports the setting at one line inside it, which is what tells
  two containers in one file apart.

A finding that could match two copies on the other side, such as a KICS query reported twice inside
one Trivy region, is matched to neither and counted on its own. A pair missing from the table costs a
duplicate, counted twice and visible, where a wrong pair would count one setting under another, so
the table holds only pairs checked in both tools' rule text and seen on one resource. It covers
Kubernetes container and pod settings, AWS Terraform resources and Dockerfiles; the file lists
each pair. Trivy's ids are compared without dashes or zero padding, so `KSV017`, `AVD-KSV-0017`
and `KSV-0017` are one id.

## Left out

- **Secrets.** KICS's secret search is off (`--disable-secrets`).
- **`.git`.** Excluded (`--exclude-paths`).
- **Experimental queries.** KICS leaves them out by default and Draugr does not turn them on.
- **`kics-scan` comments.** KICS obeys a comment in the scanned file that tells it to skip the file
  (`kics-scan ignore`), a block (`ignore-block`), a line (`ignore-line`) or some queries
  (`disable=<id>`, `enable=<id>`), as its documentation describes under *Using commands on scanned files as comments*
  (https://docs.kics.io/latest/running-kics/), and has no flag to stop. Its report names no file and
  no finding the comment skipped. Draugr reads the checkout for the comments on every run and records
  each file holding one as not checked by KICS, with the reason
  `kics-scan ignore-line comment; KICS did not check what it marks`, so a skip someone wrote in a
  file is visible rather than gone. Where [`trivy-config`](trivy-config.md) checked the file, the
  file is not unread for `iac`: Trivy still checked what the
  comment marks, and the report's evidence lists the gap as KICS's alone, as
  `iac: kics · shop · k8s/web.yaml · kics-scan ignore-line comment; …`. Where Trivy did not check
  it, the file is unread for `iac`. `config.exclude` is the way to set a finding aside and keep it.
- **`lines_ignored` in KICS's report is not read.** KICS v2.2.1 counts every ordinary comment line
  of a YAML file or a Dockerfile there, alongside the lines a `kics-scan` comment skips, as the
  [source of its YAML comment handling](https://github.com/Checkmarx/kics/blob/v2.2.1/pkg/model/comment_yaml.go)
  shows. A manifest holding a plain `#` note and no directive counts lines ignored while KICS checked
  all of it, so the count cannot say whether anything was skipped.
- Files KICS could not scan, and queries that failed to run, are reported unread against the
  repository root the same way, from the counts in its report, and the `iac` control lists each
  under [unread](../controllers/iac.md#unread).

## Cost

KICS uses more processor time than Trivy on most Kubernetes trees. On five timed targets, KICS
v2.2.0 used three to six times Trivy's CPU time on four and about a third of it on the fifth (median
of three runs each, in seconds):

| Target | Trivy CPU | KICS CPU | Trivy wall | KICS wall |
|---|---|---|---|---|
| `kubernetes/kubernetes` | 170.8 | 548.6 | 126.8 | 114.4 |
| `istio/istio` | 29.4 | 134.5 | 19.3 | 28.2 |
| `GoogleCloudPlatform/cloud-foundation-fabric` | 11.6 | 63.8 | 5.7 | 12.0 |
| `traefik/traefik` | 18.2 | 75.5 | 11.2 | 13.5 |
| `terraform-google-modules/terraform-google-kubernetes-engine` | 159.1 | 48.4 | 86.0 | 8.4 |

Those runs had 32 cores, so KICS's wall time stayed close to Trivy's. On a CI runner with two
cores the extra CPU time becomes wall time, and turning KICS on can add minutes to a scan of a
large Kubernetes repository.

## Saga options

`enabled` only. KICS's own filters (`--exclude-queries`, `--exclude-severities`, `--fail-on`) are not
exposed: each drops findings inside the tool, where Draugr never sees them. Use `config.exclude`.

## Setup

KICS needs Docker and the pinned image:

```console
$ docker pull checkmarx/kics:v2.2.1@sha256:49ccc54b6ae7f5d5fc95e96f8f95c18c57f3bba047ab611a03d80792bdff6757
```

`draugr tools install` does not pull it, and says so with this command when asked for `kics`.
`draugr doctor` with a descriptor that turns KICS on says whether Docker is on `PATH` and whether
the daemon holds the image at that digest, and names this command when it does not. A scan
refuses to start KICS without it rather than pulling it.

## Data

KICS reads nothing from outside. Its queries are in the image, and the container runs with no
network, so the release check it makes on every run goes nowhere and nothing it read can leave the
machine. The image itself is the one thing fetched, by you, with `docker pull`.

## Links

- KICS: https://kics.io, source https://github.com/Checkmarx/kics
- Queries: https://docs.kics.io/latest/queries/all-queries/
- Results and exit codes: https://docs.kics.io/latest/results/
