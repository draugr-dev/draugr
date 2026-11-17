---
title: "trivy-config"
description: "Misconfiguration scanning over Terraform, Kubernetes manifests, Dockerfiles and Helm, with your own Rego alongside the built-in policies."
section: Scanners
order: 170
---

# Scanner: `trivy-config` (IaC misconfiguration)

- **Control:** [`iac`](../controllers/iac.md)
- **Tool:** Aqua **Trivy** (config/misconfiguration mode), https://trivy.dev
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`), checked out at the scanned revision
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**. The bundled misconfig
  policies have their own terms.

## What it does

Checks out the component's repository and runs Trivy's misconfiguration checks over it to find
insecure **Infrastructure as Code**, Terraform, Kubernetes manifests, Dockerfiles, Helm charts,
CloudFormation, and more. See the [IaC glossary
entry](../../docs/reference/glossary.md#iac-scanning-infrastructure-as-code).

```
trivy fs --debug --scanners misconfig --format json --show-suppressed <dir>
trivy convert --quiet --format sarif <report>
```

The scan writes JSON because only the JSON lists what Trivy excluded, and `trivy convert` writes
the SARIF from that report without scanning again. `trivy fs` lists the repository's packages in
that report as well. Draugr removes them before converting, because `trivy convert` rejects the
whole report when one package is malformed, and `iac` reads no package. On a Trivy older than 0.53.0, which has no
`--show-suppressed`, the scan is `trivy config --debug --format sarif <dir>`.

Trivy reports these shortfalls only in its log, and exits 0 after each. Draugr reads the log for
them and reports each as [unread](../controllers/iac.md#unread):

| Terraform shortfall | Reported against | Reason |
|---|---|---|
| A module Trivy could not load | the file that calls it | `module "vpc" not loaded` |
| Module calls Trivy loaded and did not evaluate | the root module's directory | `32 of 33 module calls checked; "zbad" skipped` |

Trivy stops evaluating a module's calls after a fixed number of rounds, 32 in releases 0.69.3 to
0.76.1, and exits 0; the calls left over are loaded and never checked. A round evaluates at most
one call that no earlier round did, and a call evaluated again after another changes its inputs
spends a round too, so a module with fewer than 33 calls can reach the limit. The count of calls
includes any module Trivy could not load. A module below the root is named by its address, as in
`in module.wrap`.

### Downloaded modules

Trivy downloads a registry or git module and checks it with the configuration that calls it. It
reports what it finds at the module's own path, a file your repository does not hold. Draugr reports
the finding at the `module` block in your repository that brought the module in, the innermost one
if modules call modules. To fix it, set an input on that block or move to another version of the
module. Editing the module itself does not last. The console names the module on the finding's
location line:

```
main.tf:6 · module terraform-aws-modules/s3-bucket/aws 4.1.2
```

Two blocks calling the same module each keep their own finding.

Trivy renders a Helm chart with the chart's own values before checking it, and checks none of its
templates when the render fails:

| Helm shortfall | Reason |
|---|---|
| A dependency missing from `charts/` | `run helm dependency build; redis not in charts/` |
| A template reading a value the chart's values do not set | `set image.repository in values.yaml; read at templates/deployment.yaml:14` |
| A template's `required` or `fail` call | `templates/deployment.yaml:14: image.repository is required` |
| A `Chart.yaml` missing a field Helm requires | `add version` |
| A `Chart.yaml` that is not valid YAML | `not parsed: yaml: line 4: did not find expected ',' or ']'` |
| Any other error | `not rendered: ` and Helm's error |
| No error logged | `not rendered: no error given`; `helm template <chart>` prints why |

A chart's shortfall is reported against its Chart.yaml; a packaged chart against its archive.

### Images whose entrypoint drops root

`DS-0002`, *Image user should not be 'root'*, fires on a Dockerfile with no `USER`. Trivy reads only
the Dockerfile, and many images start as root on purpose: the entrypoint script chowns a volume or
creates a user, then starts the application as that user. Adding a `USER`, as the check asks, breaks
the script. Draugr reads the script, and where it starts the application as another user, the
finding carries that line as `privilegeDrop`, and its sentence names the line in place of Trivy's
request for a `USER`:

```
  P1  high      DS-0002
      Image user should not be 'root'
      entrypoint.sh:11 starts the application as another user with su-exec, so adding USER may break it
      scanner trivy · fix change the infrastructure
      Dockerfile:1
```

The finding keeps its band and still counts toward the gate. If the script does what you intend,
exclude DS-0002 for this Dockerfile with a reason; adding USER would break it. In `--view findings`
and in the fix list it comes after the other findings of its band, as described in
[how the list is ordered](../../docs/concepts/what-to-fix-first.md#how-the-list-is-ordered).

Draugr records the line only when all of these hold:

- The final stage's own `ENTRYPOINT`, or its `CMD` where it sets no `ENTRYPOINT`, names the script by
  path: absolute, or relative to `WORKDIR`. A shell form counts only where it is plain words. A name
  looked up on `PATH`, or an entrypoint the stage inherits from an earlier stage or its base image,
  does not count.
- The same stage copies the script in with `COPY` or `ADD` from the build context, read as the
  Dockerfile's directory and as the repository root. Where both hold a script at that path, both must
  qualify. A later copy that may write the path from another stage, a variable or a wildcard voids
  the copy, as does a later `RUN` naming the script with any command but `chmod`, `chown` or `chgrp`.
- The script has a `sh`, `bash`, `ash` or `dash` shebang, and every path a start as root takes ends
  in `exec` of `su-exec`, `gosu`, `s6-setuidgid`, `setpriv --reuid`, `runuser -u` or `chpst -u`, with
  a user that is not `root` or uid 0, or in `exit`. A test of `$(id -u)` against 0, such as
  `if [ "$(id -u)" = "0" ]`, decides which branch is root's; the other branch already runs as another
  user and is not read.
- Before the drop, a start as root runs only shell builtins and setup commands that return: file
  utilities such as `chown`, `mkdir` and `cp`, user tools such as `adduser` and `usermod`, and a drop
  command that runs a step as the user. Any other program might stay running as root beside the
  application, and so does anything sent to the background, sourced with `.`, or called through a
  shell function.

A script that cannot be read, a drop on only some of root's paths, or a drop to root leaves the
finding without the line, ranked with the rest of its band. Draugr does not read supervisord.conf,
so an image that drops root there still gets the finding as Trivy wrote it.

## Saga options

```yaml
config:
  controls:
    iac:
      trivyConfig:
        checks: [security/checks]   # your own Rego, alongside Trivy's built-in checks
        namespaces: [user]          # optional, derived from the checks' package lines when unset
```

| Option | What it does |
|---|---|
| `checks` | Paths to Rego check files or directories, one `--config-check` each. Relative to where Draugr runs. |
| `namespaces` | Top-level package names whose checks Trivy evaluates (`--check-namespaces`). Derived from `checks` when unset. |

Trivy evaluates a custom check only when the first name of its package is listed in
`--check-namespaces`, which lists no custom namespace by default. A check in
`package user.draugr.tags` runs under `namespaces: [user]`, and under neither `user.draugr` nor the
full package name.

With `checks` set and `namespaces` unset, the `iac` control reads the `package` line of every
check (each `.rego` file under a directory, `_test.rego` files excepted) and passes the first names
it finds. `draugr validate` prints the derived list for each component:

```console
$ draugr validate
✓ draugr.saga.yaml is valid
  · iac: component "api" evaluates the namespaces its checks declare
    trivyConfig.namespaces: [acme, user]
```

`draugr validate` and `draugr scan` refuse a set of checks the list cannot be derived from, naming
the file: a check with no `package` line, a directory holding no `.rego` file, a path that does not
exist. Setting `namespaces` turns the derivation off, and only the namespaces listed run.

Both add checks; neither removes findings. Trivy's `--severity` and `--ignorefile` are not
exposed. See `config.exclude` in the Saga reference for suppressing a finding in a way that stays
visible.

## Exclusions

A check that a line in `.trivyignore` excluded is reported suppressed with `origin: scanner`, the
file named as its source, and the statement as its reason where the rule gave one. Only a check the
file failed is carried across; Trivy applies the rule to the checks a file passed as well.

Two exclusions leave no record: an inline `#trivy:ignore:<id>` comment, which Trivy omits from
every output format, and any exclusion on a Trivy older than 0.53.0.
[`config.exclude`](../../docs/reference/saga-schema.md#configexclude) keeps the finding and its reason.

## Sentence

Beneath each finding's title, Draugr prints the sentence Trivy wrote for it, naming the object and the setting:

```
KSV-0017 · Privileged
Container 'api' of Pod 'demo-api' should set 'securityContext.privileged' to false
```

An action covering several findings shows the first sentence and how many others differ, as `· +2 more`. A sentence too long for the line keeps its end, where the setting is.

## Links

- Trivy misconfiguration scanning: https://trivy.dev/latest/docs/scanner/misconfiguration/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- Trivy exits 0 even when misconfigurations are found (no `--exit-code` set), so findings
  come from the report; the [`iac`](../controllers/iac.md) controller judges severity.
- Custom policy is where most of the value is. `checks` takes paths to your own Rego, so a rule
  encoding a mistake your team repeats gates the same way the built-in ones do.

## Data

The **checks bundle**, from `mirror.gcr.io/aquasec/trivy-checks`, Trivy's own default, warmed once
per run. With `--offline`, Draugr passes `--skip-check-update` and Trivy evaluates the checks built
into the pinned release. Misconfiguration scanning reads no vulnerability database.

Every `trivy fs` run passes `--offline-scan`, so this scanner resolves no `pom.xml` against a
remote Maven repository; see [`sca`](../controllers/sca.md#unread) for what Trivy then reads.

Every run, and the checks warm, passes `--skip-version-check` and `--disable-telemetry`, so Trivy
makes no version-check or telemetry request to `check.trivy.dev`. A Trivy older than 0.63.0 has
neither flag and makes no such request.

**Terraform modules**, from the host each `module` block's `source` names: `registry.terraform.io`
for a registry address, or the git host for a `git::` or GitHub source. A module with a local
`source` path is read from the checkout.

Trivy keeps the modules it downloads in `.aqua/cache` under the temporary directory, and reads that
cache before it fetches. Draugr runs each scan with `TMPDIR` set to a directory of its own and
removes it afterwards, so a scan reads only the modules it fetched itself. A module some other
program cached is never checked, a scan writes nothing another program reads, and a commit gives the
same findings on a laptop as on a fresh runner. Every scan fetches the modules it calls again. A
run takes `trivy-config` jobs one at a time.

With `--offline`, Draugr runs the scan through a closed proxy and allows git only the `file`
transport, so no module is downloaded and each remote one is reported unread, whatever an earlier
online scan downloaded. To scan what a module defines, vendor it into the repository, or allow
the hosts its `source` names.
