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
trivy fs --scanners misconfig --format json --show-suppressed <dir>
trivy convert --quiet --format sarif <report>
```

The scan writes JSON because only the JSON lists what Trivy excluded, and `trivy convert` writes
the SARIF from that report without scanning again. On a Trivy older than 0.53.0, which has no
`--show-suppressed`, the scan is `trivy config --format sarif <dir>`.

The scan runs without `--quiet` because Trivy reports a Terraform module it could not load only in
its log, and exits 0. Each such module is reported under
[**Unread**](../controllers/iac.md#unread), named by the file that calls it.

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

**Terraform modules**, from the host each `module` block's `source` names: `registry.terraform.io`
for a registry address, or the git host for a `git::` or GitHub source. Trivy downloads them into
`.aqua/cache` under the system temporary directory. A module with a local `source` path is read from the checkout.

With `--offline`, Draugr runs the scan through a closed proxy and allows git only the `file`
transport, so no module is downloaded and each remote one is reported unread. To scan what a
module defines, vendor it into the repository, or allow the hosts its `source` names.
