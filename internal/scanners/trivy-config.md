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

Checks out the component's repository, then runs `trivy config --quiet --format sarif <dir>` to
find insecure **Infrastructure as Code**, Terraform, Kubernetes manifests, Dockerfiles, Helm
charts, CloudFormation, and more. See the [IaC glossary
entry](../../docs/reference/glossary.md#iac-scanning-infrastructure-as-code).

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

## Links

- Trivy misconfiguration scanning: https://trivy.dev/latest/docs/scanner/misconfiguration/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- Trivy exits 0 even when misconfigurations are found (no `--exit-code` set), so findings
  come from the SARIF report; the [`iac`](../controllers/iac.md) controller judges severity.
- Custom policy is where most of the value is. `checks` takes paths to your own Rego, so a rule
  encoding a mistake your team repeats gates the same way the built-in ones do.

## Data

The **checks bundle**, from `mirror.gcr.io/aquasec/trivy-checks`, Trivy's own default, warmed once
per run. With `--offline`, Draugr passes `--skip-check-update` and Trivy evaluates the checks built
into the pinned release. Misconfiguration scanning reads no vulnerability database.
