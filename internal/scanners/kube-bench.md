# Scanner: `kube-bench` (CIS Kubernetes Benchmark)

- **Control:** [`infrastructure`](../controllers/infrastructure.md)
- **Tool:** Aqua **kube-bench** — https://github.com/aquasecurity/kube-bench
- **Status:** ✅ implemented (CIS section 5)
- **Target:** a Kubernetes cluster (`InfraTarget`)
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**.

## What it does

Runs

```
kube-bench run --json --targets policies --version <cluster version> [--config-dir <dir>]
```

and converts the result to SARIF.

**JSON rather than SARIF**: kube-bench has no SARIF output, so the conversion is ours. This is
the second such scanner after [`trivy-license`](trivy-license.md), and the reason
`tooladapter.Config` has a `Parse` hook.

## Draugr points it at the right cluster

kube-bench has no cluster flag: every `policies` check shells out to `kubectl`, which takes its
cluster from the environment. Left alone it would audit whatever context the machine happens to
have selected.

So the scanner resolves the context — the component's `ref`, or an explicit `context` setting —
copies the kubeconfig with that context made current, and points the tool at the copy through
`KUBECONFIG`. A copy rather than `kubectl config use-context`, which would change the operator's
own default as a side effect of running a scan. The temporary file is removed afterwards.

## Draugr supplies the Kubernetes version

kube-bench maps a Kubernetes version to a CIS benchmark, and detects that version by reading the
kubelet on the node it runs on. Off a node it cannot — and it does not say so. It falls back to
**1.18** and audits against **cis-1.6**, a benchmark for Kubernetes 1.16.

Measured against a v1.34 cluster:

| | benchmark used | findings |
|---|---|---|
| kube-bench detecting for itself | `cis-1.6` | 24 |
| version supplied by Draugr | `cis-1.12` | 29 |

A compliance report against the wrong standard is worse than no report, and this one arrives
quietly. So Draugr asks the cluster for its version — the same ambient kubeconfig the
`k8s-images` surveyor uses — and passes `--version`, letting kube-bench apply its own mapping.
Its mapping stays correct as it adds benchmarks; a table copied into Draugr would drift.

If the version cannot be determined, the scan **fails** rather than falling back. Set `version`
or `benchmark` to override. An explicit `benchmark` also covers the platform configs
(`gke-*`, `eks-*`, `rke2-*`) that no Kubernetes version maps to.

## Why only `policies`

kube-bench audits **the machine it runs on**, which decides what Draugr can honestly ask of it.

Sections 1–4 read node-local files: API server manifests, kubelet config, etcd data-dir
permissions. Off a cluster node those checks do not fail loudly — they find every file missing
and report a wall of failures about a cluster nobody looked at. Running them from a laptop or a
CI runner would produce a confident, entirely fictional verdict.

Section 5 is different. Every check shells out to `kubectl`, so it audits whatever cluster the
ambient kubeconfig points at, read-only, and means the same thing from anywhere. 35 of the 130
checks in `cis-1.9`.

Covering the rest means running kube-bench inside the cluster as a Job — Draugr creating
something in the system it is scanning. That is a different contract and is not done here.

## Mapping

| kube-bench status | SARIF level | Reported? |
|---|---|---|
| `FAIL`, scored | error | yes |
| `FAIL`, unscored | warning | yes |
| `WARN` | warning | yes |
| `PASS`, `INFO` | — | **no** |

A scored `FAIL` is the benchmark saying the cluster is out of compliance and counting it. `WARN`
means "manual check required" — a prompt for a human, not a defect; reporting it as an error
would make a clean cluster impossible.

Passing checks are not findings. A report listing three hundred passes buries the dozen failures,
which is the same reasoning that keeps permissive licences out of the `licenses` control.

Rule ids are `cis/<check number>`, e.g. `cis/5.1.1`, so a `config.exclude` rule reads the way the
benchmark does.

## Links

- kube-bench: https://github.com/aquasecurity/kube-bench
- Output format: https://github.com/aquasecurity/kube-bench/blob/main/docs/output.md
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes

## Notes

- Integration mode: **exec**. `kube-bench` and `kubectl` must both be on `PATH`, and the
  kubeconfig must reach the cluster. Both are declared, so `draugr doctor` reports either as
  missing before a scan rather than after. `draugr tools install` does not yet fetch them —
  [#386](https://github.com/draugr-dev/draugr/issues/386).
- **The kubectl requirement is kube-bench's, not Draugr's.** Its section 5 checks are shell
  scripts that invoke kubectl; exec'ing the tool means exec'ing kubectl. Implementing those
  checks natively against the Kubernetes API is
  [#389](https://github.com/draugr-dev/draugr/issues/389).
- Running the node-level sections needs kube-bench inside the cluster as a Job —
  [#388](https://github.com/draugr-dev/draugr/issues/388).
- Findings are located at the cluster (`kubernetes/<ref>`), not a file — that is what was
  assessed.
- kube-bench ships its own `cfg/` benchmark definitions and looks for them in
  `/etc/kube-bench/cfg` by default. Installing only the binary leaves them elsewhere, and the
  tool then fails with `config file is missing 'version_mapping' section`. Point the
  `configDir` setting at the directory to resolve it.
