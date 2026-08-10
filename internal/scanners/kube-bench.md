# Scanner: `kube-bench` (CIS Kubernetes Benchmark)

- **Control:** [`infrastructure`](../controllers/infrastructure.md)
- **Tool:** Aqua **kube-bench** — https://github.com/aquasecurity/kube-bench
- **Status:** ✅ implemented (CIS section 5)
- **Target:** a Kubernetes cluster (`InfraTarget`)
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**.

## What it does

Runs

```
kube-bench run --json --targets policies [--version <cluster version>] [--config-dir <dir>]
```

and converts the result to SARIF. `--version` is supplied for a vanilla cluster and deliberately
withheld for a managed one — see [choosing the benchmark](#draugr-chooses-the-benchmark).

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

## Draugr chooses the benchmark

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
or `benchmark` to override.

### On a managed cluster, supplying the version is the wrong move

kube-bench chooses like this ([`cmd/common.go`](https://github.com/aquasecurity/kube-bench/blob/main/cmd/common.go), `getBenchmarkVersion`):

```go
if isEmpty(benchmarkVersion) && isEmpty(kubeVersion) && !isEmpty(platform.Name) {
    benchmarkVersion = getPlatformBenchmarkVersion(platform)
}
```

The provider benchmarks — `eks-*`, `gke-*`, `aks-*`, `ack-*`, and the k3s and RKE ones — are
reachable **only when neither flag is set**. Passing `--version` to fix one wrong answer
therefore guarantees a different one: every managed cluster falls through to generic `cis-*`.

And that is not a near-miss. The provider benchmarks are not subsets: they drop the
control-plane checks that are not the customer's to make — and are unanswerable on a managed
control plane anyway — and add provider-specific ones the generic benchmark has never heard of.
The mismatch fails a cluster for what it cannot fix while skipping what it can.

So Draugr reads the platform out of the same `GitVersion` it already fetched
(`v1.30.4-eks-a737599` → `eks`) using kube-bench's own expression, and then:

| cluster | flags passed | benchmark chosen by |
|---|---|---|
| vanilla (`v1.34.0`) | `--version 1.34` | kube-bench's version mapping |
| recognized platform | *neither* | kube-bench's platform mapping |
| `benchmark` set | `--benchmark <value>` | you |
| `version` set | `--version <value>` | kube-bench's version mapping |

A build suffix is not automatically a platform. `v1.31.0-rc.1` parses exactly like
`v1.30.4-eks-a737599`, so only suffixes kube-bench actually maps count — a release candidate
stays vanilla rather than sending the scan after an `rc` benchmark.

### AKS does not announce itself in the version string

GKE and EKS stamp their version (`v1.29.7-gke.1104000`), so a regex is enough. A real AKS cluster
reports a bare **`v1.34.2`** — indistinguishable from kubeadm — and was therefore audited against
the generic benchmark, with nothing to signal it: no detected platform means no expectation, so
the output check had nothing to disagree with.

kube-bench knows this and looks at a node instead, for a `kubernetes.azure.com/cluster` label or
an `azure://` provider ID. It only does so along its in-cluster path, because that is where it
happens to build a client — the check itself is an ordinary `List`. So Draugr does the same,
fetching **one** node (a two-hundred-node cluster should not pay for two hundred objects to
answer a yes/no question), and only when the version string came back bare.

If reading nodes is denied, the platform is simply not detected and the version string decides,
exactly as before. A permission Draugr may not have is not a reason to fail a scan it can run.

Only the `kubernetes.azure.com/cluster` label counts — **not** the `azure://` provider ID that
kube-bench also accepts. A provider ID says which cloud the VM is on, not who runs the control
plane: RKE2, RKE and kubeadm all set it when the Azure cloud provider is configured, and calling
one of those AKS would audit it against a benchmark written for a control plane nobody can see,
dropping the checks a self-managed cluster most needs.

kube-bench can afford the looser signal because it only reaches that check from inside the
cluster, having already tested for RKE. A node read from outside carries no such context.

Distributions that stamp their own version are unaffected either way — RKE2 reports
`v1.27.6+rke2r1`, so it is resolved before any node is fetched. Node inspection is a fallback,
never an override.

OpenShift is still not detected here. kube-bench identifies it by running `oc`, not from any API
object, so this scanner cannot reach the same conclusion; set `benchmark` for it.

### The output is the guarantee, not the input

Withholding the flags hands the choice to a tool that has its own fallback — the same 1.18
fallback described above. So Draugr does not assume it worked: kube-bench states the benchmark
it used in every control it emits, and the scan **fails** if that does not match the platform
detected.

A run that audited the wrong standard is a failed scan, not a finding-free pass. The error names
the benchmark used, the platform expected, and the setting that resolves it.

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
something in the system it is scanning. That is a different contract, and is
[`kube-bench-job`](kube-bench-job.md) rather than this scanner.

### What section 5 is worth, stated plainly

The count is the flattering way to describe this mode. In `cis-1.12`:

| | |
|---|---|
| checks in section 5 | 34 |
| **scored** | **0** — every one is `(Manual)` |
| carrying an audit command | 11 |

So 23 of them are prompts for a human with nothing behind them, and none of the 34 counts toward
a compliance score. Both unscored `FAIL` and `WARN` map to a SARIF warning, which is why this
mode's output is a list of warnings rather than a verdict: it is telling you what to review, not
what it measured.

Two consequences worth being direct about:

- **A clean section 5 is not a clean benchmark.** The scored checks are in sections 1–4.
- **It is slow at scale.** Every check is a `kubectl` subprocess and most pass
  `--all-namespaces`. Against a 78-namespace managed cluster — where each invocation also
  re-runs a cloud auth plugin — a full pass takes tens of minutes.

## Scope

This scanner always audits the whole cluster. Its checks are `kubectl` pipelines with the scope
written into them — `--all-namespaces`, with no flag to change it — so a component that sets
`namespaces` on its infrastructure entry cannot be honoured.

So it is not planned for such a component, the way a controller does not plan for an
infrastructure kind it has no benchmark for. The alternative is worse than a missing feature: the
report would look scoped, the rule ids would look scoped, and the findings would be somebody
else's. The report names the skip under **Not measured**, because a scanner that quietly does not
run reads exactly like one that ran and found nothing.

Nothing needs disabling by hand. Declare the cluster twice — once narrowed to the namespaces a
component owns, once whole — and each scanner runs where it can answer.
[`draugr-k8s-policies`](draugr-k8s-policies.md) reads the Kubernetes API and can be narrowed, so it
serves both.

`kubeBenchJob` is the answer to both where a privileged pod is permitted. Where it is not — a
namespace enforcing the restricted Pod Security Standard will reject it — this mode is what runs,
and 11 automated advisory checks beat nothing. Implementing the section natively against the
Kubernetes API would fix the speed, drop the `kubectl` dependency, and make more of the 34
decidable than a shell pipeline can:
[#389](https://github.com/draugr-dev/draugr/issues/389).

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

Rule ids are `kube-bench/cis/<check number>`, e.g. `kube-bench/cis/5.1.1` — namespaced because
`draugr-draugr-k8s-policies` audits the same benchmark with the same numbering, and a bare `cis/5.1.1`
would be an id two tools both claim. A `config.exclude` rule reads the way the
benchmark does.

## Installation

`draugr tools install kube-bench` fetches the binary **and its `cfg/` tree together** — 276
benchmark definitions that kube-bench cannot run without. The binary goes to `~/.draugr/bin`, the
definitions to `~/.draugr/data/kube-bench`, and the scanner passes `--config-dir` at that tree so
kube-bench does not have to find it.

Installing the binary alone is the common mistake and does not look like one: every run then
exits with `config file is missing 'target_mapping' section`, which names an internal structure
rather than the directory nobody copied. `draugr doctor` reports the difference before a scan —
present-but-empty shows as `✗ no data`.

An explicit `configDir` in the descriptor always wins, and a system install with its own `cfg/`
keeps working as before: Draugr only supplies the flag when it has a tree of its own and the
descriptor said nothing.

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
