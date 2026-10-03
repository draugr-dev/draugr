# Controller: `kubernetes` (CIS Kubernetes Benchmark)

- **Industry term:** CIS benchmark / cluster posture
- **Scope:** component
- **Status:** ✅ implemented (CIS section 5. See the scope note below)
- **Scanners:** [`draugr-k8s-policies`](../scanners/draugr-k8s-policies.md) (default);
  [`kube-bench`](../scanners/kube-bench.md) and [`kube-bench-job`](../scanners/kube-bench-job.md) (opt-in)
- **Resource:** a component's `kubernetes:` entries, naming clusters declared under `clusters:`

## What it does

Plans one scan per cluster a component's `kubernetes:` entries name, and aggregates the findings.

**Each cluster is declared once, under `clusters:`**, with the facts that are the cluster's: the
kubeconfig context that reaches it, who operates it, and the benchmark kube-bench audits it
against. Components refer to it by name. A cluster with nothing else to say for it is a component
with no repositories, images or hosts:

```yaml
clusters:
  prod-eu:
    context: prod-eu-west-1
components:
  - name: prod-cluster
    exposure: public
    criticality: critical
    kubernetes:
      - cluster: prod-eu
```

**The context selects the cluster, it does not merely describe it.** Draugr's version lookup, its
own API reads and the `kubectl` calls kube-bench makes are all pointed at it, so a report never
names one cluster and describes another. A context the kubeconfig does not have fails the scan, and
`draugr doctor` says so before one runs. Without a context, Draugr audits the kubeconfig's current
one.

**Findings name the cluster, not the context:** `kubernetes/prod-eu[payments]`. The name is the same
on every machine that runs the descriptor, where context names often are not.

**The cluster-wide checks run once, for the component that declares the cluster whole.** A
component that names `namespaces` gets the checks about objects in them; ClusterRoleBindings,
admission webhooks, the CNI and the rest of the cluster-scoped checks are the whole-cluster
component's. On a shared cluster that files each cluster-wide answer once, rather than once per
team that owns a namespace of it.

Two components on the same cluster and scope produce two jobs with the same target, which the engine
collapses. The shared case costs one scan, not two.

## Scope: what this control covers, and what it does not

kube-bench audits **the machine it runs on**. That splits the CIS Kubernetes Benchmark in two,
and only one half is reachable the way Draugr runs:

| CIS sections | What they inspect | Reachable? |
|---|---|---|
| 5, policies | RBAC, service accounts, Pod Security Standards, network policies, secrets | ✅ via the Kubernetes API, the default |
| 1–4, master, node, etcd, controlplane | API server manifests, kubelet config, etcd data-dir permissions | ✅ via `kubeBenchJob`, which runs in the cluster |

Scanners are selected per scanner, the same way every other control does it. Each runs unless
turned off; a non-default runs only when turned on:

| Key | Scanner | |
|---|---|---|
| `draugrK8sPolicies` | [`draugr-k8s-policies`](../scanners/draugr-k8s-policies.md) | section 5 through the Kubernetes API, **the default**. No `kubectl`, nothing to install, seconds on a large cluster |
| `kubeBench` | [`kube-bench`](../scanners/kube-bench.md) | section 5 by exec'ing kube-bench. Same 11 checks decided; the reference the native reader is checked against |
| `kubeBenchJob` | [`kube-bench-job`](../scanners/kube-bench-job.md) | sections 1–4, from a privileged Job inside the cluster |

Enabling the Job does **not** replace the section-5 scanner. The Job does not run `policies`, so
a component that swapped one for the other would report a pass on half a benchmark; the default
keeps running alongside it.

The whole benchmark, which is what most people want:

```yaml
config:
  controls:
    kubernetes:
      enabled: true
      kubeBenchJob: { enabled: true }   # the node sections; the default covers section 5
```

To have kube-bench itself be the thing that ran, as a cross-check, or because a report naming the
tool matters to an auditor, swap the section-5 scanner:

```yaml
      draugrK8sPolicies: { enabled: false }
      kubeBench: { enabled: true }
```

By default this control runs section 5: **35 of the 130 checks in `cis-1.9`**, read-only, from
wherever Draugr runs. They are the checks that describe how the cluster is configured for the workloads on
it, rather than how its nodes were installed.

**Read that count with its caveat.** Section 5 is the benchmark's advisory section: in `cis-1.12`
none of its 34 checks are scored, and only 11 carry an audit command. The rest are prompts for a
human to go and look. So the default mode reports a small number of automated findings alongside a
list of things to review, and a cluster it calls clean has not been measured against the scored
parts of the benchmark. Those live in sections 1–4, and `kubeBenchJob` is how you reach them.

The other 95 read a node's own filesystem, and are available through
[`kubeBenchJob`](../scanners/kube-bench-job.md), which runs kube-bench inside the cluster and is a
different contract: Draugr creates something in the system it is scanning. It declares `mutate` and
`privilege` effects, so it does not run until those are accepted:

```yaml
config:
  allowEffects: [mutate, privilege]
  controls:
    kubernetes:
      enabled: true
      kubeBenchJob:
        enabled: true
```

Two scanners rather than one with a flag, because the difference is not an implementation detail
and effects are declared per scanner. Keeping them apart is what lets the read-only default run
unguarded.

## Configuration

```yaml
config:
  controls:
    kubernetes:
      enabled: true
      kubeBench:
        enabled: true
        configDir: /etc/kube-bench/cfg   # optional; where kube-bench's definitions live
clusters:
  prod-eu:
    context: arn:aws:eks:...             # optional; the kubeconfig's current context otherwise
    version: "1.34"                      # optional; Draugr asks the cluster otherwise
    benchmark: gke-1.6.0                 # optional; names a benchmark config directly
```

Each scanner setting belongs to the scanner that reads it, under that scanner's key, and
`draugrK8sPolicies` takes none. What belongs to a cluster, its context, benchmark and version, is on
the cluster under `clusters:`, so two clusters on different versions can each have their own.

**You should not normally need `benchmark` or `version`.** Draugr asks the cluster what it is and picks
accordingly: a vanilla cluster gets its Kubernetes version supplied, because kube-bench cannot
detect it from outside a node and quietly assumes an old one if left to guess; a managed one
(EKS, GKE, AKS, k3s, RKE2, ACK) gets its provider benchmark, which kube-bench will only select
when no version is supplied. Whichever it picks, the benchmark the tool reports having used is
checked against the cluster before any finding is produced.

Set `benchmark` to pin a config directly. For OpenShift, which is identifiable only by running `oc`,
or for any distribution Draugr does not recognize. See the [scanner doc](../scanners/kube-bench.md)
for how the choice is made.

## Links

- Scanners: [`draugr-k8s-policies`](../scanners/draugr-k8s-policies.md),
  [`kube-bench`](../scanners/kube-bench.md), [`kube-bench-job`](../scanners/kube-bench-job.md)
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Needs a working kubeconfig. Draugr reads the ambient one, the same as the `k8s-images` surveyor.
  `kube-bench` also needs `kubectl` on `PATH`, because every section-5 check it runs shells out to
  it.
- Findings are located at the cluster (`kubernetes/<name>`) rather than a file, because that is
  what was assessed.
