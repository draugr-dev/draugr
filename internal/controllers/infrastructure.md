# Controller: `infrastructure` (CIS Kubernetes Benchmark)

- **Industry term:** CIS benchmark / cluster posture
- **Scope:** component
- **Status:** ✅ implemented (CIS section 5 — see the scope note below)
- **Scanners:** [`kube-bench`](../scanners/kube-bench.md)
- **Resource:** a component's `infrastructure:` entries with `kind: kubernetes`

## What it does

Plans one scan per Kubernetes cluster a component declares, and aggregates the findings.

**Component-scoped, not project-scoped**, because that is where the Saga puts the data:
`infrastructure:` is a list on a component describing what that component runs on. A cluster with
nothing else to say for it is simply a component with no repositories, images or hosts:

```yaml
components:
  - name: prod-cluster
    exposure: public
    criticality: critical
    infrastructure:
      - kind: kubernetes
        ref: prod-eu-west-1
```

**`ref` selects the cluster, it does not merely name it.** It is matched against a kubeconfig
context, and both Draugr's version lookup and the `kubectl` calls kube-bench makes are pointed at
that context. Findings are labelled with it, so if it did not also select the cluster a report
would name one cluster and describe another — the worst way for a compliance artifact to be
wrong, because it looks right. A `ref` with no matching context fails the scan.

Where an organisation's name for a cluster is not its kubeconfig context name, set `context`.

`ref` is optional. Without it Draugr audits the kubeconfig's current context — and labels the
findings with **that** context's name, not a blank, so the report still says which cluster it
examined.

Two components on the same cluster produce two jobs with the same target, which the engine
collapses — the shared case costs one scan, not two.

Infrastructure of another kind is skipped rather than rejected. A Saga may describe surfaces
Draugr has no benchmark for, and refusing to plan the ones it understands would make a descriptor
less useful the more honestly it was written.

## Scope: what this control covers, and what it does not

kube-bench audits **the machine it runs on**. That splits the CIS Kubernetes Benchmark in two,
and only one half is reachable the way Draugr runs:

| CIS sections | What they inspect | Reachable? |
|---|---|---|
| 5 — policies | RBAC, service accounts, Pod Security Standards, network policies, secrets | ✅ via the Kubernetes API — the default |
| 1–4 — master, node, etcd, controlplane | API server manifests, kubelet config, etcd data-dir permissions | ✅ via `mode: job`, which runs in the cluster |

By default this control runs section 5: **35 of the 130 checks in `cis-1.9`**, read-only, from
wherever Draugr runs. They are the checks that describe how the cluster is configured for the workloads on
it, rather than how its nodes were installed.

The other 95 read a node's own filesystem, and are available through
[`mode: job`](../scanners/kube-bench-job.md) — which runs kube-bench inside the cluster and is a
different contract: Draugr creates something in the system it is scanning. It declares `mutate`
and `privilege` effects, so it does not run until those are accepted:

```yaml
config:
  allowEffects: [mutate, privilege]
  controllers:
    infrastructure:
      enabled: true
      mode: job
```

Two scanners rather than one with a flag, because the difference is not an implementation detail
and effects are declared per scanner. Keeping them apart is what lets the read-only default run
unguarded.

## Configuration

```yaml
config:
  controllers:
    infrastructure:
      enabled: true
      context: arn:aws:eks:...         # optional; defaults to the component's `ref`
      version: "1.34"                  # optional; Draugr asks the cluster otherwise
      benchmark: gke-1.6.0             # optional; names a benchmark config directly
      configDir: /etc/kube-bench/cfg   # optional; where kube-bench's definitions live
```

Settings pass through to the scanner. Project-level settings apply to every component; a
component may override them.

**You should not normally need `version`.** Draugr asks the cluster and tells kube-bench, because
kube-bench cannot detect it from outside a node and quietly assumes an old one if left to guess —
see the [scanner doc](../scanners/kube-bench.md). Use `benchmark` for a platform whose benchmark
is not derived from a Kubernetes version (`gke-*`, `eks-*`, `rke2-*`).

## Links

- Scanner: [`kube-bench`](../scanners/kube-bench.md)
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Needs `kubectl` on `PATH` and a working kubeconfig: every section-5 check shells out to it.
  Draugr reads the ambient kubeconfig, the same as the `k8s-images` surveyor.
- Findings are located at the cluster (`kubernetes/<ref>`) rather than a file, because that is
  what was assessed.
