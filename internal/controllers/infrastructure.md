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
| 1–4 — master, node, etcd, controlplane | API server manifests, kubelet config, etcd data-dir permissions | ✅ via `kubeBenchJob`, which runs in the cluster |

Scanners are selected per scanner, the same way every other control does it. Each runs unless
turned off; a non-default runs only when turned on:

| Key | Scanner | |
|---|---|---|
| `draugrK8sPolicies` | [`draugr-k8s-policies`](../scanners/draugr-k8s-policies.md) | section 5 through the Kubernetes API — **the default**. No `kubectl`, nothing to install, seconds on a large cluster |
| `kubeBench` | [`kube-bench`](../scanners/kube-bench.md) | section 5 by exec'ing kube-bench. Same 11 checks decided; the reference the native reader is checked against |
| `kubeBenchJob` | [`kube-bench-job`](../scanners/kube-bench-job.md) | sections 1–4, from a privileged Job inside the cluster |

Enabling the Job does **not** replace the section-5 scanner. The Job does not run `policies`, so
a component that swapped one for the other would report a pass on half a benchmark; the default
keeps running alongside it.

The whole benchmark, which is what most people want:

```yaml
config:
  controllers:
    infrastructure:
      enabled: true
      kubeBenchJob: { enabled: true }   # the node sections; the default covers section 5
```

To have kube-bench itself be the thing that ran — as a cross-check, or because a report naming
the tool matters to an auditor — swap the section-5 scanner:

```yaml
      draugrK8sPolicies: { enabled: false }
      kubeBench: { enabled: true }
```

By default this control runs section 5: **35 of the 130 checks in `cis-1.9`**, read-only, from
wherever Draugr runs. They are the checks that describe how the cluster is configured for the workloads on
it, rather than how its nodes were installed.

**Read that count with its caveat.** Section 5 is the benchmark's advisory section: in `cis-1.12`
none of its 34 checks are scored, and only 11 carry an audit command — the rest are prompts for a
human to go and look. So the default mode reports a small number of automated findings alongside
a list of things to review, and a cluster it calls clean has not been measured against the
scored parts of the benchmark. Those live in sections 1–4, and `kubeBenchJob` is how you reach them.

The other 95 read a node's own filesystem, and are available through
[`kubeBenchJob`](../scanners/kube-bench-job.md) — which runs kube-bench inside the cluster and is a
different contract: Draugr creates something in the system it is scanning. It declares `mutate`
and `privilege` effects, so it does not run until those are accepted:

```yaml
config:
  allowEffects: [mutate, privilege]
  controllers:
    infrastructure:
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

**You should not normally need either.** Draugr asks the cluster what it is and picks
accordingly: a vanilla cluster gets its Kubernetes version supplied, because kube-bench cannot
detect it from outside a node and quietly assumes an old one if left to guess; a managed one
(EKS, GKE, AKS, k3s, RKE2, ACK) gets its provider benchmark, which kube-bench will only select
when no version is supplied. Whichever it picks, the benchmark the tool reports having used is
checked against the cluster before any finding is produced.

Set `benchmark` to pin a config directly — for OpenShift, which is identifiable only by running
`oc`, or for any distribution Draugr does not recognize. See the
[scanner doc](../scanners/kube-bench.md) for how the choice is made.

## Links

- Scanner: [`kube-bench`](../scanners/kube-bench.md)
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Needs `kubectl` on `PATH` and a working kubeconfig: every section-5 check shells out to it.
  Draugr reads the ambient kubeconfig, the same as the `k8s-images` surveyor.
- Findings are located at the cluster (`kubernetes/<ref>`) rather than a file, because that is
  what was assessed.
