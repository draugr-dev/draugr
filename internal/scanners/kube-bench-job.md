---
title: "kube-bench-job"
description: "Audits the node and control-plane sections of the CIS Benchmark from a short-lived Job in the cluster. Declares mutate and privilege effects."
section: Scanners
order: 100
---

# Scanner: `kube-bench-job` (CIS benchmark, run inside the cluster)

- **Control:** [`kubernetes`](../controllers/kubernetes.md)
- **Tool:** Aqua **kube-bench**, as a container image, https://github.com/aquasecurity/kube-bench
- **Status:** ✅ implemented (CIS sections 1–4)
- **Target:** a Kubernetes cluster (`KubernetesTarget`)
- **License / terms:** **Apache-2.0** (permissive). Run as a pod from the published image.
- **Effects:** `mutate` (creates a Job), `privilege` (hostPID, host path mounts)

## What it does

Creates a short-lived Job on a node of each role, waits for them, reads their output, and deletes
them.

```
kube-bench run --json --targets master,etcd,controlplane    # on a control-plane node
kube-bench run --json --targets node                        # on a worker
```

Selected with `kubeBenchJob: { enabled: true }` on the control. The default scanner,
[`draugr-k8s-policies`](draugr-k8s-policies.md), stays read-only and covers section 5.

## Why a separate scanner rather than a mode

The two have genuinely different contracts, and the difference is the kind a user should be asked
about rather than discover:

| | `kube-bench` | `kube-bench-job` |
|---|---|---|
| Touches the cluster | reads through the API | **creates a Job** |
| Needs locally | `kube-bench`, `kubectl` | nothing. The image carries both |
| Node access | none | hostPID, host paths mounted read-only |
| CIS sections | 5 (policies) | 1–4 (master, node, etcd, controlplane) |

Effects are declared per scanner, so keeping them apart is what lets the read-only path run
unguarded while this one has to be accepted first:

```yaml
config:
  allowEffects: [mutate, privilege]
  controls:
    kubernetes:
      enabled: true
      kubeBenchJob:
        enabled: true
```

Without that, the run stops before it creates anything and says what it would have done.

## What the Job looks like

It follows kube-bench's own manifest, because the checks read files that exist only on a node:

- **`hostPID: true`**, several checks inspect control-plane processes.
- **Host paths mounted read-only**, `/etc/kubernetes`, `/var/lib/kubelet`, `/var/lib/etcd` and the
  rest of kube-bench's own list. Read-only throughout: a scan has no business being able to change
  what it inspects.
- **`/var/lib/rancher`, on k3s and RKE2 only**, where their benchmarks read the configuration,
  certificates and keys other distributions keep under `/etc/kubernetes`. A node's kubelet version
  or the cluster's `benchmark` says which distribution it is. The directory holds the cluster's
  keys, so no other cluster gets the mount.
- **`tolerations: [{operator: Exists}]`**. A control-plane node is tainted, and its configuration
  is most of what these sections check. Without this the Job is unschedulable exactly where it is
  most useful.
- **`backoffLimit: 0`**. A failing benchmark is a result, not something to retry.
- **Left out of [`draugr-k8s-policies`](draugr-k8s-policies.md)' pod checks** in the same run, so
  the scan does not report its own privileged pod as a finding about the cluster.
- **No service account or RBAC.** These sections read the host filesystem, not the API, so the
  Job needs no permissions in the cluster.

The Job needs none, and the scanning identity needs `list` on `nodes` to place it.
Without it one Job runs wherever the scheduler puts it, and the evidence says the node roles were
not read.

This is a privileged pod. On a cluster enforcing the **restricted** Pod Security Standard it will
be rejected, which is the standard working as intended. Run it in a namespace whose policy permits
it.

## Which nodes it reads

kube-bench runs whatever targets it is given on the node it lands on, and one Job reads one node.
On a worker, a control-plane check finds no API server manifest and no etcd data directory, and
kube-bench fails it. Targets are split by node role:

| Cluster | Jobs |
|---|---|
| control-plane and worker nodes | `master`, `etcd`, `controlplane` on a control-plane node; `node` on a worker |
| control-plane nodes only | every target on a control-plane node |
| no node with a control-plane role, as on a managed cluster | every target on a worker |
| `nodeSelector` set | every target on one node it selects, which the scheduler picks |

A control-plane node is one labeled `node-role.kubernetes.io/control-plane` or
`node-role.kubernetes.io/master`. Within a role the Job runs on a Ready node, the first by name, so
repeated runs read the same node.

The evidence, under **Measured against**, names each node read, and how many of the cluster's
nodes that is when some were not read.
On a two-node `kind` cluster, with `nodeSelector: kubernetes.io/hostname=kb-two-worker`:

```
benchmark: cis-1.12 · nodes: kb-two-worker · 1 of 2 nodes read
```

## Checks that read nothing

A PASS or a FAIL whose audit read nothing is not a verdict. It is listed under **Caveats** as
`unread-checks`, by node, instead of becoming a finding or counting as decided. The same run:

```
unread-checks · two-nodes
  node kb-two-worker  54 checks unread · not a control-plane node
```

A check is unread in two cases:

- **A control-plane check on a node with no control-plane role**, from a `nodeSelector` that picks a
  worker or a cluster that shows no control-plane node. The files it reads are on another machine.
  Remove `nodeSelector`, or select a control-plane node, to evaluate these checks; on a managed
  cluster, `targets: node` leaves them out.
- **A check whose audit printed only a shell's `not found`** for its command, such as the k3s
  checks that read the API server's flags through `journalctl`, which neither the image nor a
  `k3d` node carries. A check that a flag is absent passes when its audit prints no flags, so a
  PASS is listed too. No setting changes this; `report.json` lists the checks under
  `unreadChecks[]` to verify on the node by hand.

A WARN stays a finding whatever its audit printed: kube-bench is asking a person to look.
`config.gate.failOnCaveats: [unread-checks]` fails the run on these.

## Scope

The sections this Job runs read a node's own filesystem, which has no namespace, so a namespace
scope is not unimplemented here, it is meaningless. The findings always describe the whole cluster.

A component that sets `namespaces` on its `kubernetes` entry therefore cannot be served by this
scanner, so no Job is created for it and the report says so under **Caveats** as `not-measured`. A scanner that
quietly does not run reads exactly like one that ran and found nothing.

Nothing needs disabling by hand. Declare the cluster twice, once narrowed to the namespaces a
component owns, once whole, and the Job runs against the one that claims the whole cluster.
[`draugr-k8s-policies`](draugr-k8s-policies.md) reads the Kubernetes API and can be narrowed, so it
serves both.

The `namespace` option below is unrelated: it is where the Job runs, not what it looks at.

## Configuration

```yaml
config:
  controls:
    kubernetes:
      kubeBenchJob:
        enabled: true
        namespace: default              # where the Job is created
        image: docker.io/aquasec/kube-bench:v0.16.0@sha256:75506f2…
        targets: node
        nodeSelector: kubernetes.io/hostname=worker-7   # one Job, on this node
        timeout: 5m
```

The image is **pinned by digest** by default, and the digest is the part that matters. A tag is a
mutable pointer that can be repushed to different content, so a tag alone leaves you with a scan
whose result can change while nothing in the descriptor does. The digest makes the pull
reproducible and lets the runtime reject content that does not match, which is the same guarantee
`draugr tools install` gets from verifying a checksum before putting a binary on your `PATH`.

The tag is kept alongside it for readability: `@sha256:…` on its own says nothing about which
version is running, and someone reading the descriptor should be able to tell.

The default image is the kube-bench release `draugr tools install` pins for the
[`kube-bench`](kube-bench.md) scanner.

Override it for a private registry or an air-gapped mirror. If you do, pin yours by digest too,
and use the same kube-bench release so both scanners audit a cluster against the same benchmark
definitions.
This is the one setting where a convenient value quietly weakens the report.

## Cleanup

The Job is deleted on every path, including a failed or canceled scan, using a context that
survives the caller's cancellation, a Job left behind in someone's cluster is the worst thing this
scanner could do. If the wait times out, the Job is removed and the error says so.

## Links

- kube-bench Job manifest: https://github.com/aquasecurity/kube-bench/blob/main/job.yaml
- Running kube-bench: https://github.com/aquasecurity/kube-bench/blob/main/docs/running.md
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes

## Notes

- **Managed clusters.** On GKE, EKS, AKS and ACK the control plane is not yours, so `master`,
  `etcd` and `controlplane` cannot be inspected by any tool. Their checks appear under **Caveats**
  as `unread-checks`.
  `targets: node` is the useful setting there.
- Findings are located at the cluster (`kubernetes/<name>`), the same as the read-only scanner.

## Data

Nothing fetched. The benchmark definitions ship with the binary, and the image the Job runs is
pulled by the cluster from wherever the descriptor names.
