# Scanner: `kube-bench-job` (CIS benchmark, run inside the cluster)

- **Control:** [`infrastructure`](../controllers/infrastructure.md)
- **Tool:** Aqua **kube-bench**, as a container image — https://github.com/aquasecurity/kube-bench
- **Status:** ✅ implemented (CIS sections 1–4)
- **Target:** a Kubernetes cluster (`InfraTarget`)
- **License / terms:** **Apache-2.0** (permissive). Run as a pod from the published image.
- **Effects:** `mutate` (creates a Job), `privilege` (hostPID, host path mounts)

## What it does

Creates a short-lived Job in the cluster, waits for it, reads its output, and deletes it.

```
kube-bench run --json --targets master,node,etcd,controlplane
```

Selected with `mode: job` on the control. The default scanner,
[`kube-bench`](kube-bench.md), stays read-only and covers section 5.

## Why a separate scanner rather than a mode

The two have genuinely different contracts, and the difference is the kind a user should be asked
about rather than discover:

| | `kube-bench` | `kube-bench-job` |
|---|---|---|
| Touches the cluster | reads through the API | **creates a Job** |
| Needs locally | `kube-bench`, `kubectl` | nothing — the image carries both |
| Node access | none | hostPID, host paths mounted read-only |
| CIS sections | 5 (policies) | 1–4 (master, node, etcd, controlplane) |

Effects are declared per scanner, so keeping them apart is what lets the read-only path run
unguarded while this one has to be accepted first:

```yaml
config:
  allowEffects: [mutate, privilege]
  controllers:
    infrastructure:
      enabled: true
      mode: job
```

Without that, the run stops before it creates anything and says what it would have done.

## What the Job looks like

It follows kube-bench's own manifest, because the checks read files that exist only on a node:

- **`hostPID: true`** — several checks inspect control-plane processes.
- **Twelve host paths mounted read-only** — `/etc/kubernetes`, `/var/lib/kubelet`, `/var/lib/etcd`
  and the rest. Read-only throughout: a scan has no business being able to change what it
  inspects.
- **`tolerations: [{operator: Exists}]`** — a control-plane node is tainted, and its configuration
  is most of what these sections check. Without this the Job is unschedulable exactly where it is
  most useful.
- **`backoffLimit: 0`** — a failing benchmark is a result, not something to retry.
- **No service account or RBAC.** These sections read the host filesystem, not the API, so the
  Job needs no permissions in the cluster.

This is a privileged pod. On a cluster enforcing the **restricted** Pod Security Standard it will
be rejected, which is the standard working as intended — run it in a namespace whose policy
permits it.

## Configuration

```yaml
config:
  controllers:
    infrastructure:
      mode: job
      namespace: default              # where the Job is created
      image: docker.io/aquasec/kube-bench:v0.15.6@sha256:8619009…
      targets: master,node,etcd,controlplane
      nodeSelector: node-role.kubernetes.io/control-plane=
      timeout: 5m
```

The image is **pinned by digest** by default, and the digest is the part that matters. A tag is a
mutable pointer — `v0.15.6` can be repushed to different content — so a tag alone leaves you with
a scan whose result can change while nothing in the descriptor does. The digest makes the pull
reproducible and lets the runtime reject content that does not match, which is the same guarantee
`draugr tools install` gets from verifying a checksum before putting a binary on your `PATH`.

The tag is kept alongside it for readability: `@sha256:…` on its own says nothing about which
version is running, and someone reading the descriptor should be able to tell.

Override it for a private registry or an air-gapped mirror. If you do, pin yours by digest too —
this is the one setting where a convenient value quietly weakens the report.

## Cleanup

The Job is deleted on every path, including a failed or cancelled scan, using a context that
survives the caller's cancellation — a Job left behind in someone's cluster is the worst thing
this scanner could do. If the wait times out, the Job is removed and the error says so.

## Links

- kube-bench Job manifest: https://github.com/aquasecurity/kube-bench/blob/main/job.yaml
- Running kube-bench: https://github.com/aquasecurity/kube-bench/blob/main/docs/running.md
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes

## Notes

- **Managed clusters.** On GKE, EKS, AKS and ACK the control plane is not yours, so `master`,
  `etcd` and `controlplane` cannot be inspected by any tool. `targets: node` is the useful
  setting there.
- Findings are located at the cluster (`kubernetes/<ref>`), the same as the read-only scanner.
