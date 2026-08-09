# Surveyor: `k8s-cluster`

- **Discovers:** the cluster itself, as an `infrastructure` component
- **Command:** `draugr survey k8s cluster`
- **Auth:** ambient kubeconfig (`KUBECONFIG`, `~/.kube/config`, or in-cluster)
- **License / terms:** Apache-2.0 (Draugr's own). No third-party tool is executed.

## What it does

Writes the cluster you are pointed at as a component with an `infrastructure` entry, so the
[`infrastructure`](../controllers/infrastructure.md) control applies to it:

```yaml
components:
  - name: prod-cluster
    infrastructure:
      - kind: kubernetes
        ref: prod-cluster
```

```bash
draugr survey k8s cluster -o draugr.saga.yaml
draugr survey k8s cluster --context staging -o draugr.saga.yaml
```

## Why this is not part of `k8s-images`

Both read the same cluster with the same credentials, so folding them together would save a
connection. It would also mean a surveyor named for images emitting an infrastructure component
— a surprise to anyone reading `survey k8s images` in a script, and a generated descriptor is
only worth trusting if the command that produced it predicts its contents.

They also produce different things. The images are the application; the cluster is what it runs
on. Those differ in **criticality** often enough that one component would mean asserting a single
classification over both.

## Scoping

`--namespace` makes the component own that namespace rather than the whole cluster:

```yaml
    infrastructure:
      - kind: kubernetes
        ref: prod-cluster
        namespaces: [team-a]
```

This is what makes the descriptor match the survey that produced it. Without it a namespace-scoped
survey would still emit a cluster-wide component, which the operator then narrows by hand having
already said which namespace they meant. See
[namespace scoping](draugr-k8s-policies.md#scoping-to-the-namespaces-you-own) for what it changes at scan
time.

`--context` selects which cluster, for both surveyors in the `k8s` group. It is an override on
the kubeconfig, not a label: surveying whatever the machine happens to have selected while writing
the name the operator gave would produce a descriptor that names one cluster and describes
another.

## What it does not write

**`exposure` and `criticality`.** Neither is a property of a cluster — they are judgements about
how reachable it is and what its failure costs, and no manifest holds them.
[`draugr classify`](../../docs/reference/cli.md#draugr-classify-sagayaml--directory) asks a human. Until both
are set, [prioritization](../../docs/concepts/prioritization.md) has half its input.

## Notes

- The cluster is contacted before it is described. Emitting a component for a cluster that cannot
  be reached would write a descriptor whose first scan fails — better to fail while the operator
  is watching than at the scan of a cluster they believed had been checked.
- The component is named after the context, because a descriptor with a component called
  `cluster` says nothing once there are two of them, and the context is what the operator already
  calls it — the same string the infrastructure scanner resolves back to a kubeconfig entry.
- No external binary and no `kubectl`: this reads the Kubernetes API directly.
