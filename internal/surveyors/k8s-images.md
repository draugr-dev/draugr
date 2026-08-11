# Surveyor: `k8s-images`

- **Discovers:** unique container images running in a Kubernetes cluster/namespace
- **Status:** ✅ implemented
- **Provides:** image targets → a Saga component
- **Auth:** ambient kubeconfig (`KUBECONFIG` / `~/.kube/config` / in-cluster)
- **License / terms:** uses `k8s.io/client-go` (**Apache-2.0**). No external service beyond
  your own cluster.

## What it does

Lists pods in a namespace (or every namespace) via the Kubernetes API and returns the unique
container images (init + regular) as **one Saga component per namespace**, so the descriptor
writes itself. It also records each image's **running digest** (from the pod's container status),
so result caching is content-addressed — a rebuilt image under the same tag re-scans.

The namespace is the unit whether or not one was named. A cluster collapsed into a single
component loses both things that make the result usable: the namespace is what a team owns, so it
is what a finding has to be attributed to, and one exposure covering everything running anywhere
in a cluster would not mean anything.

An image running in two namespaces appears under both. That is what each component's surface
actually is, and the engine collapses identical targets when it plans the run, so the honest
descriptor costs nothing to scan.

**Proposes exposure.** Each component's `exposure` is inferred from its own namespace's topology
(see [prioritization](../../docs/concepts/prioritization.md)):

| Signal in the namespace | Proposed `exposure` |
|-------------------------|---------------------|
| An `Ingress`, or a `Service` of type `LoadBalancer`/`NodePort` | `public` |
| A `NetworkPolicy` (and no external reach) | `restricted` |
| Otherwise | `internal` |

It's a **proposal to confirm**, and the survey says so: every component it guessed an exposure
for is named on the way out, with the value it chose and a pointer to `draugr classify`. Written
into the file a proposal looks exactly like a decision, and exposure is what turns a severity into
a P1 or a P3 — so it arrives announced rather than quietly.

Authentication can't be inferred, so internet-reachable is proposed as `public` (downgrade to
`authenticated` if it sits behind auth). The three lookups are made once over the surveyed scope
rather than once per namespace — the answer is identical, and on a cluster with eighty namespaces
the per-namespace form is two hundred and forty round trips. A component that already carries an
exposure keeps it — the merge does not overwrite a decision, and no proposal is reported for it. `criticality`
is never inferred (it's human-declared) — run `draugr classify` to set it.

## Known limitations

- Exposure inference reads only **core** constructs (`Ingress`, `Service`). Workloads exposed
  via a **service mesh or alternative router** (Istio `Gateway`/`VirtualService`, Gateway API,
  OpenShift `Route`, …) are not yet detected and may be under-proposed as `internal`. Tracked
  in [#113](https://github.com/draugr-dev/draugr/issues/113).

## Links

- client-go: https://github.com/kubernetes/client-go
- Concepts: [surveyors](../../docs/concepts/surveyors.md)
