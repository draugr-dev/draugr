# Surveyor: `k8s-images` (the Ravens)

- **Discovers:** unique container images running in a Kubernetes cluster/namespace
- **Status:** ✅ implemented
- **Provides:** image targets → a Saga component
- **Auth:** ambient kubeconfig (`KUBECONFIG` / `~/.kube/config` / in-cluster)
- **License / terms:** uses `k8s.io/client-go` (**Apache-2.0**). No external service beyond
  your own cluster.

## What it does

Lists pods in a namespace (or all namespaces) via the Kubernetes API and returns the unique
container images (init + regular) as a Saga component, so the descriptor writes itself.

**Proposes exposure.** When surveying a *specific* namespace, it also infers the component's
`exposure` from topology (see [prioritization](../../docs/concepts.md#prioritization-what-to-fix-first)):

| Signal in the namespace | Proposed `exposure` |
|-------------------------|---------------------|
| An `Ingress`, or a `Service` of type `LoadBalancer`/`NodePort` | `public` |
| A `NetworkPolicy` (and no external reach) | `restricted` |
| Otherwise | `internal` |

It's a **proposal to confirm** — authentication can't be inferred, so internet-reachable is
proposed as `public` (downgrade to `authenticated` if it sits behind auth). A whole-cluster
survey lumps namespaces into one component, so exposure is not proposed there. `criticality`
is never inferred (it's human-declared) — run `draugr classify` to set it.

## Known limitations

- Exposure inference reads only **core** constructs (`Ingress`, `Service`). Workloads exposed
  via a **service mesh or alternative router** (Istio `Gateway`/`VirtualService`, Gateway API,
  OpenShift `Route`, …) are not yet detected and may be under-proposed as `internal`. Tracked
  in [#113](https://github.com/draugr-dev/draugr/issues/113).

## Links

- client-go: https://github.com/kubernetes/client-go
- Concepts: [the Ravens](../../docs/concepts.md#surveyors--the-ravens)
