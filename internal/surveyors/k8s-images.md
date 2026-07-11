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

## Links

- client-go: https://github.com/kubernetes/client-go
- Concepts: [the Ravens](../../docs/concepts.md#surveyors--the-ravens)
