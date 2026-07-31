# Scanner: `k8s-policies` (CIS policies section, natively)

- **Control:** [`infrastructure`](../controllers/infrastructure.md)
- **Tool:** none — this scanner reads the Kubernetes API directly
- **Status:** ✅ implemented, partial coverage of the section (see below)
- **Target:** a Kubernetes cluster (`InfraTarget`)
- **License / terms:** Apache-2.0 (Draugr's own). No third-party tool is executed.

## What it does

Evaluates the CIS Kubernetes Benchmark's **policies** section against a live cluster using
`client-go`, as an alternative to [`kube-bench`](kube-bench.md). Opt in with a scanner block:

```yaml
config:
  controllers:
    infrastructure:
      enabled: true
      kubeBench: { enabled: false }   # stop exec'ing kube-bench for this section
      k8sPolicies: { enabled: true }
```

## Why not just run kube-bench

kube-bench answers this section by shelling out to `kubectl` — one subprocess per check, and for
the pod-security checks one **per pod** on top of listing them:

```yaml
id: 5.2.2
audit: "kubectl get pods --all-namespaces ... | while read -r pod_name pod_namespace
         do kubectl get pod \"${pod_name}\" --namespace \"${pod_namespace}\" -o json | jq ..."
```

Against a shared cluster of 78 namespaces a single pass takes tens of minutes. Almost none of
that is the queries; it is process startup and, on a managed cluster, a fresh credential
exchange per invocation. The same questions are a handful of `List` calls.

Speed is the visible reason. Two others matter more:

- **A check written in Go can decide things a shell pipeline cannot.** CIS marks all 34 checks in
  this section manual and kube-bench automates 11 — partly because `kubectl | jq | xargs` is a
  blunt instrument for correlating roles, bindings and pod specs.
- **Namespace scoping becomes possible at all.** kube-bench's queries carry `--all-namespaces`
  inside its config, with no flag to change it, so a team on a shared cluster cannot ask about
  the namespaces it owns. See
  [#407](https://github.com/draugr-dev/draugr/issues/407).

## Coverage, stated rather than implied

A scanner that evaluates part of a benchmark and omits the rest returns a shorter, cleaner report
that quietly means less. So **every check in the section is reported**. The ones implemented here
get a verdict from the cluster; the rest are reported as requiring manual review — which is what
CIS says about them, and what kube-bench reports for them too.

Coverage is therefore additive. Implementing a check replaces "review this yourself" with an
answer and changes nothing else.

| Check | | |
|---|---|---|
| `5.1.1` | Cluster-admin role is only used where required | **decided** |
| `5.1.3` | Wildcards in Roles and ClusterRoles | **decided** |
| `5.1.5` | Default service accounts are not actively used | **decided** |
| the other 31 | | reported for manual review |

The catalogue is pinned to `cis-1.12`, deliberately: the section is renumbered between revisions,
and silently tracking "the latest" would change what a rule id means underneath an exclusion
someone wrote against it.

### The catalogue cannot quietly go out of date

A hand-maintained list of a benchmark someone else revises drifts, and drifts silently in both
directions. A check added upstream and missing here is never reported at all, so a scan covers
less than the benchmark and says nothing about it. A check retired upstream but left here is
reported forever, sending a reader after a requirement that no longer exists.

`TestCISCatalogueMatchesKubeBench` diffs the catalogue against kube-bench's own definitions and
fails on either, naming the check. It runs in the integration suite, which fetches those
definitions at a pinned commit — the tag is verified against it, because a benchmark that changed
under a stable tag is precisely what the check exists to notice.

The pin is kept in step with the image the in-cluster Job runs, so **bumping kube-bench is when a
benchmark revision is discovered**, rather than some later scan quietly covering the wrong thing.

Nothing here writes a check for us. It makes shipping an out-of-date catalogue impossible to do
without noticing, which is the part that can be automated.

## Interpreting a finding

Rule ids are `cis/<check number>` — the same ids [`kube-bench`](kube-bench.md) emits, so an
existing `config.exclude` rule keeps working when you switch modes.

Everything is reported at **warning**. That matches the benchmark: no check in this section is
scored, so none of them can say a cluster is out of compliance — they say it needs looking at.
The scored checks are in sections 1–4, which need
[`kube-bench-job`](kube-bench-job.md).

A decided check that passes produces no finding, for the same reason a clean dependency does not.

## Permissions

Read (`get`, `list`) on `clusterrolebindings`, `roles`, `clusterroles` and `serviceaccounts`.
Nothing is created, and no privileged pod is scheduled — the distinction from
[`kube-bench-job`](kube-bench-job.md), which declares `mutate` and `privilege` effects and does
not run until they are accepted.

## Links

- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- Native implementation tracking issue: https://github.com/draugr-dev/draugr/issues/389

## Notes

- No external binary, so nothing for `draugr tools install` to fetch and nothing for
  `draugr doctor` to report missing. The `kubectl` requirement that
  [`kube-bench`](kube-bench.md) carries does not apply here.
- The cluster is chosen the same way as the other infrastructure scanners: the component's
  `ref`, an explicit `context` setting, or the ambient kubeconfig context.
- Findings are located at the cluster (`kubernetes/<ref>`), not a file — that is what was
  assessed.
