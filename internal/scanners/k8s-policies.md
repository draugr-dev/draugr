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

Six of these checks are questions about a pod spec, and kube-bench asks each one separately: list
every pod, then `kubectl get pod` again per pod, per check. Measured against a cluster of 8,393
pods, answering all six from a single listing takes **8.6 seconds**.

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
| `5.1.2` | Minimize access to secrets | **decided** ¹ |
| `5.1.3` | Wildcards in Roles and ClusterRoles | **decided** |
| `5.1.4` | Minimize access to create pods | **decided** ¹ |
| `5.1.5` | Default service accounts are not actively used | **decided** |
| `5.1.6` | Service account tokens only mounted where necessary | **decided** |
| `5.2.2` | Admission of privileged containers | **decided** |
| `5.2.3` | Containers sharing the host PID namespace | **decided** |
| `5.2.4` | Containers sharing the host IPC namespace | **decided** |
| `5.2.5` | Containers sharing the host network namespace | **decided** |
| `5.2.6` | Containers with allowPrivilegeEscalation | **decided** |
| `5.2.7` | Admission of root containers | **decided** |
| `5.2.8` | Containers with the NET_RAW capability | **decided** |
| `5.2.9` | Containers with capabilities assigned | **decided** |
| `5.2.10` | Windows HostProcess containers | **decided** |
| `5.2.11` | HostPath volumes | **decided** |
| `5.2.12` | Containers using host ports | **decided** |
| `5.6.2` | A seccomp profile is set | **decided** |
| `5.6.3` | SecurityContext applied to pods and containers | **decided** |
| `5.6.4` | The default namespace is not used | **decided** |
| the other 14 | | reported for manual review |

¹ These two ask the cluster's own authorizer rather than reassembling its decision from roles and
bindings — RBAC is additive across bindings, aggregated ClusterRoles resolve at runtime, and a
webhook authorizer can grant what no Role mentions, so a reimplementation would disagree with the
cluster in exactly the cases that matter. Draugr submits the same query kube-bench does
(`can-i … --as=system:authenticated`) as a **SubjectAccessReview**.

That creates nothing — the API server answers and discards it — but submitting one needs the
`create` verb on `subjectaccessreviews`, which a deliberately read-only credential will not have.
Being refused is expected rather than exceptional, so the check is left undecided and reported
for manual review like any other this scanner cannot settle.

**20 of 34 decided, against the 11 kube-bench automates.** The nine past parity are ones
kube-bench leaves manual, and they are decidable here for the reason this scanner exists: they
are questions about a pod spec, and correlating pod specs is what a `kubectl | jq | xargs`
pipeline is worst at. They cost nothing extra — the same single listing already answers the
others.

The 14 that remain manual are honestly manual: whether an admission control mechanism is in
*place*, whether the CNI *supports* NetworkPolicy, whether secrets belong in an external store.
Those are questions about intent and architecture, not cluster state.

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

## Scoping to the namespaces you own

On a shared cluster the cluster is not the unit anyone owns:

```yaml
infrastructure:
  - kind: kubernetes
    ref: prod-cluster
    namespaces: [team-a, team-a-jobs]
```

Most of what this section examines is namespace-scoped — default service accounts, token
mounting, and all five pod-security checks. A team owning three namespaces of eighty otherwise
receives seventy-seven namespaces' worth of findings it cannot act on, and a number that will
never reach zero is a number people stop reading. It also fixes what the component's `exposure`
and `criticality` mean, which otherwise assert a risk classification over everybody else's
workloads.

**Scoping changes what is read, not what is kept.** Namespaced resources are listed per namespace
rather than cluster-wide and filtered afterwards — the distinction matters, because a credential
scoped to a few namespaces cannot perform the cluster-wide list at all, so filtering after the
fact would work only for people who did not need the feature.

Cluster-scoped checks still run and are still reported: a namespace owner is affected by a
cluster-admin binding even though they cannot remove it. Where the credential cannot read those
objects, those checks fall back to manual review rather than failing the run — a scoped audit is
usually run by a scoped credential, and the namespaced half is still worth having.

The scope is part of the finding's location (`kubernetes/prod-cluster[team-a,team-a-jobs]`) and
part of the cache key. The same rule id against the same cluster means something different
depending on how much of it was examined.

**Only this scanner can honour a scope.** kube-bench writes `--all-namespaces` into its own
checks with no flag to change it, and the in-cluster Job reads a node filesystem that has no
namespace at all. Both **refuse** a scoped component rather than quietly auditing everything and
reporting it under a component that asked for three namespaces.

## The section this scanner does not read

Every managed benchmark ships a **Managed Services** section covering what the *provider*
controls rather than what the cluster does — image registry scanning, IAM, key management, node
metadata, cluster networking, logging, storage:

| benchmark | checks |
|---|---|
| `gke-1.9.0` | 33 |
| `eks-1.8.0` | 12 |
| `aks-1.8` | 13 |

Draugr evaluates none of it: reading those settings needs the cloud provider's own API, not the
Kubernetes one. That is a defensible gap. Leaving it unmentioned is not — a reader of the report
has no way to know the section exists, so the benchmark looks smaller than it is and a clean
result looks more complete than it is.

So a managed cluster gets one finding naming the section, its benchmark and its size. **One,
rather than one per check**, unlike the policies section: there the checks share a section this
scanner partly evaluates, so listing them individually is what keeps coverage honest. Here
nothing in the section is evaluated, and saying so once is unambiguous where fifty-eight
identical "review this yourself" entries would bury the findings that came from an actual
assessment.

The counts are held to kube-bench's own definitions by `TestManagedServicesCountsMatchKubeBench`
— a number that drifts understates the very thing it exists to disclose.

## What the report says about the run

The scanner records what it measured and against what, which travels in `--format json`,
`markdown`, `html` and SARIF's own run property bag:

```
Measured against
- infrastructure — k8s-policies: benchmark cis-1.12 · coverage 20 of 34 checks decided · scope team-a
```

The coverage figure is the one a reader cannot otherwise get. Counting manual-review findings by
hand is the only alternative, and a clean report gives no hint that fourteen of the section's
checks were never decided by anything.

## Interpreting a finding

Rule ids are `draugr/cis/<check number>`, namespaced by the scanner that emitted them.
[`kube-bench`](kube-bench.md) audits the same benchmark with the same numbering, and a bare
`cis/5.1.1` would be an id two tools both claim — which is a real collision outside Draugr's own
console, where the rule id *is* the finding's identity: in SARIF, in GitHub code scanning, in an
editor.

**To exclude a check whichever scanner reports it**, glob the namespace:

```yaml
config:
  exclude:
    - rules: ["*/cis/5.1.1"]
      reason: "wildcard roles are how our operator works; accepted"
```

That is the more accurate thing to write in any case: it excuses the *check*, rather than one
tool's opinion of it.

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
