---
title: "draugr-k8s-policies"
description: "Evaluates the CIS Benchmark's policies section against a live cluster through the Kubernetes API. Native, and the default for the kubernetes control."
section: Scanners
order: 20
---

# Scanner: `draugr-k8s-policies` (CIS policies section, natively)

- **Control:** [`kubernetes`](../controllers/kubernetes.md)
- **Tool:** none. This scanner reads the Kubernetes API directly
- **Status:** ✅ implemented, partial coverage of the section (see below)
- **Target:** a Kubernetes cluster (`KubernetesTarget`)
- **License / terms:** Apache-2.0 (Draugr's own). No third-party tool is executed.

## What it does

Evaluates the CIS Kubernetes Benchmark's **policies** section against a live cluster using
`client-go`. It is the `kubernetes` control's default scanner, and needs only the control:

```yaml
config:
  controls:
    kubernetes:
      enabled: true
```

[`kube-bench`](kube-bench.md) answers the same section by running `kubectl`. To run it in this
scanner's place:

```yaml
config:
  controls:
    kubernetes:
      enabled: true
      draugrK8sPolicies: { enabled: false }
      kubeBench: { enabled: true }
```

## Why not just run kube-bench

kube-bench answers this section by shelling out to `kubectl`, one subprocess per check, and for the
pod-security checks one **per pod** on top of listing them:

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
  this section manual and kube-bench automates 11, partly because `kubectl | jq | xargs` is a
  blunt instrument for correlating roles, bindings and pod specs.
- **Namespace scoping becomes possible at all.** kube-bench's queries carry `--all-namespaces`
  inside its config, with no flag to change it, so a team on a shared cluster cannot ask about
  the namespaces it owns.

## Coverage, stated rather than implied

A scanner that evaluates part of a benchmark and omits the rest returns a shorter, cleaner report
that quietly means less. So **every check in the section is accounted for**. The ones implemented
here get a verdict from the cluster. The rest are left for a person to review. They are not findings: nothing was seen to fail and nothing changed in the cluster clears
them, so they take no band and do not count toward the gate. The coverage line counts them,
`--evidence` lists each by rule id and title, and `report.json` and SARIF's run properties carry
them as `unsettledChecks`.

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
| `5.1.8` | Bind, impersonate and escalate permissions | **decided** ² |
| `5.1.9` | Access to create persistent volumes | **decided** ² |
| `5.1.10` | Access to the `nodes/proxy` subresource | **decided** ² |
| `5.1.11` | Access to approve certificate signing requests | **decided** ² |
| `5.1.12` | Access to webhook configuration objects | **decided** ² |
| `5.1.13` | Access to create service account tokens | **decided** ² |
| `5.2.1` | At least one active policy control mechanism | **decided** ³ |
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
| `5.3.2` | Every namespace has a NetworkPolicy | **decided** |
| `5.4.1` | Secrets as files rather than environment variables | **decided** |
| `5.6.2` | A seccomp profile is set | **decided** |
| `5.6.3` | SecurityContext applied to pods and containers | **decided** |
| `5.6.4` | The default namespace is not used | **decided** |
| `5.1.7`, `5.3.1`, `5.4.2`, `5.5.1`, `5.6.1` | | left for a person |

¹ These two ask the cluster's own authorizer rather than reassembling its decision from roles and
bindings. RBAC is additive across bindings, aggregated ClusterRoles resolve at runtime, and a
webhook authorizer can grant what no Role mentions, so a reimplementation would disagree with the
cluster in exactly the cases that matter. Draugr submits the same query kube-bench does (`can-i …
--as=system:authenticated`) as a **SubjectAccessReview**.

That creates nothing. The API server answers and discards it, but submitting one needs the `create`
verb on `subjectaccessreviews`, which a deliberately read-only credential will not have. Being
refused is expected rather than exceptional, so the check is left for a person, like any other this
scanner cannot settle.

² Each names the roles that grant the permission, a wildcard included, and who each is bound to:
`1 role granting permission to bind, escalate or impersonate: role team-a/deployer (bound to
serviceaccount team-a/ci)`. A role nothing binds grants nothing and is left out. Whether those
subjects should hold the permission is the reader's call, made on a finding that names them.

A role counts as the distribution's only when the role is Kubernetes' or kubeadm's and every binding
granting it is too: an operator who binds the built-in `edit` role to a team gave that team the
access. A finding that names only the distribution's roles, such as `cluster-admin` and the
controllers' own, leaves you nothing to change, since the cluster needs them; it is low for that
reason.

A run scoped to namespaces reads the bindings there and the ClusterRoles they name. 5.1.8 and 5.1.13
are the two it decides, because 5.1.9 through 5.1.12 concern cluster-wide objects and run only over
the whole cluster. Where it cannot read a ClusterRole a binding names, it leaves both for a person
rather than answering from part of the grants.

³ Passes on any mechanism the API shows: a namespace Pod Security Admission enforces a level other
than `privileged` on, a bound ValidatingAdmissionPolicy, or a Gatekeeper or Kyverno admission
webhook. A default level set in the API server's own admission configuration file is not visible
through the API, so the finding says so. If the cluster sets one, add `draugr/cis/5.2.1` to
`config.exclude`.

**29 of 34 decided, against the 11 kube-bench automates.** The eighteen past parity are ones the
benchmark marks manual and kube-bench leaves that way. They are decidable here for the reason this
scanner exists: they are questions about pod specs, roles, bindings and namespaces, and correlating
those is what a `kubectl | jq | xargs` pipeline is worst at.

Why each stays with a person:

- **5.1.7** `system:masters`: membership is in a client certificate, which the API never sees.
- **5.3.1** whether the CNI enforces NetworkPolicy: a property of the network plugin, not an object.
- **5.5.1** ImagePolicyWebhook: an API server flag, readable only on the node.
- **5.4.2** external secret storage, and **5.6.1** namespaces as administrative boundaries: choices
  about how the system is built.

The catalog is pinned to `cis-1.12`, deliberately: the section is renumbered between revisions,
and silently tracking "the latest" would change what a rule id means underneath an exclusion
someone wrote against it.

### The catalog cannot quietly go out of date

A hand-maintained list of a benchmark someone else revises drifts, and drifts silently in both
directions. A check added upstream and missing here is never reported at all, so a scan covers
less than the benchmark and says nothing about it. A check retired upstream but left here is
reported forever, sending a reader after a requirement that no longer exists.

A test diffs the catalog against kube-bench's own definitions and fails on either drift, naming
the check. It runs in the integration suite against those definitions at a pinned commit, and the
tag is verified against them, because a benchmark that changed under a stable tag is precisely what
the check exists to notice.

The pin is kept in step with the image the in-cluster Job runs, so **bumping kube-bench is when a
benchmark revision is discovered**, rather than some later scan quietly covering the wrong thing.

Nothing here writes a check for us. It makes shipping an out-of-date catalog impossible to do
without noticing, which is the part that can be automated.

## Scoping to the namespaces you own

On a shared cluster the cluster is not the unit anyone owns:

```yaml
kubernetes:
  - cluster: prod-cluster
    namespaces: [team-a, team-a-jobs]
```

Most of what this section examines is namespace-scoped, default service accounts, token mounting,
and all five pod-security checks. A team owning three namespaces of eighty otherwise receives
seventy-seven namespaces' worth of findings it cannot act on, and a number that will never reach
zero is a number people stop reading. It also fixes what the component's `exposure` and
`criticality` mean, which otherwise assert a risk classification over everybody else's workloads.

**Scoping changes what is read, not what is kept.** Namespaced resources are listed per namespace
rather than cluster-wide and filtered afterwards, the distinction matters, because a credential
scoped to a few namespaces cannot perform the cluster-wide list at all, so filtering after the fact
would work only for people who did not need the feature.

The cluster-scoped checks, such as 5.1.1 on ClusterRoleBindings, do not run in a scoped scan. They
belong to the component that declares the whole cluster, so a shared cluster's answer is filed once
rather than once per team that owns a namespace of it. A scoped scan's required reads are all inside
its namespaces, so a credential limited to them can run it; [Permissions](#permissions) lists them.

The scope is part of the finding's location (`kubernetes/prod-cluster[team-a,team-a-jobs]`) and
part of the cache key. The same rule id against the same cluster means something different
depending on how much of it was examined.

**Only this scanner can honor a scope.** kube-bench writes `--all-namespaces` into its own
checks with no flag to change it, and the in-cluster Job reads a node filesystem that has no
namespace at all. Both **refuse** a scoped component rather than quietly auditing everything and
reporting it under a component that asked for three namespaces.

## The section this scanner does not read

Every managed benchmark ships a **Managed Services** section covering what the *provider* controls
rather than what the cluster does, image registry scanning, IAM, key management, node metadata,
cluster networking, logging, storage:

| benchmark | checks |
|---|---|
| `gke-1.9.0` | 33 |
| `eks-1.8.0` | 12 |
| `aks-1.8` | 13 |

Draugr evaluates none of it: reading those settings needs the cloud provider's own API, not the
Kubernetes one. That is a defensible gap. Leaving it unmentioned is not, a reader of the report has
no way to know the section exists, so the benchmark looks smaller than it is and a clean result
looks more complete than it is.

So a managed cluster gets one finding naming the section, its benchmark and its size. **One,
rather than one per check**, unlike the policies section: there the checks share a section this
scanner partly evaluates, so listing them individually is what keeps coverage honest. Here
nothing in the section is evaluated, and saying so once is unambiguous where fifty-eight
identical "review this yourself" entries would bury the findings that came from an actual
assessment.

The counts are held to kube-bench's own definitions by a test, because a number that drifts
understates the very thing it exists to disclose.

## What the report says about the run

The scanner records what it measured and against what, which travels in `--format json`,
`markdown`, `html` and SARIF's own run property bag:

```
Measured against
- kubernetes · draugr-k8s-policies: benchmark cis-1.12 · coverage 29 of 34 checks decided, 5 left for a person · scope whole cluster
- kubernetes · draugr-k8s-policies: benchmark cis-1.12 · coverage 22 of 22 checks decided · scope namespace team-a
```

Three facts, and each answers a question a reader has about a finding they are looking at.

**The benchmark** names the standard the checks came from, which is what makes the result defensible
to somebody who was not there, `cis-1.12` measures different things from `aks-1.8`.

**The coverage** is the figure a reader cannot otherwise get. Without it, a clean report gives no
hint that some of the section's checks were never decided by anything.

**The scope** says what the scan covered, and it is stated even when it covers everything. A scan of
the whole cluster and a scan whose scope nobody recorded are the same silence otherwise, and the
difference decides whether a finding belongs to the reader or to whoever owns the cluster, the
question a namespace owner asks first.

## Interpreting a finding

Rule ids are `draugr/cis/<check number>`, namespaced by the scanner that emitted them.
[`kube-bench`](kube-bench.md) audits the same benchmark with the same numbering, and a bare
`cis/5.1.1` would be an id two tools both claim, which is a real collision outside Draugr's own
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

### Severity

No check in this section is scored by the benchmark, so the severity comes from the
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/):

| Severity | Checks |
|---|---|
| high | what the **Baseline** profile forbids: `5.2.2` privileged, `5.2.3` host PID, `5.2.4` host IPC, `5.2.5` host network, `5.2.10` Windows HostProcess, `5.2.11` hostPath volumes, `5.2.12` host ports; and `5.1.1`, a binding to `cluster-admin` |
| medium | every other decided check |

The scored checks of the benchmark are in sections 1–4, which [`kube-bench-job`](kube-bench-job.md)
reads.

With no exposure or criticality declared, a high finding is P1, so a privileged pod or a host mount
fails the default gate.

### Ownership

A new cluster fails several of these checks with objects its distribution installed, such as
`kube-proxy` on kind. Each check is one row: your objects first, then `the distribution's:` objects.
A check only the distribution's objects fail is **low**, so it appears in the report without failing
the gate. On a kind cluster with a `ClusterRoleBinding` named `superadmin` to `cluster-admin`:

```
draugr/cis/5.1.1 · bound to cluster-admin: superadmin; the distribution's: bound to cluster-admin: kubeadm:cluster-admins
```

An object is the distribution's when it is a pod in `kube-system`, or an RBAC object Kubernetes
labels as one of its defaults (`kubernetes.io/bootstrapping: rbac-defaults`) or names with a prefix
Kubernetes or kubeadm reserves, `system:` or `kubeadm:`. `kube-system` is a stand-in for the
distribution's own pods. A workload you install there is listed after `the distribution's:`, and a
check that only such objects fail is low, so look through that part of the row for anything you put
there.

A decided check that passes produces no finding, for the same reason a clean dependency does not.

## Permissions

The scanner reads the cluster, changes nothing in it and schedules no pod, the distinction from
[`kube-bench-job`](kube-bench-job.md), which declares `mutate` and `privilege` effects and does not
run until they are accepted.

Kubernetes decides what a credential may read with RBAC: a Role or ClusterRole is a named set of
permissions, and a binding grants one to a user, group or service account. The scanner's reads fall
in two groups:

- A **required** read is one the scan cannot do without. If the API server refuses it, the
  `kubernetes` control reports an error naming the read, and no check is decided.
- An **optional** read serves particular checks. If it is refused, those checks are left for a person
  and the scan completes.

The built-in `view` ClusterRole, the usual read-only grant, is not enough. It cannot read Roles,
ClusterRoles or their bindings, so a scan of the whole cluster stops at its first read. Grant the
role under [A role to grant](#a-role-to-grant) instead.

### Scanning the whole cluster

Required, `list` across all namespaces:

| Resource | API group | Checks |
|---|---|---|
| `clusterrolebindings` | `rbac.authorization.k8s.io` | 5.1.1, 5.1.8 to 5.1.13 |
| `clusterroles` | `rbac.authorization.k8s.io` | 5.1.3, 5.1.8 to 5.1.13 |
| `roles` | `rbac.authorization.k8s.io` | 5.1.3, 5.1.8 to 5.1.13 |
| `serviceaccounts` | core | 5.1.5, 5.1.6 |
| `pods` | core | 5.1.6, 5.2.2 to 5.2.12, 5.4.1, 5.6.2 to 5.6.4 |

Optional:

| Permission | API group | If refused |
|---|---|---|
| `list` `rolebindings` | `rbac.authorization.k8s.io` | 5.1.8 to 5.1.13 are left for a person |
| `list` `namespaces` | core | 5.2.1 and 5.3.2 are left for a person |
| `list` `networkpolicies` | `networking.k8s.io` | 5.3.2 is left for a person |
| `list` `validatingwebhookconfigurations` | `admissionregistration.k8s.io` | 5.2.1 is left for a person, unless a namespace enforces a Pod Security level other than `privileged` or a ValidatingAdmissionPolicy is bound |
| `list` `validatingadmissionpolicybindings` | `admissionregistration.k8s.io` | 5.2.1 is decided from the other two mechanisms alone |
| `create` `subjectaccessreviews` | `authorization.k8s.io` | 5.1.2 and 5.1.4 are left for a person (see ¹ above) |
| `list` `nodes` | core | an AKS cluster is not recognized, so its Managed Services finding is missing |

### Scanning namespaces

A scan scoped to `namespaces` reads only inside them, except for the two cluster-wide permissions
listed as optional below.

Required, `list` in each namespace named: `roles`, `serviceaccounts` and `pods`.

Optional:

| Permission | API group | If refused |
|---|---|---|
| `list` `rolebindings` | `rbac.authorization.k8s.io` | 5.1.8 and 5.1.13 are left for a person |
| `get` on each ClusterRole a binding in the namespaces names | `rbac.authorization.k8s.io` | 5.1.8 and 5.1.13 are left for a person |
| `list` `networkpolicies` | `networking.k8s.io` | 5.3.2 is left for a person |
| `create` `subjectaccessreviews` | `authorization.k8s.io` | 5.1.2 and 5.1.4 are left for a person |

### A role to grant

This ClusterRole holds every permission above, required and optional, and nothing else:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: draugr-k8s-policies
rules:
  # get is for a scan scoped to namespaces, which reads each ClusterRole a binding there names.
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings", "clusterroles", "rolebindings", "roles"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["namespaces", "nodes", "pods", "serviceaccounts"]
    verbs: ["list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["list"]
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingadmissionpolicybindings", "validatingwebhookconfigurations"]
    verbs: ["list"]
  # Asks the API server whether every signed-in user holds a permission (5.1.2, 5.1.4). The server
  # answers and stores nothing.
  - apiGroups: ["authorization.k8s.io"]
    resources: ["subjectaccessreviews"]
    verbs: ["create"]
```

To scan the whole cluster, bind it across the cluster to the identity Draugr runs as, here a service
account `draugr` in the namespace `security`:

```bash
kubectl create clusterrolebinding draugr-k8s-policies \
  --clusterrole=draugr-k8s-policies --serviceaccount=security:draugr
```

To scan only some namespaces, bind it in each of them instead:

```bash
kubectl create rolebinding draugr-k8s-policies --namespace=team-a \
  --clusterrole=draugr-k8s-policies --serviceaccount=security:draugr
```

A binding made in a namespace grants the role's permissions in that namespace only, which covers
every required read. It cannot grant the two cluster-wide ones, `get` on ClusterRoles and `create`
on SubjectAccessReviews, so with namespace bindings alone 5.1.2, 5.1.4, 5.1.8 and 5.1.13 are left
for a person: the binding above names a ClusterRole, the one this page defines, and the scan cannot
read it through that binding. To have the four decided, grant those two permissions across the
cluster as well, with a ClusterRoleBinding to a ClusterRole holding only them.

`kubectl auth can-i --list --namespace <namespace>` lists those two permissions under a namespace
binding, because it prints the rules of the role that binding names. They take effect only across
the cluster, which is why the scan leaves the four checks for a person.

## Links

- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes

## Notes

- No external binary, so nothing for `draugr tools install` to fetch and nothing for
  `draugr doctor` to report missing. The `kubectl` requirement that
  [`kube-bench`](kube-bench.md) carries does not apply here.
- The cluster is chosen the same way as the control's other scanners: the cluster's `context`
  under `clusters:`, or the ambient kubeconfig context.
- Findings are located at the cluster (`kubernetes/<name>`), not a file. That is what was
  assessed.
- The pod of a [`kube-bench-job`](kube-bench-job.md) Job the same run created is left out of the
  pod checks. It is privileged and mounts host paths, and it runs while the pods are read. A pod is
  recognized by the Job that owns it, which the run names before creating it, and never by a label,
  which any pod can carry.

## Data

Nothing. The CIS policy set is compiled into Draugr, which is why the cache key carries
Draugr's own version: a corrected check has to invalidate results the previous one produced.
