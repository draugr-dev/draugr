package scanners

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// k8sPoliciesScannerName identifies the native reader of the CIS policies section.
const k8sPoliciesScannerName = "k8s-policies"

// k8sPoliciesScanner evaluates the CIS Kubernetes Benchmark's policies section against the
// Kubernetes API directly, instead of shelling out to kube-bench.
//
// The section is the part of the benchmark that can be answered without standing on a node, and
// kube-bench answers it by running a shell pipeline per check — several of them once per pod.
// Against a shared cluster of 78 namespaces a single pass takes tens of minutes, because the
// cost is a subprocess and a fresh credential exchange per object rather than the query itself.
//
// The same questions are a handful of List calls. That is the immediate reason for this scanner,
// but not the interesting one: a check expressed in Go can decide things a `kubectl | jq`
// pipeline cannot, and it can be scoped to the namespaces a team actually owns — which is
// impossible through kube-bench, whose queries carry --all-namespaces inside the config.
type k8sPoliciesScanner struct {
	info plugin.ScannerInfo
	// client builds a Kubernetes client for a context; injectable for tests.
	client func(kubeCtx string) (kubernetes.Interface, error)
}

// NewK8sPolicies returns a Scanner that reads the CIS policies section through the Kubernetes API.
func NewK8sPolicies() plugin.Scanner {
	return k8sPoliciesScanner{
		info: plugin.ScannerInfo{
			Name: k8sPoliciesScannerName,
			// No Binary: this scanner is the tool. Nothing to install, and nothing for
			// `draugr doctor` to report missing.
			Controls:    []string{"infrastructure"},
			TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
		},
		client: clientForContext,
	}
}

// Info describes the scanner.
func (s k8sPoliciesScanner) Info() plugin.ScannerInfo { return s.info }

// Scan evaluates the policies section against the cluster the target names.
//
// Every check in the section is answered. The ones implemented here get a verdict from the
// cluster's actual state; the rest are reported as requiring a human, which is what CIS says
// about them and what kube-bench reports too. A partially implemented scanner that omitted the
// rest would return a shorter, cleaner report that quietly means less.
func (s k8sPoliciesScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	if _, ok := target.(plugin.InfraTarget); !ok {
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want infrastructure)", k8sPoliciesScannerName, target)
	}
	kubeCtx := kubeContext(target, cfg)
	client, err := s.client(kubeCtx)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", k8sPoliciesScannerName, err)
	}

	infra, _ := target.(plugin.InfraTarget)
	decided, err := evaluatePolicies(ctx, client, infra.Namespaces)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", k8sPoliciesScannerName, err)
	}
	return policiesReport(decided, clusterScopeLabel(kubeCtx, infra.Namespaces)), nil
}

// policyVerdict is the outcome of a check this scanner implements.
type policyVerdict struct {
	// Compliant reports whether the cluster satisfies the check.
	Compliant bool
	// Detail names what failed, e.g. the bindings or roles at fault. Empty when compliant.
	Detail string
}

// evaluatePolicies runs the implemented checks and returns their verdicts by rule id.
//
// One List per resource kind, reused across checks. kube-bench re-queries per check and, for the
// pod-security ones, per pod; the cost of that is the whole reason this exists.
func evaluatePolicies(ctx context.Context, client kubernetes.Interface, namespaces []string) (map[string]policyVerdict, error) {
	out := map[string]policyVerdict{}
	scoped := len(namespaces) > 0

	// Cluster-scoped reads. When the audit is scoped, the credential running it may be scoped
	// too — a team with read on its own namespaces and nothing else is the normal case, and the
	// one this feature exists for. So being refused here leaves the check undecided rather than
	// failing the run: the namespaced checks are still worth having, and a check reported for
	// manual review is an honest answer where an aborted scan is none.
	//
	// Unscoped, the same refusal is a real failure. Nothing was asked to be narrowed, so a
	// cluster-wide audit that cannot read cluster-wide objects has not audited the cluster.
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	switch {
	case err == nil:
		out["5.1.1"] = checkClusterAdminBindings(crbs.Items)
	case !scoped:
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}

	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil && !scoped {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}

	roles, err := listNamespaced(namespaces, func(ns string) (*rbacv1.RoleList, error) {
		return client.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
	}, func(l *rbacv1.RoleList) []rbacv1.Role { return l.Items })
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	out["5.1.3"] = checkWildcardRules(roles, clusterRoles.Items)

	accounts, err := listNamespaced(namespaces, func(ns string) (*corev1.ServiceAccountList, error) {
		return client.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	}, func(l *corev1.ServiceAccountList) []corev1.ServiceAccount { return l.Items })
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	out["5.1.5"] = checkDefaultServiceAccounts(accounts)

	pods, err := listNamespaced(namespaces, func(ns string) (*corev1.PodList, error) {
		return client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	}, func(l *corev1.PodList) []corev1.Pod { return l.Items })
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	maps.Copy(out, evaluatePodSecurity(pods, accounts))

	// Last, and never fatal: these ask the authorizer, which a read-only credential may not be
	// allowed to do. Whatever it cannot answer stays undecided and is reported for review.
	maps.Copy(out, evaluateBroadAccess(ctx, client, namespaces))

	return out, nil
}

// checkClusterAdminBindings implements 5.1.1.
//
// cluster-admin is unbounded, so the benchmark asks that nothing be bound to it beyond the
// binding Kubernetes ships for its own bootstrap — `cluster-admin`, which grants it to
// system:masters. Any other binding to that role is what the check looks for.
func checkClusterAdminBindings(bindings []rbacv1.ClusterRoleBinding) policyVerdict {
	var offenders []string
	for _, b := range bindings {
		if b.RoleRef.Name != "cluster-admin" || b.Name == "cluster-admin" {
			continue
		}
		offenders = append(offenders, b.Name)
	}
	if len(offenders) == 0 {
		return policyVerdict{Compliant: true}
	}
	sort.Strings(offenders)
	return policyVerdict{Detail: "bound to cluster-admin: " + strings.Join(offenders, ", ")}
}

// checkWildcardRules implements 5.1.3.
//
// A wildcard in any of apiGroups, resources or verbs grants whatever those fields come to mean
// later, so a role written today silently widens as the cluster gains APIs.
func checkWildcardRules(roles []rbacv1.Role, clusterRoles []rbacv1.ClusterRole) policyVerdict {
	var offenders []string
	for _, r := range roles {
		if rulesUseWildcard(r.Rules) {
			offenders = append(offenders, "role "+r.Namespace+"/"+r.Name)
		}
	}
	for _, r := range clusterRoles {
		if rulesUseWildcard(r.Rules) {
			offenders = append(offenders, "clusterrole "+r.Name)
		}
	}
	if len(offenders) == 0 {
		return policyVerdict{Compliant: true}
	}
	sort.Strings(offenders)
	return policyVerdict{Detail: "wildcards in " + summarize(offenders)}
}

func rulesUseWildcard(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		for _, set := range [][]string{rule.APIGroups, rule.Resources, rule.Verbs} {
			for _, v := range set {
				if v == "*" {
					return true
				}
			}
		}
	}
	return false
}

// checkDefaultServiceAccounts implements 5.1.5.
//
// Every namespace has a default service account, and a pod that names none is given it. The
// benchmark asks that it not be usable against the API — automountServiceAccountToken set to
// false — so that a workload which never asked for credentials is not handed any.
//
// An unset field is not compliant: the default is to mount.
func checkDefaultServiceAccounts(accounts []corev1.ServiceAccount) policyVerdict {
	var offenders []string
	for _, sa := range accounts {
		if sa.Name != "default" {
			continue
		}
		if sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
			continue
		}
		offenders = append(offenders, sa.Namespace)
	}
	if len(offenders) == 0 {
		return policyVerdict{Compliant: true}
	}
	sort.Strings(offenders)
	return policyVerdict{Detail: "default service account still mounts a token in " + summarize(offenders)}
}

// summarize lists offenders without letting one finding become a wall of text. A reader needs
// enough to recognize the problem; the full set is a query away once they know to look.
func summarize(items []string) string {
	const show = 5
	if len(items) <= show {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:show], ", "), len(items)-show)
}

// policiesReport renders the whole section: a verdict where there is one, a manual prompt
// everywhere else.
func policiesReport(decided map[string]policyVerdict, location string) sarif.Report {
	report := sarif.Report{Tool: k8sPoliciesScannerName, Rules: map[string]sarif.Rule{}}

	for _, check := range cisPolicies {
		ruleID := "cis/" + check.ID
		verdict, implemented := decided[check.ID]
		if implemented && verdict.Compliant {
			// A passing check is not a finding, for the same reason a clean dependency is not
			// one: three hundred passes bury the dozen failures.
			continue
		}

		message := check.Title + " — requires manual review"
		if implemented {
			message = check.Title + " — " + verdict.Detail
		}

		report.Results = append(report.Results, sarif.Result{
			Tool:     k8sPoliciesScannerName,
			RuleID:   ruleID,
			Level:    sarif.LevelWarning,
			Message:  message,
			Location: sarif.Location{URI: location},
		})
		report.Rules[ruleID] = sarif.Rule{
			Name:             "CIS " + check.ID,
			ShortDescription: check.Title,
			FullDescription:  check.Remediation,
			HelpURI:          "https://www.cisecurity.org/benchmark/kubernetes",
		}
	}
	return report
}

// evaluatePodSecurity implements 5.1.6 and 5.2.2 through 5.2.6 from a single Pod listing.
//
// kube-bench answers each of these by listing pods and then running `kubectl get pod` once more
// per pod, per check — six passes over every workload in the cluster. They are all questions
// about a pod spec, so one List answers all of them.
//
// A running pod is evidence, not policy. CIS asks whether admission *prevents* these settings,
// and a cluster with none of them today may simply not have been asked yet. Reporting what is
// actually running is the same thing kube-bench reports, and is the answerable half: 5.2.1 —
// whether a policy mechanism is in place — stays a manual check.
func evaluatePodSecurity(pods []corev1.Pod, accounts []corev1.ServiceAccount) map[string]policyVerdict {
	automountByAccount := map[string]bool{}
	for _, sa := range accounts {
		if sa.AutomountServiceAccountToken != nil {
			automountByAccount[sa.Namespace+"/"+sa.Name] = *sa.AutomountServiceAccountToken
		}
	}

	var tokens, privileged, hostPID, hostIPC, hostNet, escalation []string
	for i := range pods {
		pod := &pods[i]
		where := pod.Namespace + "/" + pod.Name

		if podMountsToken(pod, automountByAccount) {
			tokens = append(tokens, where)
		}
		if pod.Spec.HostPID {
			hostPID = append(hostPID, where)
		}
		if pod.Spec.HostIPC {
			hostIPC = append(hostIPC, where)
		}
		if pod.Spec.HostNetwork {
			hostNet = append(hostNet, where)
		}
		for _, c := range allContainers(pod) {
			sc := c.SecurityContext
			if sc == nil {
				continue
			}
			if sc.Privileged != nil && *sc.Privileged {
				privileged = append(privileged, where+"/"+c.Name)
			}
			if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
				escalation = append(escalation, where+"/"+c.Name)
			}
		}
	}

	return map[string]policyVerdict{
		"5.1.6": verdictFrom(tokens, "mounting a service account token without needing one"),
		"5.2.2": verdictFrom(privileged, "running privileged"),
		"5.2.3": verdictFrom(hostPID, "sharing the host PID namespace"),
		"5.2.4": verdictFrom(hostIPC, "sharing the host IPC namespace"),
		"5.2.5": verdictFrom(hostNet, "sharing the host network namespace"),
		"5.2.6": verdictFrom(escalation, "allowing privilege escalation"),
	}
}

// podMountsToken implements 5.1.6.
//
// A pod is handed API credentials unless something says otherwise, and either the pod or its
// service account can say so. The pod wins where both speak, which is how Kubernetes resolves it
// — reading only one of the two would mark a correctly hardened workload as a finding.
func podMountsToken(pod *corev1.Pod, automountByAccount map[string]bool) bool {
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	name := pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	if mounts, set := automountByAccount[pod.Namespace+"/"+name]; set {
		return mounts
	}
	// Neither said anything, and the default is to mount.
	return true
}

// allContainers returns every container in a pod, init and ephemeral included.
//
// An init container runs with the same privileges and can do the same damage in the seconds it
// is alive; a check that only looked at spec.containers would pass a pod that mounts the host
// filesystem as root before the workload ever starts.
func allContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	out = append(out, pod.Spec.Containers...)
	out = append(out, pod.Spec.InitContainers...)
	for _, e := range pod.Spec.EphemeralContainers {
		out = append(out, corev1.Container(e.EphemeralContainerCommon))
	}
	return out
}

// verdictFrom turns a list of offenders into a verdict, or a pass when there are none.
func verdictFrom(offenders []string, doing string) policyVerdict {
	if len(offenders) == 0 {
		return policyVerdict{Compliant: true}
	}
	sort.Strings(offenders)
	return policyVerdict{Detail: fmt.Sprintf("%d %s: %s", len(offenders), doing, summarize(offenders))}
}

// evaluateBroadAccess implements 5.1.2 and 5.1.4 by asking the cluster's own authorizer.
//
// These two are not role scans. The benchmark asks whether *everyone* can read secrets or create
// pods, and the honest way to answer is to ask the authorizer rather than reassemble its decision
// from roles and bindings — RBAC is additive across bindings, aggregated ClusterRoles resolve at
// runtime, and a webhook authorizer can grant what no Role mentions. A reimplementation would
// disagree with the cluster in exactly the cases that matter.
//
// So Draugr asks the same question kube-bench does — `can-i ... --as=system:authenticated` — via
// a SubjectAccessReview. Every authenticated identity holds that group, so a yes means any
// account that can log in can do this.
//
// A SubjectAccessReview creates nothing: it is a query the API server answers and discards. But
// submitting one requires the `create` verb on `subjectaccessreviews`, which a deliberately
// read-only credential will not have — so being refused is expected, not exceptional. The check
// is then left undecided and reported for manual review, which is the same answer a reader gets
// for every check this scanner cannot settle. Failing the scan over a permission it was never
// promised would turn a partial answer into no answer.
func evaluateBroadAccess(ctx context.Context, client kubernetes.Interface, namespaces []string) map[string]policyVerdict {
	out := map[string]policyVerdict{}

	type query struct {
		id       string
		verbs    []string
		resource string
		phrase   string
	}
	for _, q := range []query{
		{"5.1.2", []string{"get", "list", "watch"}, "secrets", "read secrets"},
		{"5.1.4", []string{"create"}, "pods", "create pods"},
	} {
		var allowed []string
		undecided := false
		for _, verb := range q.verbs {
			// Scoped, the question becomes "can everyone do this *here*", which is the one a
			// namespace owner can act on — and the only one they are likely to be permitted to
			// ask. Unscoped it stays cluster-wide, as before.
			ok, err := allowedForAllAuthenticated(ctx, client, verb, q.resource, namespaces)
			if err != nil {
				undecided = true
				break
			}
			if ok {
				allowed = append(allowed, verb)
			}
		}
		if undecided {
			continue
		}
		if len(allowed) == 0 {
			out[q.id] = policyVerdict{Compliant: true}
			continue
		}
		out[q.id] = policyVerdict{Detail: fmt.Sprintf(
			"every authenticated user can %s (%s)", q.phrase, strings.Join(allowed, ", "))}
	}
	return out
}

// allowedForAllAuthenticated asks whether the system:authenticated group holds a permission
// across all namespaces.
func allowedForAllAuthenticated(ctx context.Context, client kubernetes.Interface, verb, resource string, namespaces []string) (bool, error) {
	// Unscoped means every namespace, which an empty Namespace already expresses.
	scopes := namespaces
	if len(scopes) == 0 {
		scopes = []string{""}
	}
	for _, ns := range scopes {
		review := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				Groups: []string{"system:authenticated"},
				ResourceAttributes: &authzv1.ResourceAttributes{
					Verb:      verb,
					Resource:  resource,
					Namespace: ns,
				},
			},
		}
		result, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		// Allowed anywhere in scope is a finding: the check asks whether the permission is held
		// too widely, and one namespace where it is holds the answer.
		if result.Status.Allowed {
			return true, nil
		}
	}
	return false, nil
}

// listNamespaced lists a namespaced resource across the audit's scope.
//
// An empty scope means the whole cluster, which is one call against all namespaces. A scope
// means one call per namespace rather than a cluster-wide list filtered afterwards — the
// difference matters, because a credential scoped to a few namespaces cannot perform the
// cluster-wide list at all. Filtering after the fact would work only for people who did not need
// the feature.
func listNamespaced[L any, T any](
	namespaces []string,
	list func(ns string) (L, error),
	items func(L) []T,
) ([]T, error) {
	if len(namespaces) == 0 {
		l, err := list(metav1.NamespaceAll)
		if err != nil {
			return nil, err
		}
		return items(l), nil
	}
	var out []T
	for _, ns := range namespaces {
		l, err := list(ns)
		if err != nil {
			return nil, fmt.Errorf("namespace %q: %w", ns, err)
		}
		out = append(out, items(l)...)
	}
	return out, nil
}

// clusterScopeLabel names what was assessed, scope included.
//
// A finding located at the cluster when only part of it was examined overstates the evidence:
// the same rule id against `kubernetes/prod` means something different depending on whether
// seventy-seven other namespaces were looked at.
func clusterScopeLabel(kubeCtx string, namespaces []string) string {
	label := clusterLabel(kubeCtx)
	if len(namespaces) == 0 {
		return label
	}
	ns := slices.Clone(namespaces)
	slices.Sort(ns)
	return label + "[" + strings.Join(ns, ",") + "]"
}
