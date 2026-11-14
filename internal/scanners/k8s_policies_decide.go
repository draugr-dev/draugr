package scanners

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/draugr-dev/draugr/internal/english"
)

// The checks below are ones the benchmark marks Manual, which the cluster's API answers all the
// same: who holds a permission is in the roles and their bindings, whether a namespace has a
// NetworkPolicy is a list, and how a pod receives a secret is in its spec. What stays a person's
// call, whether somebody should hold a permission, is made on a finding naming them rather than on
// a check left blank.
//
// Each read here is one the checks already in place did not need, so a credential granted only
// those may be refused it. A refusal leaves the checks that needed the read undecided, reported for
// a person as before, rather than failing a scan that used to complete.

// accessGrant is one permission an access check looks for: a verb on a resource in an API group.
type accessGrant struct {
	verbs    []string
	group    string
	resource string
}

// accessCheck is a "minimize access" check: the permissions it asks about, and how a finding says it.
type accessCheck struct {
	id     string
	grants []accessGrant
	phrase string
	// clusterScoped checks run only over the whole cluster, as the catalog marks them.
	clusterScoped bool
}

// writeVerbs are the verbs that change an object.
var writeVerbs = []string{"create", "update", "patch", "delete"}

// accessChecks are 5.1.8 through 5.1.13.
var accessChecks = []accessCheck{
	{id: "5.1.8", phrase: "bind, escalate or impersonate", grants: []accessGrant{
		{[]string{"bind", "escalate"}, rbacv1.GroupName, "roles"},
		{[]string{"bind", "escalate"}, rbacv1.GroupName, "clusterroles"},
		{[]string{"impersonate"}, "", "users"},
		{[]string{"impersonate"}, "", "groups"},
		{[]string{"impersonate"}, "", "serviceaccounts"},
	}},
	{id: "5.1.9", phrase: "create persistent volumes", clusterScoped: true, grants: []accessGrant{
		{[]string{"create"}, "", "persistentvolumes"},
	}},
	{id: "5.1.10", phrase: "use the nodes/proxy subresource", clusterScoped: true, grants: []accessGrant{
		{[]string{"get", "create", "update", "patch", "delete"}, "", "nodes/proxy"},
	}},
	{id: "5.1.11", phrase: "approve certificate signing requests", clusterScoped: true, grants: []accessGrant{
		{[]string{"update", "patch"}, "certificates.k8s.io", "certificatesigningrequests/approval"},
	}},
	{id: "5.1.12", phrase: "change admission webhook configurations", clusterScoped: true, grants: []accessGrant{
		{writeVerbs, admissionv1.GroupName, "validatingwebhookconfigurations"},
		{writeVerbs, admissionv1.GroupName, "mutatingwebhookconfigurations"},
	}},
	{id: "5.1.13", phrase: "create service account tokens", grants: []accessGrant{
		{[]string{"create"}, "", "serviceaccounts/token"},
	}},
}

// ruleGrants reports whether an RBAC rule grants any of g's verbs on its resource. A wildcard in a
// field matches anything, and "nodes/*" matches "nodes/proxy". Resource names narrow a rule to
// named objects, but the permission is held all the same, so they are not read.
func ruleGrants(rule rbacv1.PolicyRule, g accessGrant) bool {
	matchVerb := false
	for _, v := range rule.Verbs {
		if v == "*" || slices.Contains(g.verbs, v) {
			matchVerb = true
			break
		}
	}
	if !matchVerb || !slices.Contains(rule.APIGroups, "*") && !slices.Contains(rule.APIGroups, g.group) {
		return false
	}
	parent, sub, hasSub := strings.Cut(g.resource, "/")
	for _, r := range rule.Resources {
		if r == "*" || r == g.resource || hasSub && (r == parent+"/*" || r == "*/"+sub) {
			return true
		}
	}
	return false
}

// boundRole is a role some binding grants, the subjects it is granted to, and whether every binding
// granting it is the distribution's.
type boundRole struct {
	name         string
	subjects     []string
	rules        []rbacv1.PolicyRule
	distribution bool
}

// subjectName renders a binding's subject the way kubectl names its kind: "serviceaccount
// team-a/ci", "user alice", "group devs".
func subjectName(s rbacv1.Subject, bindingNamespace string) string {
	switch s.Kind {
	case rbacv1.ServiceAccountKind:
		ns := s.Namespace
		if ns == "" {
			ns = bindingNamespace
		}
		return "serviceaccount " + ns + "/" + s.Name
	case rbacv1.UserKind:
		return "user " + s.Name
	case rbacv1.GroupKind:
		return "group " + s.Name
	}
	return strings.ToLower(s.Kind) + " " + s.Name
}

// holders says who a role is bound to, a few by name, so a finding names who holds the permission.
func (r boundRole) holders() string {
	const show = 3
	if len(r.subjects) <= show {
		return strings.Join(r.subjects, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(r.subjects[:show], ", "), len(r.subjects)-show)
}

// distributionBinding says a binding is the distribution's: a cluster binding Kubernetes or kubeadm
// made, or a namespaced one in kube-system or named as theirs.
func distributionBinding(namespace, name string, labels map[string]string) bool {
	return namespace == distributionNamespace || distributionRBAC(name, labels)
}

// boundRoles are the roles a binding grants to somebody. A role nothing binds grants nothing, so it
// is not access held, and neither is a binding with no subjects. A role counts as the distribution's only when the role is and every binding
// granting it is, since an operator binding the built-in edit role to a team gave that team access.
func boundRoles(
	clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role,
	clusterBindings []rbacv1.ClusterRoleBinding, bindings []rbacv1.RoleBinding,
) []boundRole {
	type ref struct{ kind, namespace, name string }
	owned := map[ref]bool{}
	holders := map[ref]map[string]bool{}
	note := func(r ref, namespace string, subjects []rbacv1.Subject, distribution bool) {
		if len(subjects) == 0 {
			return
		}
		if holders[r] == nil {
			holders[r] = map[string]bool{}
		}
		for _, s := range subjects {
			holders[r][subjectName(s, namespace)] = true
		}
		if !distribution {
			owned[r] = true
		}
	}
	for _, b := range clusterBindings {
		if b.RoleRef.Kind == "ClusterRole" {
			note(ref{"ClusterRole", "", b.RoleRef.Name}, "", b.Subjects, distributionBinding("", b.Name, b.Labels))
		}
	}
	for _, b := range bindings {
		switch b.RoleRef.Kind {
		case "ClusterRole":
			note(ref{"ClusterRole", "", b.RoleRef.Name}, b.Namespace, b.Subjects, distributionBinding(b.Namespace, b.Name, b.Labels))
		case "Role":
			note(ref{"Role", b.Namespace, b.RoleRef.Name}, b.Namespace, b.Subjects, distributionBinding(b.Namespace, b.Name, b.Labels))
		}
	}
	subjects := func(k ref) []string {
		out := slices.Collect(maps.Keys(holders[k]))
		slices.Sort(out)
		return out
	}
	var out []boundRole
	for _, r := range clusterRoles {
		k := ref{"ClusterRole", "", r.Name}
		if holders[k] != nil {
			out = append(out, boundRole{"clusterrole " + r.Name, subjects(k), r.Rules, !owned[k] && distributionRBAC(r.Name, r.Labels)})
		}
	}
	for _, r := range roles {
		k := ref{"Role", r.Namespace, r.Name}
		if holders[k] != nil {
			out = append(out, boundRole{"role " + r.Namespace + "/" + r.Name, subjects(k), r.Rules, !owned[k] && r.Namespace == distributionNamespace})
		}
	}
	return out
}

// checkAccess implements one access check over the roles somebody is bound to. Each offender is the
// role, and the finding names who holds it, "role team-a/deployer (bound to serviceaccount team-a/ci)",
// since the question it leaves the reader is whether those subjects should.
//
// The role alone is the object a comparison of two scans pairs the check on. Its holders change
// whenever somebody joins or leaves a team, and the role failing the check is the same failure
// either way: a holder in the object would make a check that still fails read as fixed, or one
// somebody was only removed from read as new.
func checkAccess(c accessCheck, roles []boundRole) policyVerdict {
	var offenders []string
	distribution := map[string]bool{}
	held := map[string]string{}
	for _, r := range roles {
		if grantsAny(r.rules, c.grants) {
			offenders = append(offenders, r.name)
			distribution[r.name] = r.distribution
			held[r.name] = r.name + " (bound to " + r.holders() + ")"
		}
	}
	return failing(offenders, func(o string) bool { return distribution[o] }, func(l []string) string {
		named := make([]string, 0, len(l))
		for _, o := range l {
			named = append(named, held[o])
		}
		return english.Count(len(l), "role") + " granting permission to " + c.phrase + ": " + summarize(named)
	})
}

func grantsAny(rules []rbacv1.PolicyRule, grants []accessGrant) bool {
	for _, rule := range rules {
		for _, g := range grants {
			if ruleGrants(rule, g) {
				return true
			}
		}
	}
	return false
}

// evaluateAccess implements 5.1.8 through 5.1.13.
//
// Over the whole cluster it reads every ClusterRole bound anywhere. A run scoped to namespaces reads
// the roles bound there, fetching each ClusterRole a binding there names; where one cannot be read,
// the namespaced checks stay undecided rather than answering from part of the grants.
func evaluateAccess(
	ctx context.Context, client kubernetes.Interface, namespaces []string,
	clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role,
) map[string]policyVerdict {
	out := map[string]policyVerdict{}
	scoped := len(namespaces) > 0

	bindings, err := listNamespaced(namespaces, func(ns string) (*rbacv1.RoleBindingList, error) {
		return client.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	}, func(l *rbacv1.RoleBindingList) []rbacv1.RoleBinding { return l.Items })
	if err != nil {
		return out
	}
	var clusterBindings []rbacv1.ClusterRoleBinding
	if !scoped {
		crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
		if err != nil {
			return out
		}
		clusterBindings = crbs.Items
	} else {
		// The ClusterRoles bindings in scope grant, read one by one: a namespace owner's credential
		// can usually get a named role where it cannot list them all.
		seen := map[string]bool{}
		for _, b := range bindings {
			if b.RoleRef.Kind != "ClusterRole" || seen[b.RoleRef.Name] {
				continue
			}
			seen[b.RoleRef.Name] = true
			cr, err := client.RbacV1().ClusterRoles().Get(ctx, b.RoleRef.Name, metav1.GetOptions{})
			if err != nil {
				return out
			}
			clusterRoles = append(clusterRoles, *cr)
		}
	}

	bound := boundRoles(clusterRoles, roles, clusterBindings, bindings)
	for _, c := range accessChecks {
		if scoped && c.clusterScoped {
			continue
		}
		out[c.id] = checkAccess(c, bound)
	}
	return out
}

// distributionNamespaces are the namespaces Kubernetes itself creates. kube-system holds the
// distribution's workloads; kube-public and kube-node-lease hold no workloads at all.
var distributionNamespaces = map[string]bool{
	distributionNamespace: true, "kube-public": true, "kube-node-lease": true,
}

// evaluateNetworkPolicies implements 5.3.2: every namespace has at least one NetworkPolicy.
//
// Whether a policy allows the right traffic is the reader's to judge. Whether there is one is a
// list, and a namespace with none admits everything from everywhere.
func evaluateNetworkPolicies(ctx context.Context, client kubernetes.Interface, namespaces []string) (policyVerdict, bool) {
	names := namespaces
	if len(names) == 0 {
		list, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return policyVerdict{}, false
		}
		for _, ns := range list.Items {
			names = append(names, ns.Name)
		}
	}
	policies, err := listNamespaced(namespaces, func(ns string) (*networkingv1.NetworkPolicyList, error) {
		return client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	}, func(l *networkingv1.NetworkPolicyList) []networkingv1.NetworkPolicy { return l.Items })
	if err != nil {
		return policyVerdict{}, false
	}
	covered := map[string]bool{}
	for _, p := range policies {
		covered[p.Namespace] = true
	}
	var offenders []string
	for _, ns := range names {
		if !covered[ns] {
			offenders = append(offenders, ns)
		}
	}
	return failing(offenders, func(ns string) bool { return distributionNamespaces[ns] }, func(l []string) string {
		return english.Count(len(l), "namespace") + " with no NetworkPolicy: " + summarize(l)
	}), true
}

// checkSecretsInEnvironment implements 5.4.1: a secret handed to a container as an environment
// variable, rather than mounted as a file. The environment is copied into child processes and
// printed by crash reports and debug endpoints, which a file is not.
func checkSecretsInEnvironment(pods []corev1.Pod) policyVerdict {
	var offenders []string
	for i := range pods {
		pod := &pods[i]
		for _, c := range allContainers(pod) {
			if containerReadsSecretFromEnv(c) {
				offenders = append(offenders, pod.Namespace+"/"+pod.Name+"/"+c.Name)
			}
		}
	}
	return verdictFrom(offenders, "with a secret in an environment variable")
}

func containerReadsSecretFromEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			return true
		}
	}
	for _, e := range c.EnvFrom {
		if e.SecretRef != nil {
			return true
		}
	}
	return false
}

// podSecurityEnforceLabel is the namespace label Pod Security Admission enforces a level from.
const podSecurityEnforceLabel = "pod-security.kubernetes.io/enforce"

// policyEngineWebhooks name the admission webhooks of the policy engines that implement 5.2.1's
// mechanism, as each installs it.
var policyEngineWebhooks = []string{"gatekeeper", "kyverno"}

// evaluatePolicyControl implements 5.2.1: at least one policy control mechanism is in place.
//
// The API shows three: a namespace Pod Security Admission enforces a level on, a bound
// ValidatingAdmissionPolicy, and a policy engine's admission webhook. A default level the API
// server sets for every namespace from its own configuration file is not visible through the API,
// so a finding says what was read, and a cluster run that way is one to record as an exclusion.
func evaluatePolicyControl(ctx context.Context, client kubernetes.Interface) (policyVerdict, bool) {
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return policyVerdict{}, false
	}
	var enforced []string
	for _, ns := range namespaces.Items {
		if ns.Labels[podSecurityEnforceLabel] != "" && ns.Labels[podSecurityEnforceLabel] != "privileged" {
			enforced = append(enforced, ns.Name)
		}
	}
	if len(enforced) > 0 {
		return policyVerdict{Compliant: true}, true
	}
	if bindings, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, metav1.ListOptions{}); err == nil && len(bindings.Items) > 0 {
		return policyVerdict{Compliant: true}, true
	}
	webhooks, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return policyVerdict{}, false
	}
	for _, w := range webhooks.Items {
		for _, engine := range policyEngineWebhooks {
			if strings.Contains(w.Name, engine) {
				return policyVerdict{Compliant: true}, true
			}
		}
	}
	const message = "No policy control mechanism found: no namespace enforces a Pod Security level above privileged, " +
		"no ValidatingAdmissionPolicy is bound, and no Gatekeeper or Kyverno webhook is configured. A default level in " +
		"the API server's admission configuration file is not visible here; if you set one, exclude " +
		draugrCISRulePrefix + "5.2.1."
	return policyVerdict{Detail: message, message: message}, true
}

// evaluateMarkedManual runs the checks the benchmark marks Manual that the API answers, adding each
// verdict it reaches to out.
func evaluateMarkedManual(
	ctx context.Context, client kubernetes.Interface, namespaces []string,
	clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role, pods []corev1.Pod, out map[string]policyVerdict,
) {
	for id, v := range evaluateAccess(ctx, client, namespaces, clusterRoles, roles) {
		out[id] = v
	}
	if v, ok := evaluateNetworkPolicies(ctx, client, namespaces); ok {
		out["5.3.2"] = v
	}
	out["5.4.1"] = checkSecretsInEnvironment(pods)
	if len(namespaces) == 0 {
		if v, ok := evaluatePolicyControl(ctx, client); ok {
			out["5.2.1"] = v
		}
	}
}
