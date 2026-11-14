package scanners

import (
	"context"
	"errors"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestRuleGrants(t *testing.T) {
	t.Parallel()

	proxy := accessGrant{[]string{"get"}, "", "nodes/proxy"}
	for _, tc := range []struct {
		name string
		rule rbacv1.PolicyRule
		g    accessGrant
		want bool
	}{
		{"exact", rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes/proxy"}}, proxy, true},
		{"wildcard verb", rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"nodes/proxy"}}, proxy, true},
		{"wildcard group and resource", rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{"*"}, Resources: []string{"*"}}, proxy, true},
		{"every subresource of nodes", rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes/*"}}, proxy, true},
		{"the parent alone", rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes"}}, proxy, false},
		{"another verb", rbacv1.PolicyRule{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"nodes/proxy"}}, proxy, false},
		{"another group", rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{"apps"}, Resources: []string{"nodes/proxy"}}, proxy, false},
	} {
		if got := ruleGrants(tc.rule, tc.g); got != tc.want {
			t.Errorf("%s: ruleGrants = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// accessCluster has roles granting the access checks' permissions, bound in two namespaces, beside
// the distribution's own and a role nothing binds.
func accessCluster() *fake.Clientset {
	impersonate := []rbacv1.PolicyRule{{Verbs: []string{"impersonate"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts"}}}
	return fake.NewSimpleClientset(
		// team-a binds its own role, which impersonates.
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "team-a"}, Rules: impersonate},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: "team-a"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "ci"}},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "deployer"}},
		// A binding with no subjects grants nothing either.
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "idle", Namespace: "team-a"}, Rules: impersonate},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "idle", Namespace: "team-a"},
			RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "idle"}},
		// team-b holds the same role, bound by nobody: it grants nothing.
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "deployer", Namespace: "team-b"}, Rules: impersonate},
		// team-b binds a built-in ClusterRole that creates tokens: the team was given that access.
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "token-maker", Labels: map[string]string{rbacDefaultsLabel: "rbac-defaults"}},
			Rules: []rbacv1.PolicyRule{{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "builders", Namespace: "team-b"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "builders"}},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "token-maker"}},
		// The distribution's: a system role that approves CSRs, bound by a system binding.
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:certificates-approver"},
			Rules: []rbacv1.PolicyRule{{Verbs: []string{"update"}, APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "system:certificates-approver"},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "certificate-controller", Namespace: "kube-system"}},
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:certificates-approver"}},
		// An operator's cluster role that creates persistent volumes.
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "storage-admin"},
			Rules: []rbacv1.PolicyRule{{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"persistentvolumes"}}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "storage-team"},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "dana"}, {Kind: rbacv1.UserKind, Name: "ari"},
				{Kind: rbacv1.UserKind, Name: "lee"}, {Kind: rbacv1.UserKind, Name: "kim"},
			},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "storage-admin"}},
	)
}

func clusterRolesOf(t *testing.T, c *fake.Clientset) ([]rbacv1.ClusterRole, []rbacv1.Role) {
	t.Helper()
	crs, err := c.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	roles, err := c.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return crs.Items, roles.Items
}

// Each access check names the roles somebody is bound to, its own apart from the distribution's, and
// leaves out a role nothing binds.
func TestAccessChecksNameTheBoundRoles(t *testing.T) {
	t.Parallel()

	c := accessCluster()
	crs, roles := clusterRolesOf(t, c)
	got := evaluateAccess(context.Background(), c, nil, crs, roles)

	for id, want := range map[string]struct{ owned, distribution []string }{
		"5.1.8":  {owned: []string{"role team-a/deployer (bound to serviceaccount team-a/ci)"}},
		"5.1.9":  {owned: []string{"clusterrole storage-admin (bound to user ari, user dana, user kim and 1 more)"}},
		"5.1.10": {},
		"5.1.11": {distribution: []string{"clusterrole system:certificates-approver (bound to serviceaccount kube-system/certificate-controller)"}},
		"5.1.12": {},
		"5.1.13": {owned: []string{"clusterrole token-maker (bound to group builders)"}},
	} {
		v, ok := got[id]
		if !ok {
			t.Errorf("%s was not decided", id)
			continue
		}
		if len(want.owned)+len(want.distribution) == 0 {
			if !v.Compliant {
				t.Errorf("%s should pass, got %q", id, v.Detail)
			}
			continue
		}
		if strings.Join(v.Owned, ",") != strings.Join(want.owned, ",") || strings.Join(v.Distribution, ",") != strings.Join(want.distribution, ",") {
			t.Errorf("%s: owned %v distribution %v, want %v and %v", id, v.Owned, v.Distribution, want.owned, want.distribution)
		}
	}
	if want := "1 role granting permission to bind, escalate or impersonate: role team-a/deployer (bound to serviceaccount team-a/ci)"; got["5.1.8"].Detail != want {
		t.Errorf("5.1.8 detail = %q, want %q (not team-b's role, which nothing binds, nor team-a's idle one, bound to nobody)", got["5.1.8"].Detail, want)
	}
}

// A run scoped to a namespace answers the namespaced access checks from what is bound there, fetching
// the ClusterRoles its bindings name, and leaves the cluster-scoped ones to the cluster's owner.
func TestAccessChecksScopedToANamespace(t *testing.T) {
	t.Parallel()

	c := accessCluster()
	roles, err := c.RbacV1().Roles("team-b").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := evaluateAccess(context.Background(), c, []string{"team-b"}, nil, roles.Items)

	if ids := len(got); ids != 2 {
		t.Errorf("decided %d checks, want the 2 namespaced ones: %v", ids, got)
	}
	if v := got["5.1.13"]; strings.Join(v.Owned, ",") != "clusterrole token-maker (bound to group builders)" {
		t.Errorf("5.1.13 owned %v, want the ClusterRole team-b binds", v.Owned)
	}
	if !got["5.1.8"].Compliant {
		t.Errorf("5.1.8 should pass in team-b, whose deployer nothing binds: %q", got["5.1.8"].Detail)
	}
}

// refusing answers every request for one resource with forbidden.
func refusing(c *fake.Clientset, verb, resource string) {
	c.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New(resource + " is forbidden")
	})
}

// A credential refused a read the new checks need leaves those checks undecided, and the scan
// completes as it did before they existed.
func TestARefusedReadLeavesItsChecksUndecided(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		verb, resource string
		scoped         bool
		undecided      []string
	}{
		{"list", "rolebindings", false, []string{"5.1.8", "5.1.9", "5.1.13"}},
		{"get", "clusterroles", true, []string{"5.1.8", "5.1.13"}},
		{"list", "namespaces", false, []string{"5.3.2", "5.2.1"}},
		{"list", "networkpolicies", false, []string{"5.3.2"}},
		{"list", "validatingwebhookconfigurations", false, []string{"5.2.1"}},
	} {
		c := accessCluster()
		refusing(c, tc.verb, tc.resource)
		var namespaces []string
		if tc.scoped {
			namespaces = []string{"team-b"}
		}
		got, err := evaluatePolicies(context.Background(), c, namespaces)
		if err != nil {
			t.Fatalf("%s %s refused: the scan failed: %v", tc.verb, tc.resource, err)
		}
		for _, id := range tc.undecided {
			if _, decided := got[id]; decided {
				t.Errorf("%s %s refused, yet %s was decided", tc.verb, tc.resource, id)
			}
		}
	}
}

// 5.3.2 names every namespace with no NetworkPolicy, Kubernetes' own apart.
func TestNetworkPoliciesNameUncoveredNamespaces(t *testing.T) {
	t.Parallel()

	ns := func(name string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	}
	c := fake.NewSimpleClientset(ns("team-a"), ns("team-b"), ns("kube-system"),
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "team-a"}})

	v, ok := evaluateNetworkPolicies(context.Background(), c, nil)
	if !ok || strings.Join(v.Owned, ",") != "team-b" || strings.Join(v.Distribution, ",") != "kube-system" {
		t.Errorf("owned %v distribution %v, want team-b and kube-system", v.Owned, v.Distribution)
	}
	if got, want := v.describe(v.Owned), "1 namespace with no NetworkPolicy: team-b"; got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
	scoped, ok := evaluateNetworkPolicies(context.Background(), c, []string{"team-a"})
	if !ok || !scoped.Compliant {
		t.Errorf("team-a has a NetworkPolicy, got %q", scoped.Detail)
	}
}

// 5.4.1 names each container handed a secret through its environment, init containers included.
func TestSecretsInEnvironment(t *testing.T) {
	t.Parallel()

	secretKey := corev1.EnvVar{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: "t"}}}
	pods := []corev1.Pod{
		pod("team-a", "api", func(p *corev1.Pod) { p.Spec.Containers[0].Env = []corev1.EnvVar{secretKey} }),
		pod("team-b", "worker", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init",
				EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{}}}}}
		}),
		pod("team-b", "plain", func(p *corev1.Pod) { p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "MODE", Value: "x"}} }),
		pod("kube-system", "dns", func(p *corev1.Pod) { p.Spec.Containers[0].Env = []corev1.EnvVar{secretKey} }),
	}
	v := checkSecretsInEnvironment(pods)
	owned := strings.Join(v.Owned, ",")
	if !strings.Contains(owned, "team-a/api/") || !strings.Contains(owned, "team-b/worker/init") || strings.Contains(owned, "plain") {
		t.Errorf("owned = %v, want team-a's api and team-b's init container, not the plain pod", v.Owned)
	}
	if len(v.Distribution) != 1 || !strings.HasPrefix(v.Distribution[0], "kube-system/dns/") {
		t.Errorf("distribution = %v, want kube-system's dns", v.Distribution)
	}
	if got := v.describe(v.Owned); !strings.HasPrefix(got, "2 with a secret in an environment variable: ") {
		t.Errorf("detail = %q, want it to lead with the count", got)
	}
}

// 5.2.1 passes on any one mechanism the API shows, and otherwise says what it read.
func TestPolicyControl(t *testing.T) {
	t.Parallel()

	labeled := func(level string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team", Labels: map[string]string{podSecurityEnforceLabel: level}}}
	}
	for _, tc := range []struct {
		name    string
		objects []runtime.Object
		pass    bool
	}{
		{"nothing", []runtime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team"}}}, false},
		{"a namespace enforcing baseline", []runtime.Object{labeled("baseline")}, true},
		{"a namespace enforcing privileged, which enforces nothing", []runtime.Object{labeled("privileged")}, false},
		{"a bound admission policy", []runtime.Object{&admissionv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: "no-latest"}}}, true},
		{"a policy engine's webhook", []runtime.Object{&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "kyverno-resource-validating-webhook-cfg"}}}, true},
		{"another webhook", []runtime.Object{&admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-webhook"}}}, false},
	} {
		v, ok := evaluatePolicyControl(context.Background(), fake.NewSimpleClientset(tc.objects...))
		if !ok {
			t.Errorf("%s: undecided", tc.name)
			continue
		}
		if v.Compliant != tc.pass {
			t.Errorf("%s: compliant = %v, want %v (%q)", tc.name, v.Compliant, tc.pass, v.Detail)
		}
		if !v.Compliant && (!strings.Contains(v.message, "not visible") || !strings.HasSuffix(v.message, "exclude draugr/cis/5.2.1.")) {
			t.Errorf("%s: the finding should say what the API cannot show and which rule id to exclude, got %q", tc.name, v.message)
		}
	}
}

// Over a whole cluster the scan leaves for a person only the checks no API answers in full.
func TestOnlyTheChecksNoAPIAnswersStayUndecided(t *testing.T) {
	t.Parallel()

	c := accessCluster()
	// An API server answers the authorizer's questions 5.1.2 and 5.1.4 ask; the fake does not.
	c.PrependReactor("create", "subjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{}, nil
	})
	rep, err := scanPolicies(t, c)
	if err != nil {
		t.Fatal(err)
	}
	var undecided []string
	for _, r := range rep.Results {
		if r.Undecided {
			undecided = append(undecided, strings.TrimPrefix(r.RuleID, draugrCISRulePrefix))
		}
		// 5.2.1's finding is a sentence of its own, not a clause glued to the check's title.
		if r.RuleID == draugrCISRulePrefix+"5.2.1" && !strings.HasPrefix(r.Message, "No policy control mechanism found: ") {
			t.Errorf("5.2.1 message = %q", r.Message)
		}
	}
	if got, want := strings.Join(undecided, ","), "5.1.7,5.3.1,5.4.2,5.5.1,5.6.1"; got != want {
		t.Errorf("undecided = %s, want %s", got, want)
	}
}

// A finding names who holds a role the way kubectl names each kind of subject.
func TestSubjectName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		s    rbacv1.Subject
		want string
	}{
		{rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "ci"}, "serviceaccount team-a/ci"},
		{rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "ci", Namespace: "build"}, "serviceaccount build/ci"},
		{rbacv1.Subject{Kind: rbacv1.UserKind, Name: "alice"}, "user alice"},
		{rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "devs"}, "group devs"},
		{rbacv1.Subject{Kind: "Robot", Name: "r2"}, "robot r2"},
	} {
		if got := subjectName(tc.s, "team-a"); got != tc.want {
			t.Errorf("subjectName(%+v) = %q, want %q", tc.s, got, tc.want)
		}
	}
}
