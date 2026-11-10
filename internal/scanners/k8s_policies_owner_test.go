package scanners

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A cluster-scoped RBAC object is the distribution's when Kubernetes labels it as one of its defaults,
// or when its name carries a prefix Kubernetes or kubeadm reserves. kubeadm's own bindings carry no
// label, so the name is all they have.
func TestDistributionRBAC(t *testing.T) {
	t.Parallel()
	defaults := map[string]string{rbacDefaultsLabel: "rbac-defaults"}
	for _, c := range []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"cluster-admin", defaults, true},
		{"system:controller:job-controller", nil, true},
		{"kubeadm:cluster-admins", nil, true},
		{"superadmin", nil, false},
		{"my-system:role", nil, false},
	} {
		if got := distributionRBAC(c.name, c.labels); got != c.want {
			t.Errorf("distributionRBAC(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// Every check that names objects splits them by who put them there.
func TestVerdictsSplitTheDistributionsObjects(t *testing.T) {
	t.Parallel()
	admin := rbacv1.RoleRef{Name: "cluster-admin"}
	bindings := checkClusterAdminBindings([]rbacv1.ClusterRoleBinding{
		{ObjectMeta: metav1.ObjectMeta{Name: "superadmin"}, RoleRef: admin},
		{ObjectMeta: metav1.ObjectMeta{Name: "kubeadm:cluster-admins"}, RoleRef: admin},
		{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"}, RoleRef: admin},
	})
	wildcard := []rbacv1.PolicyRule{{Verbs: []string{"*"}}}
	roles := checkWildcardRules(
		[]rbacv1.Role{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kp"}, Rules: wildcard},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "deployer"}, Rules: wildcard},
		},
		[]rbacv1.ClusterRole{
			{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: map[string]string{rbacDefaultsLabel: "rbac-defaults"}}, Rules: wildcard},
			{ObjectMeta: metav1.ObjectMeta{Name: "ops"}, Rules: wildcard},
		})
	accounts := checkDefaultServiceAccounts([]corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "default"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "default"}},
	})
	yes := true
	privileged := func(p *corev1.Pod) {
		p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &yes}
	}
	pods := evaluatePodSecurity([]corev1.Pod{
		pod("default", "health-check", privileged),
		pod("kube-system", "kube-proxy", privileged),
	}, nil)

	for _, c := range []struct {
		name        string
		got         policyVerdict
		owned, dist []string
	}{
		{"5.1.1", bindings, []string{"superadmin"}, []string{"kubeadm:cluster-admins"}},
		{"5.1.3", roles, []string{"clusterrole ops", "role apps/deployer"}, []string{"clusterrole cluster-admin", "role kube-system/kp"}},
		{"5.1.5", accounts, []string{"apps"}, []string{"kube-system"}},
		{"5.2.2", pods["5.2.2"], []string{"default/health-check/app"}, []string{"kube-system/kube-proxy/app"}},
	} {
		if !slices.Equal(c.got.Owned, c.owned) || !slices.Equal(c.got.Distribution, c.dist) {
			t.Errorf("%s: owned %v, distribution %v; want %v and %v", c.name, c.got.Owned, c.got.Distribution, c.owned, c.dist)
		}
	}
	// The detail still names every object, for the checks it is read from directly.
	if !strings.Contains(bindings.Detail, "kubeadm:cluster-admins") || !strings.Contains(bindings.Detail, "superadmin") {
		t.Errorf("detail = %q", bindings.Detail)
	}
}

// A check the Pod Security Standards' Baseline profile covers is high, and so is a binding to
// cluster-admin. One only Restricted asks for stays medium. A check only the distribution's objects
// fail is low, and lists them; a check the operators' objects fail lists theirs first.
func TestPoliciesReportRanksByCheckAndOwner(t *testing.T) {
	t.Parallel()
	privileged := verdictFrom([]string{"default/hc/app", "kube-system/kube-proxy/app"}, "running privileged")
	hostPath := verdictFrom([]string{"kube-system/kube-proxy (lib-modules)"}, "mounting a hostPath volume")
	seccomp := verdictFrom([]string{"apps/web"}, "without a seccomp profile")
	decided := map[string]policyVerdict{
		"5.2.2":  privileged,
		"5.2.11": hostPath,
		"5.6.2":  seccomp,
		// The authorizer's answer names no object, so it keeps the check's title.
		"5.1.2": {Detail: "any authenticated identity may get secrets"},
	}
	rep := policiesReport(decided, "kubernetes/c", nil)
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		if _, dup := byRule[r.RuleID]; dup {
			t.Errorf("%s reported twice; one row per check", r.RuleID)
		}
		byRule[r.RuleID] = r
	}
	for _, c := range []struct {
		id      string
		level   sarif.Level
		message string
	}{
		{"5.2.2", sarif.LevelError, "1 running privileged: default/hc/app; the distribution's: 1 running privileged: kube-system/kube-proxy/app"},
		{"5.2.11", sarif.LevelNote, "the distribution's: 1 mounting a hostPath volume: kube-system/kube-proxy (lib-modules)"},
		{"5.6.2", sarif.LevelWarning, "1 without a seccomp profile: apps/web"},
		{"5.1.2", sarif.LevelWarning, "Minimize access to secrets, any authenticated identity may get secrets"},
		{"5.1.10", sarif.LevelWarning, "Minimize access to the proxy sub-resource of nodes, requires manual review"},
	} {
		r, ok := byRule[draugrCISRulePrefix+c.id]
		if !ok {
			t.Errorf("%s: no finding", c.id)
			continue
		}
		if r.Level != c.level || r.Message != c.message {
			t.Errorf("%s: %s %q, want %s %q", c.id, r.Level, r.Message, c.level, c.message)
		}
	}
	for id := range cisHighChecks {
		if _, ok := cisPolicyByID[id]; !ok {
			t.Errorf("cisHighChecks names %s, which the catalog does not hold", id)
		}
	}
}
