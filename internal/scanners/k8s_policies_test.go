package scanners

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func boolPtr(b bool) *bool { return &b }

func TestK8sPoliciesInfo(t *testing.T) {
	t.Parallel()
	info := NewK8sPolicies().Info()

	if info.Name != k8sPoliciesScannerName {
		t.Errorf("name = %q", info.Name)
	}
	// No binary is the point of this scanner: nothing to install, and doctor has nothing to
	// report missing.
	if info.Binary != "" {
		t.Errorf("Binary = %q, want empty — this scanner execs nothing", info.Binary)
	}
	if len(info.AlsoRequires) != 0 {
		t.Errorf("AlsoRequires = %v, want none — the kubectl dependency is kube-bench's", info.AlsoRequires)
	}
	if len(info.Effects) != 0 {
		t.Errorf("Effects = %v, want none — this scanner only reads", info.Effects)
	}
}

// 5.1.1. The binding Kubernetes ships to bootstrap itself is named cluster-admin and grants the
// role to system:masters; treating it as a violation would make every cluster fail forever.
func TestCheckClusterAdminBindings(t *testing.T) {
	t.Parallel()

	bootstrap := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
	}
	other := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "view-everything"},
		RoleRef:    rbacv1.RoleRef{Name: "view"},
	}
	granted := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "ci-runner-admin"},
		RoleRef:    rbacv1.RoleRef{Name: "cluster-admin"},
	}

	if v := checkClusterAdminBindings([]rbacv1.ClusterRoleBinding{bootstrap, other}); !v.Compliant {
		t.Errorf("the bootstrap binding must not count as a violation, got %q", v.Detail)
	}
	v := checkClusterAdminBindings([]rbacv1.ClusterRoleBinding{bootstrap, granted})
	if v.Compliant {
		t.Fatal("a binding to cluster-admin should not be compliant")
	}
	if !strings.Contains(v.Detail, "ci-runner-admin") {
		t.Errorf("the detail should name the binding, got %q", v.Detail)
	}
}

// 5.1.3. A wildcard in any of the three fields is enough, because each one grants whatever that
// field comes to mean as the cluster gains APIs.
func TestCheckWildcardRules(t *testing.T) {
	t.Parallel()

	specific := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}

	for _, tc := range []struct {
		name  string
		rules []rbacv1.PolicyRule
		want  bool // compliant
	}{
		{"specific", specific, true},
		{"wildcard verb", []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}}, false},
		{"wildcard resource", []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}}, false},
		{"wildcard api group", []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			role := rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "team"}, Rules: tc.rules}
			if got := checkWildcardRules([]rbacv1.Role{role}, nil).Compliant; got != tc.want {
				t.Errorf("compliant = %v, want %v", got, tc.want)
			}
		})
	}

	// The finding has to say which object, or it is only a statement that something is wrong.
	cr := rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "too-broad"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"*"}}}}
	if d := checkWildcardRules(nil, []rbacv1.ClusterRole{cr}).Detail; !strings.Contains(d, "too-broad") {
		t.Errorf("detail should name the clusterrole, got %q", d)
	}
}

// 5.1.5. An unset automountServiceAccountToken is not compliant — the default is to mount, so
// treating absent as "fine" would pass exactly the clusters the check is aimed at.
func TestCheckDefaultServiceAccounts(t *testing.T) {
	t.Parallel()

	sa := func(ns, name string, automount *bool) corev1.ServiceAccount {
		return corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: ns},
			AutomountServiceAccountToken: automount,
		}
	}

	hardened := checkDefaultServiceAccounts([]corev1.ServiceAccount{
		sa("team", "default", boolPtr(false)),
		sa("team", "worker", nil), // not the default account; out of scope for this check
	})
	if !hardened.Compliant {
		t.Errorf("want compliant, got %q", hardened.Detail)
	}

	for _, tc := range []struct {
		name      string
		automount *bool
	}{
		{"unset", nil},
		{"explicitly true", boolPtr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := checkDefaultServiceAccounts([]corev1.ServiceAccount{sa("payments", "default", tc.automount)})
			if v.Compliant {
				t.Fatal("a default service account that still mounts a token is not compliant")
			}
			if !strings.Contains(v.Detail, "payments") {
				t.Errorf("the detail should name the namespace, got %q", v.Detail)
			}
		})
	}
}

// A wall of names is not a finding anyone reads, and the full set is a query away.
func TestSummarizeCaps(t *testing.T) {
	t.Parallel()
	got := summarize([]string{"a", "b", "c", "d", "e", "f", "g"})
	if !strings.HasSuffix(got, "and 2 more") {
		t.Errorf("summarize = %q, want a truncated list", got)
	}
	if short := summarize([]string{"a", "b"}); short != "a, b" {
		t.Errorf("a short list should not be truncated, got %q", short)
	}
}

// The guarantee this scanner rests on: a check it cannot decide is still reported, so partial
// coverage can never read as a clean result.
func TestK8sPoliciesReportsEveryCheck(t *testing.T) {
	t.Parallel()

	// A cluster that satisfies all three implemented checks.
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"}, RoleRef: rbacv1.RoleRef{Name: "cluster-admin"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: "team"},
			AutomountServiceAccountToken: boolPtr(false),
		},
	)
	rep, err := scanPolicies(t, client)
	if err != nil {
		t.Fatal(err)
	}

	// Derived, not hardcoded: the count moves every time a check becomes decidable, and a test
	// that had to be edited alongside would be edited to match rather than to check.
	decided, err := evaluatePolicies(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	passing := 0
	for _, v := range decided {
		if v.Compliant {
			passing++
		}
	}
	if want := len(cisPolicies) - passing; len(rep.Results) != want {
		t.Fatalf("got %d results, want %d (%d checks, %d decided and passing) — every undecided check must still be reported",
			len(rep.Results), want, len(cisPolicies), passing)
	}
	for _, r := range rep.Results {
		if !strings.Contains(r.Message, "requires manual review") {
			t.Errorf("%s should be a manual prompt on a compliant cluster, got %q", r.RuleID, r.Message)
		}
	}
}

// A decided failure must read as a finding about the cluster, not as a prompt.
func TestK8sPoliciesDecidesWhatItCan(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "ci-admin"}, RoleRef: rbacv1.RoleRef{Name: "cluster-admin"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "payments"}},
	)
	rep, err := scanPolicies(t, client)
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]string{}
	for _, r := range rep.Results {
		found[r.RuleID] = r.Message
	}
	if msg := found["cis/5.1.1"]; !strings.Contains(msg, "ci-admin") {
		t.Errorf("5.1.1 should name the offending binding, got %q", msg)
	}
	if msg := found["cis/5.1.5"]; !strings.Contains(msg, "payments") {
		t.Errorf("5.1.5 should name the namespace, got %q", msg)
	}
	if msg := found["cis/5.1.1"]; strings.Contains(msg, "manual review") {
		t.Error("a decided check must not also ask for manual review")
	}
}

// Rule ids have to match kube-bench's, or an exclusion written against one scanner silently
// stops applying when someone switches mode.
func TestK8sPoliciesRuleIDsMatchKubeBench(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset()
	rep, err := scanPolicies(t, client)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Results {
		if !strings.HasPrefix(r.RuleID, "cis/5.") {
			t.Errorf("rule id %q should use the benchmark's own numbering", r.RuleID)
		}
	}
}

func TestK8sPoliciesRejectsTheWrongTarget(t *testing.T) {
	t.Parallel()
	s := k8sPoliciesScanner{
		info:   plugin.ScannerInfo{Name: k8sPoliciesScannerName},
		client: func(string) (kubernetes.Interface, error) { return fake.NewSimpleClientset(), nil },
	}
	if _, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "https://example.com/x.git"}, nil); err == nil {
		t.Fatal("want an error for a non-infrastructure target")
	}
}

// An unreachable cluster is an error, not an empty report: a control that could not run must
// never look like one that found nothing.
func TestK8sPoliciesReportsAnUnreachableCluster(t *testing.T) {
	t.Parallel()
	s := k8sPoliciesScanner{
		info:   plugin.ScannerInfo{Name: k8sPoliciesScannerName},
		client: func(string) (kubernetes.Interface, error) { return nil, errors.New("no kubeconfig") },
	}
	_, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err == nil || !strings.Contains(err.Error(), k8sPoliciesScannerName) {
		t.Errorf("want an error naming the scanner, got %v", err)
	}
}

func scanPolicies(t *testing.T, client kubernetes.Interface) (sarif.Report, error) {
	t.Helper()
	s := k8sPoliciesScanner{
		info:   plugin.ScannerInfo{Name: k8sPoliciesScannerName},
		client: func(string) (kubernetes.Interface, error) { return client, nil },
	}
	return s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes", Ref: "test"}, nil)
}

// The catalogue is the coverage guarantee, so it has to be internally sound: no duplicate ids,
// nothing malformed, and a remediation on every entry — a finding with no remediation is a
// complaint.
func TestCISCatalogueIsWellFormed(t *testing.T) {
	t.Parallel()

	idRE := regexp.MustCompile(`^5\.\d+\.\d+$`)
	seen := map[string]bool{}
	for _, c := range cisPolicies {
		if !idRE.MatchString(c.ID) {
			t.Errorf("id %q is not a section 5 check number", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("duplicate check %q — the index would silently drop one", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Title) == "" {
			t.Errorf("%s has no title", c.ID)
		}
		if strings.TrimSpace(c.Remediation) == "" {
			t.Errorf("%s has no remediation", c.ID)
		}
	}
	if len(cisPolicyByID) != len(cisPolicies) {
		t.Errorf("index has %d entries for %d checks", len(cisPolicyByID), len(cisPolicies))
	}
}

// Every check the evaluator decides must exist in the catalogue, or its verdict is computed and
// then thrown away — the report only walks the catalogue.
func TestEveryDecidedCheckIsInTheCatalogue(t *testing.T) {
	t.Parallel()

	decided, err := evaluatePolicies(context.Background(), fake.NewSimpleClientset())
	if err != nil {
		t.Fatal(err)
	}
	if len(decided) == 0 {
		t.Fatal("no checks are implemented")
	}
	for id := range decided {
		if _, ok := cisPolicyByID[id]; !ok {
			t.Errorf("check %q is evaluated but missing from the catalogue, so its verdict is discarded", id)
		}
	}
}

func pod(ns, name string, mutate func(*corev1.Pod)) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

// 5.2.2 through 5.2.6, all answered from one pod listing.
func TestEvaluatePodSecurity(t *testing.T) {
	t.Parallel()

	sc := func(f func(*corev1.SecurityContext)) *corev1.SecurityContext {
		s := &corev1.SecurityContext{}
		f(s)
		return s
	}

	pods := []corev1.Pod{
		pod("clean", "ok", nil),
		pod("ns", "privileged", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext = sc(func(s *corev1.SecurityContext) { s.Privileged = boolPtr(true) })
		}),
		pod("ns", "hostpid", func(p *corev1.Pod) { p.Spec.HostPID = true }),
		pod("ns", "hostipc", func(p *corev1.Pod) { p.Spec.HostIPC = true }),
		pod("ns", "hostnet", func(p *corev1.Pod) { p.Spec.HostNetwork = true }),
		pod("ns", "escalation", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext = sc(func(s *corev1.SecurityContext) { s.AllowPrivilegeEscalation = boolPtr(true) })
		}),
	}

	got := evaluatePodSecurity(pods, nil)
	for id, want := range map[string]string{
		"5.2.2": "privileged", "5.2.3": "hostpid", "5.2.4": "hostipc",
		"5.2.5": "hostnet", "5.2.6": "escalation",
	} {
		v := got[id]
		if v.Compliant {
			t.Errorf("%s should have found %q", id, want)
			continue
		}
		if !strings.Contains(v.Detail, want) {
			t.Errorf("%s detail should name the pod %q, got %q", id, want, v.Detail)
		}
	}

	clean := evaluatePodSecurity([]corev1.Pod{pod("clean", "ok", nil)}, nil)
	for _, id := range []string{"5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6"} {
		if !clean[id].Compliant {
			t.Errorf("%s should pass on a clean pod, got %q", id, clean[id].Detail)
		}
	}
}

// An init container runs with the same privileges and can do the same damage in the seconds it
// is alive, so a check reading only spec.containers would pass a pod that mounts the host as
// root before the workload starts.
func TestPodSecurityCoversInitContainers(t *testing.T) {
	t.Parallel()

	p := pod("ns", "sneaky", func(p *corev1.Pod) {
		p.Spec.InitContainers = []corev1.Container{{
			Name:            "setup",
			SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)},
		}}
	})
	v := evaluatePodSecurity([]corev1.Pod{p}, nil)["5.2.2"]
	if v.Compliant {
		t.Fatal("a privileged init container is still a privileged container")
	}
	if !strings.Contains(v.Detail, "setup") {
		t.Errorf("detail should name the init container, got %q", v.Detail)
	}
}

// 5.1.6. Either the pod or its service account can decline the token, and the pod wins where
// both speak — which is how Kubernetes resolves it. Reading only one would flag a correctly
// hardened workload.
func TestPodMountsToken(t *testing.T) {
	t.Parallel()

	accounts := map[string]bool{
		"ns/hardened": false,
		"ns/opted-in": true,
	}

	for _, tc := range []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"nothing set anywhere", pod("ns", "p", nil), true},
		{"pod declines", pod("ns", "p", func(p *corev1.Pod) {
			p.Spec.AutomountServiceAccountToken = boolPtr(false)
		}), false},
		{"service account declines", pod("ns", "p", func(p *corev1.Pod) {
			p.Spec.ServiceAccountName = "hardened"
		}), false},
		{"pod overrides a declining service account", pod("ns", "p", func(p *corev1.Pod) {
			p.Spec.ServiceAccountName = "hardened"
			p.Spec.AutomountServiceAccountToken = boolPtr(true)
		}), true},
		{"pod overrides an accepting service account", pod("ns", "p", func(p *corev1.Pod) {
			p.Spec.ServiceAccountName = "opted-in"
			p.Spec.AutomountServiceAccountToken = boolPtr(false)
		}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := podMountsToken(&tc.pod, accounts); got != tc.want {
				t.Errorf("podMountsToken = %v, want %v", got, tc.want)
			}
		})
	}
}

// 5.1.2 and 5.1.4 ask the authorizer, and a deliberately read-only credential is not allowed to.
// Being refused must leave the check undecided — reported for review like any other the scanner
// cannot settle — rather than failing a scan it was never promised the permission for.
func TestBroadAccessUndecidedWhenTheAuthorizerRefuses(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "subjectaccessreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("subjectaccessreviews.authorization.k8s.io is forbidden")
	})

	got := evaluateBroadAccess(context.Background(), client)
	for _, id := range []string{"5.1.2", "5.1.4"} {
		if _, decided := got[id]; decided {
			t.Errorf("%s should be left undecided when the authorizer cannot be asked", id)
		}
	}
}

// And when it can be asked, a yes is a finding naming what everyone can do.
func TestBroadAccessReportsWhatEveryoneCanDo(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		allowed := review.Spec.ResourceAttributes.Resource == "secrets"
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})

	got := evaluateBroadAccess(context.Background(), client)
	if got["5.1.2"].Compliant {
		t.Error("5.1.2 should fail when every authenticated user can read secrets")
	}
	if !strings.Contains(got["5.1.2"].Detail, "read secrets") {
		t.Errorf("5.1.2 detail should say what is allowed, got %q", got["5.1.2"].Detail)
	}
	if !got["5.1.4"].Compliant {
		t.Errorf("5.1.4 should pass when pod creation is denied, got %q", got["5.1.4"].Detail)
	}
}
