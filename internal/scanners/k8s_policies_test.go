package scanners

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
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

	if info.Name != draugrK8sPoliciesScannerName {
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
	decided, err := evaluatePolicies(context.Background(), client, nil)
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
	if msg := found["draugr/cis/5.1.1"]; !strings.Contains(msg, "ci-admin") {
		t.Errorf("5.1.1 should name the offending binding, got %q", msg)
	}
	if msg := found["draugr/cis/5.1.5"]; !strings.Contains(msg, "payments") {
		t.Errorf("5.1.5 should name the namespace, got %q", msg)
	}
	if msg := found["draugr/cis/5.1.1"]; strings.Contains(msg, "manual review") {
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
		if !strings.HasPrefix(r.RuleID, "draugr/cis/5.") {
			t.Errorf("rule id %q should use the benchmark's own numbering", r.RuleID)
		}
	}
}

func TestK8sPoliciesRejectsTheWrongTarget(t *testing.T) {
	t.Parallel()
	s := draugrK8sPoliciesScanner{
		info:   plugin.ScannerInfo{Name: draugrK8sPoliciesScannerName},
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
	s := draugrK8sPoliciesScanner{
		info:   plugin.ScannerInfo{Name: draugrK8sPoliciesScannerName},
		client: func(string) (kubernetes.Interface, error) { return nil, errors.New("no kubeconfig") },
	}
	_, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err == nil || !strings.Contains(err.Error(), draugrK8sPoliciesScannerName) {
		t.Errorf("want an error naming the scanner, got %v", err)
	}
}

func scanPolicies(t *testing.T, client kubernetes.Interface) (sarif.Report, error) {
	t.Helper()
	s := draugrK8sPoliciesScanner{
		info:   plugin.ScannerInfo{Name: draugrK8sPoliciesScannerName},
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

	decided, err := evaluatePolicies(context.Background(), fake.NewSimpleClientset(), nil)
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

	got := evaluateBroadAccess(context.Background(), client, nil)
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

	got := evaluateBroadAccess(context.Background(), client, nil)
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

// Scoping has to change what is read, not filter what was read. A team that owns three
// namespaces of eighty very likely cannot list pods cluster-wide at all, so a cluster-wide list
// filtered afterwards would work only for the people who did not need the feature.
func TestScopedListingQueriesOnlyItsNamespaces(t *testing.T) {
	t.Parallel()

	client := fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mine", Namespace: "team-a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "theirs", Namespace: "other"}},
	)
	var asked []string
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ns := action.GetNamespace()
		if ns == "" {
			t.Errorf("a scoped audit must not list across all namespaces")
		}
		asked = append(asked, ns)
		return false, nil, nil // fall through to the tracker
	})

	if _, err := evaluatePolicies(context.Background(), client, []string{"team-a"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(asked, []string{"team-a"}) {
		t.Errorf("namespaces queried = %v, want [team-a]", asked)
	}
}

// A scoped audit is usually run by a scoped credential, so a refused cluster-wide read must
// leave that check undecided rather than abort a run whose namespaced half is perfectly good.
// Unscoped, the same refusal means the cluster was not audited, and must fail.
func TestClusterWideRefusalDependsOnScope(t *testing.T) {
	t.Parallel()

	newClient := func() *fake.Clientset {
		c := fake.NewSimpleClientset()
		c.PrependReactor("list", "clusterrolebindings", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("clusterrolebindings is forbidden")
		})
		return c
	}

	scoped, err := evaluatePolicies(context.Background(), newClient(), []string{"team-a"})
	if err != nil {
		t.Fatalf("a scoped audit must survive being denied a cluster-wide read: %v", err)
	}
	if _, decided := scoped["5.1.1"]; decided {
		t.Error("5.1.1 should be undecided when its objects could not be read")
	}

	if _, err := evaluatePolicies(context.Background(), newClient(), nil); err == nil {
		t.Error("an unscoped audit that cannot read cluster-wide objects has not audited the cluster")
	}
}

// The location has to carry the scope. The same rule id against the same cluster means something
// different depending on whether seventy-seven other namespaces were examined.
func TestClusterScopeLabel(t *testing.T) {
	t.Parallel()

	if got := clusterScopeLabel("prod", nil); got != "kubernetes/prod" {
		t.Errorf("unscoped label = %q", got)
	}
	// Sorted, so the same scope written in a different order is the same identity.
	got := clusterScopeLabel("prod", []string{"team-b", "team-a"})
	if want := "kubernetes/prod[team-a,team-b]"; got != want {
		t.Errorf("scoped label = %q, want %q", got, want)
	}
}

// The half that keeps this honest. kube-bench writes --all-namespaces into its own checks, so a
// scoped component audited by it would get the whole cluster reported against a component
// claiming three namespaces — a wrong answer wearing the right label.
func TestScannersThatCannotScopeRefuse(t *testing.T) {
	t.Parallel()

	target := plugin.InfraTarget{Platform: "kubernetes", Ref: "prod", Namespaces: []string{"team-a"}}

	kb := kubeBenchScanner{
		info: plugin.ScannerInfo{Name: kubeBenchScannerName},
		run: func(context.Context, []string, []string) ([]byte, error) {
			t.Error("kube-bench must not run against a scoped component")
			return nil, nil
		},
	}
	_, err := kb.Scan(context.Background(), target, nil)
	if err == nil {
		t.Fatal("want a refusal")
	}
	for _, want := range []string{"namespace", "draugrK8sPolicies"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should mention %q so the reader knows what to use, got: %v", want, err)
		}
	}

	// And an unscoped component is unaffected.
	if err := refuseNamespaceScope(kubeBenchScannerName, nil); err != nil {
		t.Errorf("an unscoped component must still be scannable: %v", err)
	}
}

// Every managed benchmark carries a section covering what the provider controls, and Draugr
// evaluates none of it. That gap is defensible; leaving it unmentioned is not — a reader has no
// way to know the section exists, so the benchmark looks smaller than it is.
func TestManagedServicesFinding(t *testing.T) {
	t.Parallel()

	for platform, want := range map[string]string{
		"gke": "gke-1.9.0", "eks": "eks-1.8.0", "aks": "aks-1.8",
	} {
		res, rule, ok := managedServicesFinding(platform, "kubernetes/x")
		if !ok {
			t.Errorf("%s should report its managed-services section", platform)
			continue
		}
		if !strings.Contains(res.Message, want) {
			t.Errorf("%s message should name the benchmark, got %q", platform, res.Message)
		}
		// The number is the disclosure: "some of it" is not an answer anyone can act on.
		if !strings.Contains(res.Message, fmt.Sprint(managedServicesByPlatform[platform].Checks)) {
			t.Errorf("%s message should say how many checks, got %q", platform, res.Message)
		}
		if rule.Name == "" || res.RuleID != managedServicesRuleID {
			t.Errorf("%s: rule id = %q", platform, res.RuleID)
		}
	}

	// A vanilla cluster's benchmark has no such section, so there is nothing to disclose.
	if _, _, ok := managedServicesFinding("", "kubernetes/x"); ok {
		t.Error("a vanilla cluster has no managed-services section")
	}
	if _, _, ok := managedServicesFinding("k3s", "kubernetes/x"); ok {
		t.Error("k3s ships no managed-services section")
	}
}

// The rule id stays out of the cis/<number> space: it is a statement about a section, not one of
// the benchmark's checks, and a check number would make it look like one.
func TestManagedServicesRuleIDIsNotACheckNumber(t *testing.T) {
	t.Parallel()
	if regexp.MustCompile(`^cis/\d`).MatchString(managedServicesRuleID) {
		t.Errorf("rule id %q reads as a benchmark check", managedServicesRuleID)
	}
}

// 5.2.7. A container runs as root unless something says otherwise, and either the pod or the
// container can say it — the container winning where both do, as Kubernetes resolves it. Reading
// only one side would clear a workload that is still root, or flag one that is not.
func TestRunsAsRoot(t *testing.T) {
	t.Parallel()

	i64 := func(n int64) *int64 { return &n }
	podWith := func(ps *corev1.PodSecurityContext) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{SecurityContext: ps}}
	}

	for _, tc := range []struct {
		name string
		pod  *corev1.PodSecurityContext
		c    *corev1.SecurityContext
		want bool
	}{
		{"nothing set anywhere", nil, nil, true},
		{"container says non-root", nil, &corev1.SecurityContext{RunAsNonRoot: boolPtr(true)}, false},
		{"container runs as uid 0", nil, &corev1.SecurityContext{RunAsUser: i64(0)}, true},
		{"container runs as uid 1000", nil, &corev1.SecurityContext{RunAsUser: i64(1000)}, false},
		{"pod says non-root", &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)}, nil, false},
		{"container overrides the pod", &corev1.PodSecurityContext{RunAsNonRoot: boolPtr(true)},
			&corev1.SecurityContext{RunAsNonRoot: boolPtr(false)}, true},
		{"pod uid inherited", &corev1.PodSecurityContext{RunAsUser: i64(1000)}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := corev1.Container{Name: "app", SecurityContext: tc.c}
			if got := runsAsRoot(podWith(tc.pod), &c); got != tc.want {
				t.Errorf("runsAsRoot = %v, want %v", got, tc.want)
			}
		})
	}
}

// 5.6.2. A profile on the pod covers every container; one on a container covers only itself, so
// a pod is only confined when every container is. Unconfined is a choice, but not this one.
func TestPodSetsSeccomp(t *testing.T) {
	t.Parallel()

	profile := func(k corev1.SeccompProfileType) *corev1.SeccompProfile { return &corev1.SeccompProfile{Type: k} }
	two := []corev1.Container{{Name: "a"}, {Name: "b"}}

	for _, tc := range []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"nothing set", corev1.Pod{Spec: corev1.PodSpec{Containers: two}}, false},
		{"pod-level profile covers all", corev1.Pod{Spec: corev1.PodSpec{
			Containers:      two,
			SecurityContext: &corev1.PodSecurityContext{SeccompProfile: profile(corev1.SeccompProfileTypeRuntimeDefault)},
		}}, true},
		{"pod-level unconfined does not count", corev1.Pod{Spec: corev1.PodSpec{
			Containers:      two,
			SecurityContext: &corev1.PodSecurityContext{SeccompProfile: profile(corev1.SeccompProfileTypeUnconfined)},
		}}, false},
		{"one container covered is not enough", corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "a", SecurityContext: &corev1.SecurityContext{SeccompProfile: profile(corev1.SeccompProfileTypeRuntimeDefault)}},
			{Name: "b"},
		}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := podSetsSeccomp(&tc.pod); got != tc.want {
				t.Errorf("podSetsSeccomp = %v, want %v", got, tc.want)
			}
		})
	}
}

// The rest of the nine, each from the same single pod listing.
func TestEvaluatePodSecurityCoversTheRemainingChecks(t *testing.T) {
	t.Parallel()

	pods := []corev1.Pod{
		pod("ns", "netraw", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_RAW"}}}
		}),
		pod("ns", "hostpath", func(p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "root", VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: "/"}}}}
		}),
		pod("ns", "hostport", func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{HostPort: 8080}}
		}),
		pod("ns", "winhost", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
				WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)}}
		}),
		pod("default", "wrong-namespace", nil),
	}

	got := evaluatePodSecurity(pods, nil)
	for id, want := range map[string]string{
		"5.2.8": "netraw", "5.2.9": "netraw", "5.2.10": "winhost",
		"5.2.11": "hostpath", "5.2.12": "hostport", "5.6.4": "wrong-namespace",
	} {
		v := got[id]
		if v.Compliant {
			t.Errorf("%s should have found %q", id, want)
			continue
		}
		if !strings.Contains(v.Detail, want) {
			t.Errorf("%s should name %q, got %q", id, want, v.Detail)
		}
	}
	// A capability that is not NET_RAW still counts for 5.2.9 and not for 5.2.8.
	only := evaluatePodSecurity([]corev1.Pod{pod("ns", "chown", func(p *corev1.Pod) {
		p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"CHOWN"}}}
	})}, nil)
	if only["5.2.8"].Compliant != true {
		t.Error("CHOWN is not NET_RAW")
	}
	if only["5.2.9"].Compliant {
		t.Error("CHOWN is a capability, so 5.2.9 applies")
	}
}

func TestPoliciesReportDeclaresWhatItSettled(t *testing.T) {
	// The distinction the whole thing exists for: a control this scanner decided and found clean
	// is not the same as one it never examined, and only one of them is a dissent.
	decided := map[string]policyVerdict{
		"5.1.1": {Compliant: true},
		"5.1.5": {Compliant: false, Detail: "payments"},
	}
	rep := policiesReport(decided, "kubernetes/prod", nil)

	if len(rep.Decided) != 2 {
		t.Fatalf("declared %d settled checks, want 2: %+v", len(rep.Decided), rep.Decided)
	}
	for _, tx := range rep.Decided {
		if tx.Taxonomy != cisKubernetesTaxonomy || tx.Version != cisCatalogueVersion {
			t.Errorf("a taxon without its scheme and revision cannot correlate: %+v", tx)
		}
	}
	// 5.1.1 was decided and compliant, so it is declared but produces no finding. Declaring it
	// is the whole point: without that, a check that passed and a check nobody ran look the
	// same.
	for _, r := range rep.Results {
		if r.RuleID == draugrCISRulePrefix+"5.1.1" {
			t.Error("a compliant check is not a finding")
		}
	}
	if !slices.ContainsFunc(rep.Decided, func(tx sarif.Taxon) bool { return tx.ID == "5.1.1" }) {
		t.Error("a compliant check must still be declared as decided")
	}
}

func TestPoliciesReportDeclaresNothingForAManualCheck(t *testing.T) {
	// A check requiring human judgement was examined and not settled. Declaring it would let a
	// consumer read our silence as a verdict.
	rep := policiesReport(map[string]policyVerdict{}, "kubernetes/prod", nil)
	if len(rep.Decided) != 0 {
		t.Errorf("nothing was settled: %+v", rep.Decided)
	}
	if len(rep.Results) == 0 {
		t.Error("the manual-review findings should still be reported")
	}
}

// A reader asks whether a finding is theirs to fix, and the answer is what the scan covered.
// Reported only for a narrowed scan, "the whole cluster" was indistinguishable from "nobody
// recorded it" — and a component owning one namespace and one owning the cluster produce findings
// that otherwise read alike.
func TestScopeDescription(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ns   []string
		want string
	}{
		{"nothing named covers everything", nil, "whole cluster"},
		{"an empty list is the same thing", []string{}, "whole cluster"},
		{"one namespace reads as one", []string{"team-a"}, "namespace team-a"},
		{"several are listed", []string{"team-b", "team-a"}, "namespaces team-a, team-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := scopeDescription(tc.ns); got != tc.want {
				t.Errorf("scopeDescription(%v) = %q, want %q", tc.ns, got, tc.want)
			}
		})
	}
}

// The scope has to reach the report, not just exist. It travels as provenance, which is what the
// console and the markdown render under the control — and which, unlike the finding's location, is
// not part of a finding's fingerprint, so saying it cannot make every existing finding look new.
func TestAClusterWideScanSaysSo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ns   []string
		want string
	}{
		{"whole cluster", nil, "whole cluster"},
		{"one namespace", []string{"team-a"}, "namespace team-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := policiesReport(map[string]policyVerdict{}, "kubernetes/prod", tc.ns)
			var got string
			for _, p := range rep.Provenance {
				for _, f := range p.Fields {
					if f.Key == "scope" {
						got = f.Value
					}
				}
			}
			if got != tc.want {
				t.Errorf("scope provenance = %q, want %q", got, tc.want)
			}
		})
	}
}
