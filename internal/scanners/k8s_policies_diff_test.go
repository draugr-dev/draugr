package scanners

import (
	"context"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// runsPrivileged is a pod whose one container runs privileged.
func runsPrivileged(ns, name string) *corev1.Pod {
	p := pod(ns, name, func(p *corev1.Pod) {
		p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: boolPtr(true)}
	})
	return &p
}

// policiesFor scans the pods as the policies scanner reads a cluster and files what it finds under
// a component, as the engine does.
func policiesFor(t *testing.T, cluster, component string, pods ...runtime.Object) []sarif.Result {
	t.Helper()
	decided, err := evaluatePolicies(context.Background(), fake.NewSimpleClientset(pods...), nil)
	if err != nil {
		t.Fatal(err)
	}
	rep := policiesReport(decided, "kubernetes/"+cluster, nil)
	for i := range rep.Results {
		rep.Results[i].Component = component
	}
	return rep.Results
}

// throughTheFile writes a report and reads it back, as `draugr diff` and `scan --base` read one.
func throughTheFile(t *testing.T, results []sarif.Result) sarif.Report {
	t.Helper()
	encoded, err := sarif.Report{Results: results}.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	read, err := sarif.FromSARIF(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return read
}

// A Kubernetes check is one finding listing every object that fails it, so its message changes when
// one object joins or leaves. Comparing two scans must not take a check that still fails for a fixed
// one. Two clusters under two components: one gains a privileged pod, the other loses one, and
// kube-proxy stays privileged in both.
func TestAnObjectJoiningACheckIsNewAndFixesNothing(t *testing.T) {
	t.Parallel()
	proxy := func() *corev1.Pod { return runsPrivileged("kube-system", "kube-proxy-wh627") }

	base := append(
		policiesFor(t, "prod", "api", proxy()),
		policiesFor(t, "staging", "web", proxy(), runsPrivileged("apps", "old-debug"))...)
	head := append(
		policiesFor(t, "prod", "api", proxy(), runsPrivileged("default", "debug-shell")),
		policiesFor(t, "staging", "web", proxy())...)

	got := diff.Compare(throughTheFile(t, base), throughTheFile(t, head))

	if len(got.Fixed) != 0 {
		for _, f := range got.Fixed {
			t.Errorf("fixed %s in %s: %q, but every object it listed still fails it", f.RuleID, f.Component, f.Message)
		}
	}
	// The pod added to prod is new on every check it fails, and only there.
	var privileged bool
	for _, n := range got.New {
		if n.Component != "api" || !slices.Contains(n.Objects, "default/debug-shell/app") &&
			!slices.Contains(n.Objects, "default/debug-shell") {
			t.Errorf("new %s in %s lists %v, want only checks the pod added to prod fails", n.RuleID, n.Component, n.Objects)
		}
		if n.RuleID == draugrCISRulePrefix+"5.2.2" {
			privileged = true
		}
	}
	if !privileged {
		t.Errorf("the privileged pod added to prod is not new under 5.2.2: new = %v", checksIn(got.New))
	}
	// Staging lost a pod and gained none, so none of its checks is new, and 5.2.2 still fails for
	// kube-proxy: unchanged, as the head reads it.
	var stagingPrivileged *sarif.Result
	for i, u := range got.Unchanged {
		if u.Component == "web" && u.RuleID == draugrCISRulePrefix+"5.2.2" {
			stagingPrivileged = &got.Unchanged[i]
		}
	}
	if stagingPrivileged == nil {
		t.Fatalf("staging's 5.2.2 is not unchanged: unchanged = %v", checksIn(got.Unchanged))
	}
	if strings.Contains(stagingPrivileged.Message, "old-debug") {
		t.Errorf("unchanged staging 5.2.2 reads %q, want the head's list", stagingPrivileged.Message)
	}
	// The gate on new findings still trips on what the change added.
	if len(got.GateNew(sarif.SeverityLow, "")) == 0 {
		t.Error("the gate on new findings did not trip on a privileged pod added to prod")
	}
}

// A check listing the same objects in both scans pairs on its message, as any finding does, and a
// check that only reads in one scan is new or fixed as before.
func TestACheckWithTheSameObjectsIsUnchanged(t *testing.T) {
	t.Parallel()
	pods := func() []runtime.Object {
		return []runtime.Object{runsPrivileged("kube-system", "kube-proxy-a"), runsPrivileged("apps", "agent")}
	}
	base := append(policiesFor(t, "prod", "api", pods()...), policiesFor(t, "staging", "web", pods()...)...)
	head := append(policiesFor(t, "prod", "api", pods()...), policiesFor(t, "staging", "web")...)

	got := diff.Compare(throughTheFile(t, base), throughTheFile(t, head))
	if len(got.New) != 0 {
		t.Errorf("new = %v, want none", checksIn(got.New))
	}
	for _, f := range got.Fixed {
		if f.Component != "web" {
			t.Errorf("fixed %s in %s, want only staging's checks, which nothing fails any more", f.RuleID, f.Component)
		}
	}
	if len(got.Fixed) == 0 {
		t.Error("staging's checks pass at the head and none was reported fixed")
	}
}

// Every object is on the finding, not the shortened list its message prints.
func TestAFindingCarriesEveryObject(t *testing.T) {
	t.Parallel()
	var pods []runtime.Object
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		pods = append(pods, runsPrivileged("apps", name))
	}
	pods = append(pods, runsPrivileged("kube-system", "kube-proxy"))
	for _, r := range throughTheFile(t, policiesFor(t, "prod", "api", pods...)).Results {
		if r.RuleID != draugrCISRulePrefix+"5.2.2" {
			continue
		}
		if !strings.Contains(r.Message, "and 2 more") {
			t.Errorf("message %q, want the list shortened", r.Message)
		}
		if len(r.Objects) != 8 || r.Objects[7] != "kube-system/kube-proxy/app" {
			t.Errorf("objects = %v, want all seven of the operators' and then the distribution's", r.Objects)
		}
		return
	}
	t.Fatal("no 5.2.2 finding")
}

// checksIn names each finding by its component and rule, for a failure message.
func checksIn(rs []sarif.Result) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Component+":"+r.RuleID)
	}
	return out
}
