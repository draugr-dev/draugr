package scanners

import (
	"context"
	"slices"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// On the recorded AWS run, every check the scan did not decide has a kind: a denial or a precondition
// in the unread list, MANUAL as left for a person, and a check with no result at all as one with
// nothing to check. None of them is the unexplained gap between the coverage count and the total.
func TestEveryUndecidedAWSCheckHasAKind(t *testing.T) {
	f := recordedAWSScan(t)
	f.log += memberAccountLog()
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), webProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, d := range report.Decided {
		kinds[d.ID] = "decided"
	}
	for _, u := range report.Unchecked {
		if !u.PartlyRead {
			kinds[u.Check] = u.Kind
		} else {
			kinds[u.Check] = "partly read"
		}
	}
	for _, u := range report.UnsettledChecks {
		kinds[u.RuleID[len(prowlerRulePrefix):]] = u.Kind
		if u.Location != "aws/111111111111" {
			t.Errorf("%s located at %q, want the account", u.RuleID, u.Location)
		}
	}
	for _, check := range f.checks {
		if kinds[check] == "" {
			t.Errorf("%s has no kind", check)
		}
	}
	for check, want := range map[string]string{
		"account_maintain_current_contact_details": sarif.UncheckedDenied,
		"organizations_delegated_administrators":   sarif.UncheckedPrecondition,
	} {
		if kinds[check] != want {
			t.Errorf("%s is %q, want %q", check, kinds[check], want)
		}
	}
	if !slices.ContainsFunc(report.UnsettledChecks, func(u sarif.UnsettledCheck) bool { return u.Kind == sarif.UnsettledNoResources }) {
		t.Error("no check with nothing to check, on a role with no RDS instances")
	}
}

// forbidding answers verb on resource with the API server's Forbidden.
func forbidding(c *fake.Clientset, verb, resource string) {
	c.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, "", nil)
	})
}

// 5.2.1 with its admission policy bindings refused and no policy engine to pass it is denied with
// that read, not left for a person: granting the list decides it.
func TestARefusedBindingsListDeniesThePolicyControlCheck(t *testing.T) {
	c := accessCluster()
	forbidding(c, "list", "validatingadmissionpolicybindings")
	s := NewK8sPolicies().(draugrK8sPoliciesScanner)
	s.client = func(string) (kubernetes.Interface, error) { return c, nil }
	report, err := s.Scan(context.Background(), plugin.KubernetesTarget{Context: "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(report.Unchecked, func(u sarif.Unchecked) bool { return u.Check == "draugr/cis/5.2.1" })
	if i < 0 {
		t.Fatalf("5.2.1 is not unread: %+v", report.Unchecked)
	}
	if u := report.Unchecked[i]; u.Kind != sarif.UncheckedDenied || u.Reason != "denied list validatingadmissionpolicybindings" {
		t.Errorf("5.2.1 unread as %q, %q", u.Kind, u.Reason)
	}
}

// A read the cluster refuses the credential leaves its checks unread, denied, with the read, rather
// than left for a person; the rest of what the scanner cannot decide stays left for a person.
func TestARefusedReadIsDenied(t *testing.T) {
	c := accessCluster()
	forbidding(c, "list", "rolebindings")
	forbidding(c, "create", "subjectaccessreviews")
	s := NewK8sPolicies().(draugrK8sPoliciesScanner)
	s.client = func(string) (kubernetes.Interface, error) { return c, nil }
	report, err := s.Scan(context.Background(), plugin.KubernetesTarget{Context: "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]string{}
	for _, u := range report.Unchecked {
		if u.Kind != sarif.UncheckedDenied {
			t.Errorf("%s kind %q, want denied", u.Check, u.Kind)
		}
		denied[u.Check] = u.Reason
	}
	for check, reason := range map[string]string{
		"draugr/cis/5.1.8": "denied list rolebindings", "draugr/cis/5.1.13": "denied list rolebindings",
		"draugr/cis/5.1.2": "denied create subjectaccessreviews", "draugr/cis/5.1.4": "denied create subjectaccessreviews",
	} {
		if denied[check] != reason {
			t.Errorf("%s: reason %q, want %q", check, denied[check], reason)
		}
	}
	for _, r := range report.Results {
		if r.Undecided && denied[r.RuleID] != "" {
			t.Errorf("%s is both denied and left for a person", r.RuleID)
		}
	}
	if !slices.ContainsFunc(report.Results, func(r sarif.Result) bool { return r.Undecided }) {
		t.Error("no check left for a person")
	}
	// Another failure is no denial, and its checks stay left for a person.
	other := accessCluster()
	refusing(other, "list", "rolebindings")
	s.client = func(string) (kubernetes.Interface, error) { return other, nil }
	if report, _ := s.Scan(context.Background(), plugin.KubernetesTarget{Context: "prod"}, nil); len(report.Unchecked) != 0 {
		t.Errorf("a read that failed for another reason is denied: %+v", report.Unchecked)
	}
}
