package scanners

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

	decided, err := evaluatePolicies(ctx, client)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", k8sPoliciesScannerName, err)
	}
	return policiesReport(decided, clusterLabel(kubeCtx)), nil
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
func evaluatePolicies(ctx context.Context, client kubernetes.Interface) (map[string]policyVerdict, error) {
	out := map[string]policyVerdict{}

	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	out["5.1.1"] = checkClusterAdminBindings(crbs.Items)

	roles, err := client.RbacV1().Roles(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	out["5.1.3"] = checkWildcardRules(roles.Items, clusterRoles.Items)

	accounts, err := client.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	out["5.1.5"] = checkDefaultServiceAccounts(accounts.Items)

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
