package scanners

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// privilegedPod is a pod running a privileged container, owned by the named Job, or by nothing
// when job is "".
func privilegedPod(namespace, name, job string, labels map[string]string) *corev1.Pod {
	yes := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", SecurityContext: &corev1.SecurityContext{Privileged: &yes},
		}}},
	}
	if job != "" {
		pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job}}
	}
	return pod
}

func TestOwnedByThisRun(t *testing.T) {
	t.Parallel()
	registerOwnJob("ctx-own", "scan", "draugr-kube-bench-1")
	for _, c := range []struct {
		name    string
		kubeCtx string
		pod     *corev1.Pod
		want    bool
	}{
		{"the registered Job's pod", "ctx-own", privilegedPod("scan", "p", "draugr-kube-bench-1", nil), true},
		{"the same name in another cluster", "ctx-other", privilegedPod("scan", "p", "draugr-kube-bench-1", nil), false},
		{"the same name in another namespace", "ctx-own", privilegedPod("default", "p", "draugr-kube-bench-1", nil), false},
		{"another Job", "ctx-own", privilegedPod("scan", "p", "draugr-kube-bench-2", nil), false},
		// A label anybody can set is not a way out of the policy checks.
		{"Draugr's label on a pod of its own", "ctx-own",
			privilegedPod("scan", "p", "", map[string]string{"app.kubernetes.io/managed-by": "draugr"}), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := ownedByThisRun(c.kubeCtx, c.pod); got != c.want {
				t.Errorf("ownedByThisRun = %v, want %v", got, c.want)
			}
		})
	}
}

// The policy scanner reads the cluster's pods while kube-bench-job's privileged pod runs. That pod
// is the scan's own and is left out; a privileged pod of the cluster's is still reported.
func TestThePolicyScannerLeavesOutTheJobsOwnPod(t *testing.T) {
	t.Parallel()
	c := clusterOf(nil, testNode("solo", true, true, ""))
	job := NewKubeBenchJob().(kubeBenchJobScanner)
	job.client = func(string) (kubernetes.Interface, error) { return c, nil }
	job.now = fixedNow
	job.logs = func(ctx context.Context, cl kubernetes.Interface, ns, name string) ([]byte, error) {
		// While the Job runs: its pod exists beside a privileged pod of the cluster's.
		for _, p := range []*corev1.Pod{
			privilegedPod(ns, name+"-abcde", name, nil),
			privilegedPod("apps", "cluster-own", "", nil),
		} {
			if _, err := cl.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
				return nil, err
			}
		}
		policies := NewK8sPolicies().(draugrK8sPoliciesScanner)
		policies.client = func(string) (kubernetes.Interface, error) { return cl, nil }
		rep, err := policies.Scan(ctx, plugin.KubernetesTarget{Context: "ctx-policies"}, nil)
		if err != nil {
			return nil, err
		}
		var got []string
		for _, r := range rep.Results {
			if r.RuleID == draugrCISRulePrefix+"5.2.2" {
				got = append(got, r.Message)
			}
		}
		joined := strings.Join(got, "\n")
		if strings.Contains(joined, name) || !strings.Contains(joined, "apps/cluster-own") {
			t.Errorf("5.2.2 findings = %q, want the cluster's pod and not the Job's", got)
		}
		return []byte(planeOutput), nil
	}
	if _, err := job.Scan(context.Background(), plugin.KubernetesTarget{Context: "ctx-policies"}, nil); err != nil {
		t.Fatal(err)
	}
}
