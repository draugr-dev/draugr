package scanners

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// fixedNow keeps generated Job names stable across a test.
func fixedNow() time.Time { return time.Unix(1700000000, 0).UTC() }

// jobScanner wires the scanner to a fake cluster whose Jobs immediately reach the given status,
// with a pod carrying the given logs.
func jobScanner(client kubernetes.Interface) kubeBenchJobScanner {
	s := NewKubeBenchJob().(kubeBenchJobScanner)
	s.client = func(string) (kubernetes.Interface, error) { return client, nil }
	s.now = fixedNow
	return s
}

// completedCluster returns a fake clientset where any created Job is immediately Succeeded, so a
// scan runs to completion without waiting.
//
// The reactor only mutates the object it was handed. Calling back into the clientset from inside
// a reactor re-enters its lock and deadlocks, which surfaces as the test hanging rather than
// failing.
func completedCluster() *fake.Clientset {
	c := fake.NewSimpleClientset()
	c.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
		a.(ktesting.CreateAction).GetObject().(*batchv1.Job).Status.Succeeded = 1
		return false, nil, nil // let the tracker store it, status and all
	})
	return c
}

func TestKubeBenchJobInfo(t *testing.T) {
	info := NewKubeBenchJob().Info()
	if info.Name != kubeBenchJobScannerName {
		t.Errorf("name = %q", info.Name)
	}
	// No local binary: the work happens in the cluster, from an image.
	if info.Binary != "" {
		t.Errorf("binary = %q, want none — the image carries the tool", info.Binary)
	}
	// The whole reason this is a separate scanner. Without both effects declared, a run that
	// schedules a privileged pod in someone's cluster would need no acknowledgement.
	kinds := map[plugin.EffectKind]bool{}
	for _, e := range info.Effects {
		kinds[e.Kind] = true
		if e.Detail == "" {
			t.Errorf("effect %q has no detail; the consent prompt would say nothing", e.Kind)
		}
	}
	for _, want := range []plugin.EffectKind{plugin.EffectMutate, plugin.EffectPrivilege} {
		if !kinds[want] {
			t.Errorf("missing %q effect: %+v", want, info.Effects)
		}
	}
}

// The Job must match what kube-bench needs to read a node — host PID and the host paths — and
// must not ask for more than that.
func TestKubeBenchJobSpec(t *testing.T) {
	s := NewKubeBenchJob().(kubeBenchJobScanner)
	s.now = fixedNow
	job := s.buildJob(nil)

	pod := job.Spec.Template.Spec
	if !pod.HostPID {
		t.Error("hostPID is required to see control-plane processes")
	}
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restart policy = %q, want Never", pod.RestartPolicy)
	}
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 {
		t.Error("a failing benchmark is a result, not something to retry")
	}
	if len(pod.Volumes) != len(hostPaths) || len(pod.Containers[0].VolumeMounts) != len(hostPaths) {
		t.Errorf("want %d host paths mounted, got %d volumes / %d mounts",
			len(hostPaths), len(pod.Volumes), len(pod.Containers[0].VolumeMounts))
	}
	// Read-only throughout: a scan has no business being able to change what it inspects.
	for _, m := range pod.Containers[0].VolumeMounts {
		if !m.ReadOnly {
			t.Errorf("mount %q is writable", m.Name)
		}
	}
	// Pinned by digest. A tag is a mutable pointer — v0.15.6 can be repushed — so a tag alone
	// is a scan whose result can change with nothing in the descriptor changing.
	img := pod.Containers[0].Image
	if !strings.Contains(img, "@sha256:") {
		t.Errorf("image %q is not pinned by digest", img)
	}
	// The tag stays for readability: a digest alone says nothing about which version is running.
	if !strings.Contains(img, ":v") {
		t.Errorf("image %q should carry a readable version alongside the digest", img)
	}
	// The default targets are the sections that can only be answered from inside the cluster.
	args := strings.Join(pod.Containers[0].Args, " ")
	if !strings.Contains(args, "--targets master,node,etcd,controlplane") {
		t.Errorf("args = %q", args)
	}
	if strings.Contains(args, "policies") {
		t.Error("policies is answerable read-only; running it here would create a Job for nothing")
	}
}

func TestKubeBenchJobHonoursConfig(t *testing.T) {
	s := NewKubeBenchJob().(kubeBenchJobScanner)
	s.now = fixedNow
	job := s.buildJob(plugin.Config{
		"image":        "registry.example.com/kube-bench:v0.15.6",
		"targets":      "node",
		"benchmark":    "cis-1.9",
		"nodeSelector": "node-role.kubernetes.io/control-plane=, kubernetes.io/os=linux",
	})
	c := job.Spec.Template.Spec.Containers[0]
	if c.Image != "registry.example.com/kube-bench:v0.15.6" {
		t.Errorf("image = %q", c.Image)
	}
	args := strings.Join(c.Args, " ")
	for _, want := range []string{"--targets node", "--benchmark cis-1.9"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q missing %q", args, want)
		}
	}
	sel := job.Spec.Template.Spec.NodeSelector
	if sel["kubernetes.io/os"] != "linux" || len(sel) != 2 {
		t.Errorf("node selector = %v", sel)
	}
	// A control-plane node is tainted, and its configuration is most of what these checks read.
	if len(job.Spec.Template.Spec.Tolerations) == 0 {
		t.Error("without a toleration the Job cannot schedule where it is most useful")
	}
}

func TestParseSelector(t *testing.T) {
	got := parseSelector(" a=1 , b=2 ,, c= ")
	if len(got) != 3 || got["a"] != "1" || got["b"] != "2" || got["c"] != "" {
		t.Errorf("parseSelector = %v", got)
	}
	if parseSelector("  ") != nil {
		t.Error("an empty selector should place no constraint")
	}
}

func TestDurationSetting(t *testing.T) {
	fallback := 5 * time.Minute
	for _, tc := range []struct {
		in   any
		want time.Duration
	}{
		{"90s", 90 * time.Second},
		{"2m", 2 * time.Minute},
		{120, 2 * time.Minute}, // plain seconds, as YAML often gives
		{"nonsense", fallback},
		{-1, fallback},
		{nil, fallback},
	} {
		if got := durationSetting(plugin.Config{"timeout": tc.in}, "timeout", fallback); got != tc.want {
			t.Errorf("durationSetting(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The whole path against a fake cluster: create, wait, read logs, parse, clean up.
func TestKubeBenchJobScan(t *testing.T) {
	c := completedCluster()
	raw, err := os.ReadFile("testdata/kube-bench.json")
	if err != nil {
		t.Fatal(err)
	}
	s := jobScanner(c)
	s.logs = func(context.Context, kubernetes.Interface, string, string) ([]byte, error) {
		return raw, nil
	}

	rep, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes", Ref: "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Errorf("want the fixture's 2 findings, got %d", len(rep.Results))
	}
	if got := rep.Results[0].Location.URI; got != "kubernetes/prod" {
		t.Errorf("location = %q", got)
	}
}

// A Job left behind in someone's cluster is the worst thing this scanner could do. It must go
// even when the scan fails.
func TestKubeBenchJobAlwaysCleansUp(t *testing.T) {
	c := completedCluster()
	s := jobScanner(c)
	s.logs = func(context.Context, kubernetes.Interface, string, string) ([]byte, error) {
		return nil, io.ErrUnexpectedEOF // the run failed after the Job was created
	}
	if _, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil); err == nil {
		t.Fatal("expected the log failure to surface")
	}
	jobs, err := c.BatchV1().Jobs("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("the Job was left behind: %+v", jobs.Items)
	}
}

func TestKubeBenchJobRejectsNonInfraTargets(t *testing.T) {
	_, err := NewKubeBenchJob().Scan(context.Background(), plugin.HostTarget{URL: "https://x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported target") {
		t.Errorf("want an unsupported-target error, got %v", err)
	}
}

// kube-bench exits non-zero when checks fail, so a Failed Job is usually a result rather than a
// crash. The logs are read either way and the parse decides — treating Failed as fatal would
// throw away the findings of every cluster that has any.
func TestWaitForJobTreatsAFailedRunAsAResult(t *testing.T) {
	c := fake.NewSimpleClientset(&batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "kb", Namespace: "default"},
		Status:     batchv1.JobStatus{Failed: 1},
	})
	if err := waitForJob(context.Background(), c, "default", "kb"); err != nil {
		t.Errorf("a failed benchmark run should not be an error: %v", err)
	}
}

// A Job that never finishes — unschedulable, image pull failing — must give up rather than hang,
// because the deferred cleanup only runs once the wait returns.
func TestWaitForJobGivesUp(t *testing.T) {
	c := fake.NewSimpleClientset(&batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "kb", Namespace: "default"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := waitForJob(ctx, c, "default", "kb")
	if err == nil {
		t.Fatal("expected the wait to give up")
	}
	// The message has to suggest what to do; "context deadline exceeded" alone is a dead end.
	for _, want := range []string{"did not finish", "timeout", "nodeSelector"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestWaitForJobReportsALookupFailure(t *testing.T) {
	c := fake.NewSimpleClientset() // no such job
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForJob(ctx, c, "default", "missing"); err == nil {
		t.Error("expected an error when the job cannot be read")
	}
}

// A Job that produced no pod is a different failure from a pod that produced no output, and the
// message should say which.
func TestJobLogsWithNoPod(t *testing.T) {
	c := fake.NewSimpleClientset()
	_, err := jobLogs(context.Background(), c, "default", "kb")
	if err == nil || !strings.Contains(err.Error(), "no pod") {
		t.Errorf("want a no-pod error, got %v", err)
	}
}

// Reaching the cluster can fail before anything is created — a bad context, no kubeconfig.
func TestKubeBenchJobReportsClientFailure(t *testing.T) {
	s := NewKubeBenchJob().(kubeBenchJobScanner)
	s.client = func(string) (kubernetes.Interface, error) { return nil, io.ErrUnexpectedEOF }
	if _, err := s.Scan(context.Background(), plugin.InfraTarget{}, nil); err == nil {
		t.Error("expected the client failure to surface")
	}
}

// The Job lands where the descriptor says, not always in default.
func TestKubeBenchJobHonoursNamespace(t *testing.T) {
	c := completedCluster()
	s := jobScanner(c)
	var sawNamespace string
	s.logs = func(_ context.Context, _ kubernetes.Interface, ns, _ string) ([]byte, error) {
		sawNamespace = ns
		return []byte(`{"Controls":[]}`), nil
	}
	if _, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"},
		plugin.Config{"namespace": "security"}); err != nil {
		t.Fatal(err)
	}
	if sawNamespace != "security" {
		t.Errorf("logs read from %q, want security", sawNamespace)
	}
}

// Two scanners share kube-bench's output format. A finding has to name the one that produced it,
// because the Scanner column is how a reader tells a section-5 finding from a section-4 one.
func TestKubeBenchJobFindingsNameTheJobScanner(t *testing.T) {
	raw, err := os.ReadFile("testdata/kube-bench.json")
	if err != nil {
		t.Fatal(err)
	}
	s := jobScanner(completedCluster())
	s.logs = func(context.Context, kubernetes.Interface, string, string) ([]byte, error) { return raw, nil }
	rep, err := s.Scan(context.Background(), plugin.InfraTarget{Platform: "kubernetes"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tool != kubeBenchJobScannerName {
		t.Errorf("report tool = %q, want %q", rep.Tool, kubeBenchJobScannerName)
	}
	for _, r := range rep.Results {
		if r.Tool != kubeBenchJobScannerName {
			t.Errorf("finding %s names %q, want %q", r.RuleID, r.Tool, kubeBenchJobScannerName)
		}
	}
}

// The two cases of the wait's select can be ready at once, and Go picks between them at random —
// so half the time the loop asked the API with an expired context, and client-go refused inside
// its rate limiter. The reader got a message about our own client instead of the one saying what
// to do about their cluster.
func TestWaitForJobExplainsATimeoutRatherThanTheClient(t *testing.T) {
	t.Parallel()
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "draugr-kube-bench-1-abcde",
			Labels:    map[string]string{"job-name": "draugr-kube-bench-1"},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"},
				},
			}},
		},
	})
	// Already expired: the state the loop is in when the deadline passes.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := waitForJob(ctx, client, "default", "draugr-kube-bench-1")
	if err == nil {
		t.Fatal("want a timeout error")
	}
	if strings.Contains(err.Error(), "rate limiter") {
		t.Errorf("the client's own complaint reached the reader:\n%v", err)
	}
	for _, want := range []string{"did not finish", "ContainerCreating", "longer `timeout`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q:\n%v", want, err)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the cause should still be the deadline: %v", err)
	}
}

// A pod that was never scheduled is a different problem from one still pulling an image, and the
// answer differs: fix the node selector rather than wait longer.
func TestWaitForJobNamesAPodThatWasNeverScheduled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := waitForJob(ctx, fake.NewSimpleClientset(), "default", "draugr-kube-bench-2")
	if err == nil {
		t.Fatal("want a timeout error")
	}
	if !strings.Contains(err.Error(), "not scheduled onto any node") {
		t.Errorf("error should say the pod never started:\n%v", err)
	}
}
