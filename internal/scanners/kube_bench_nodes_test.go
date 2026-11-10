package scanners

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// testNode is a node with the labels kubeadm gives it: a hostname, and a control-plane role where
// it is one.
func testNode(name string, controlPlane, ready bool, kubelet string) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{hostnameLabel: name}}}
	if controlPlane {
		n.Labels[controlPlaneRoleLabel] = ""
	}
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}}
	n.Status.NodeInfo.KubeletVersion = kubelet
	return n
}

// clusterOf is a fake cluster holding objs, where any Job created is immediately Succeeded and
// is recorded in created.
func clusterOf(created *[]*batchv1.Job, objs ...runtime.Object) *fake.Clientset {
	c := fake.NewSimpleClientset(objs...)
	var mu sync.Mutex
	c.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, runtime.Object, error) {
		job := a.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Succeeded = 1
		if created != nil {
			mu.Lock()
			*created = append(*created, job.DeepCopy())
			mu.Unlock()
		}
		return false, nil, nil
	})
	return c
}

// twoNodeCluster is a kind cluster's shape: one control-plane node and one worker.
func twoNodeCluster() *fake.Clientset {
	return clusterOf(nil,
		testNode("kind-control-plane", true, true, "v1.34.0"),
		testNode("kind-worker", false, true, "v1.34.0"))
}

func TestPlanJobsPlacesEachRoleOnItsNode(t *testing.T) {
	t.Parallel()
	plan := planJobs(context.Background(), twoNodeCluster(), nil, "")
	if len(plan.placements) != 2 {
		t.Fatalf("want a Job per role, got %+v", plan.placements)
	}
	plane, worker := plan.placements[0], plan.placements[1]
	if plane.selector[hostnameLabel] != "kind-control-plane" ||
		!slices.Equal(plane.targets, []string{"master", "etcd", "controlplane"}) {
		t.Errorf("control-plane Job = %+v, want master, etcd and controlplane on kind-control-plane", plane)
	}
	if worker.selector[hostnameLabel] != "kind-worker" || !slices.Equal(worker.targets, []string{"node"}) {
		t.Errorf("worker Job = %+v, want node on kind-worker", worker)
	}
	if plane.role == worker.role {
		t.Errorf("two Jobs created in one second need different names, both have role %q", plane.role)
	}
}

func TestPlanJobsOnOneRole(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		cfg     plugin.Config
		nodes   []runtime.Object
		want    string
		targets []string
	}{
		{
			name:    "a single control-plane node runs every target",
			nodes:   []runtime.Object{testNode("solo", true, true, "")},
			want:    "solo",
			targets: []string{"master", "node", "etcd", "controlplane"},
		},
		{
			// A managed cluster shows no control-plane node. A worker reads it all, and the
			// control-plane checks it cannot answer are listed as unread.
			name:    "workers only, the Ready one first",
			nodes:   []runtime.Object{testNode("a-down", false, false, ""), testNode("b-up", false, true, "")},
			want:    "b-up",
			targets: []string{"master", "node", "etcd", "controlplane"},
		},
		{
			name:    "only the node target runs on a worker",
			cfg:     plugin.Config{"targets": "node"},
			nodes:   []runtime.Object{testNode("plane", true, true, ""), testNode("worker", false, true, "")},
			want:    "worker",
			targets: []string{"node"},
		},
		{
			name:    "only control-plane targets run on the control plane",
			cfg:     plugin.Config{"targets": "master, etcd"},
			nodes:   []runtime.Object{testNode("plane", true, true, ""), testNode("worker", false, true, "")},
			want:    "plane",
			targets: []string{"master", "etcd"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			plan := planJobs(context.Background(), clusterOf(nil, c.nodes...), c.cfg, "")
			if len(plan.placements) != 1 {
				t.Fatalf("want one Job, got %+v", plan.placements)
			}
			p := plan.placements[0]
			if p.read.node != c.want || p.role != "" || !slices.Equal(p.targets, c.targets) {
				t.Errorf("Job = %+v, want %v on %s", p, c.targets, c.want)
			}
		})
	}
}

// A node without a hostname label is pinned by name, so it is still the node the run reads.
func TestPlanJobsPinsANodeWithNoHostnameLabelByName(t *testing.T) {
	t.Parallel()
	n := testNode("unlabeled", true, true, "")
	delete(n.Labels, hostnameLabel)
	plan := planJobs(context.Background(), clusterOf(nil, n), nil, "")
	if p := plan.placements[0]; p.nodeName != "unlabeled" || p.selector != nil {
		t.Errorf("Job = %+v, want it pinned to unlabeled by name", p)
	}
}

// Without the node list the scheduler chooses, as it did before nodes were read, and the
// provenance says the roles were not read.
func TestPlanJobsWithoutTheNodeList(t *testing.T) {
	t.Parallel()
	c := clusterOf(nil)
	c.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "", nil)
	})
	c.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.35.5+k3s1"}

	plan := planJobs(context.Background(), c, nil, "")
	if len(plan.placements) != 1 || plan.placements[0].selector != nil || plan.placements[0].nodeName != "" {
		t.Fatalf("want one Job the scheduler places, got %+v", plan.placements)
	}
	if !plan.rancher {
		t.Error("the API server's version names k3s, so /var/lib/rancher has to be mounted")
	}
	got := sarif.Provenance{Fields: plan.provenance("cis-1.9", []jobRun{{}})}.Describe()
	if want := "benchmark: cis-1.9 · nodes: a node the scheduler chose · node roles unknown, the nodes could not be listed"; got != want {
		t.Errorf("provenance = %q, want %q", got, want)
	}
}

// k3s and RKE2 keep their configuration and keys under /var/lib/rancher, and their benchmarks read
// it there. Without the mount every such check finds no file and fails.
func TestTheRancherMountFollowsTheDistribution(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name      string
		kubelet   string
		benchmark string
		want      bool
	}{
		{"k3s node", "v1.35.5+k3s1", "", true},
		{"RKE2 node", "v1.30.4+rke2r1", "", true},
		{"k3s benchmark named", "v1.34.0", "k3s-cis-1.9", true},
		{"RKE2 benchmark named", "v1.34.0", "rke2-cis-1.7", true},
		{"vanilla", "v1.34.0", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			plan := planJobs(context.Background(), clusterOf(nil, testNode("n", true, true, c.kubelet)), nil, c.benchmark)
			if plan.rancher != c.want {
				t.Fatalf("rancher = %v, want %v", plan.rancher, c.want)
			}
			s := NewKubeBenchJob().(kubeBenchJobScanner)
			s.now = fixedNow
			pod := s.buildJob(nil, c.benchmark, plan.placements[0], plan.rancher).Spec.Template.Spec
			mounted := false
			for _, m := range pod.Containers[0].VolumeMounts {
				if m.MountPath == "/var/lib/rancher" {
					mounted = true
					if !m.ReadOnly {
						t.Error("/var/lib/rancher holds the cluster's keys and is mounted writable")
					}
				}
			}
			if mounted != c.want || len(pod.Volumes) != len(pod.Containers[0].VolumeMounts) {
				t.Errorf("/var/lib/rancher mounted = %v, want %v (%d volumes, %d mounts)",
					mounted, c.want, len(pod.Volumes), len(pod.Containers[0].VolumeMounts))
			}
		})
	}
}

// kube-bench output for each Job, in the shape a real run prints: a control-plane check that read
// a file, and a worker check that did.
const (
	planeOutput = `{"Controls":[{"id":"1","version":"cis-1.12","node_type":"master","tests":[
	 {"section":"1.1","results":[
	  {"test_number":"1.1.1","test_desc":"API server pod file permissions","status":"FAIL","scored":true,"actual_value":"permissions=644"},
	  {"test_number":"1.1.2","test_desc":"API server pod file ownership","status":"PASS","scored":true,"actual_value":"root:root"}]}]}]}`
	workerOutput = `{"Controls":[{"id":"4","version":"cis-1.12","node_type":"node","tests":[
	 {"section":"4.1","results":[
	  {"test_number":"4.1.1","test_desc":"kubelet service file permissions","status":"FAIL","scored":true,"actual_value":"permissions=777"}]}]}]}`
	// A worker reading control-plane checks prints nothing for them, and kube-bench fails them.
	workerReadingThePlane = `{"Controls":[{"id":"1","version":"cis-1.12","node_type":"master","tests":[
	 {"section":"1.1","results":[
	  {"test_number":"1.1.1","test_desc":"API server pod file permissions","status":"FAIL","scored":true,"actual_value":""}]}]},
	 {"id":"4","version":"cis-1.12","node_type":"node","tests":[
	 {"section":"4.1","results":[
	  {"test_number":"4.1.1","test_desc":"kubelet service file permissions","status":"FAIL","scored":true,"actual_value":"permissions=777"}]}]}]}`
)

// logsByRole answers each Job with the output for its role.
func logsByRole(byRole map[string]string) func(context.Context, kubernetes.Interface, string, string) ([]byte, error) {
	return func(_ context.Context, _ kubernetes.Interface, _, job string) ([]byte, error) {
		for role, out := range byRole {
			if role != "" && strings.HasSuffix(job, "-"+role) {
				return []byte(out), nil
			}
		}
		return []byte(byRole[""]), nil
	}
}

// The whole path on a two-node cluster: a Job on each node, both outputs in one report, the nodes
// named in its provenance, and both Jobs removed.
func TestKubeBenchJobScanReadsANodeOfEachRole(t *testing.T) {
	t.Parallel()
	var created []*batchv1.Job
	c := clusterOf(&created,
		testNode("kind-control-plane", true, true, "v1.34.0"),
		testNode("kind-worker", false, true, "v1.34.0"),
		testNode("kind-worker2", false, true, "v1.34.0"))
	s := jobScanner(c)
	s.logs = logsByRole(map[string]string{controlPlaneJobRole: planeOutput, nodeJobRole: workerOutput})

	rep, err := s.Scan(context.Background(), plugin.KubernetesTarget{Cluster: "kind"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, r := range rep.Results {
		rules = append(rules, r.RuleID)
	}
	slices.Sort(rules)
	if want := []string{"kube-bench/cis/1.1.1", "kube-bench/cis/4.1.1"}; !slices.Equal(rules, want) {
		t.Errorf("findings = %v, want %v", rules, want)
	}
	if len(rep.Decided) != 3 || len(rep.Unchecked) != 0 {
		t.Errorf("decided %d, unchecked %+v; want 3 decided and nothing unread", len(rep.Decided), rep.Unchecked)
	}
	if len(rep.Provenance) != 1 {
		t.Fatalf("provenance = %+v, want one entry", rep.Provenance)
	}
	want := "benchmark: cis-1.12 · nodes: kind-control-plane, kind-worker · 2 of 3 nodes read"
	if got := rep.Provenance[0].Describe(); got != want {
		t.Errorf("provenance = %q, want %q", got, want)
	}

	if len(created) != 2 {
		t.Fatalf("created %d Jobs, want one per role", len(created))
	}
	for _, job := range created {
		host := job.Spec.Template.Spec.NodeSelector[hostnameLabel]
		switch {
		case strings.HasSuffix(job.Name, "-"+controlPlaneJobRole) && host == "kind-control-plane":
		case strings.HasSuffix(job.Name, "-"+nodeJobRole) && host == "kind-worker":
		default:
			t.Errorf("Job %s pinned to %q", job.Name, host)
		}
	}
	jobs, err := c.BatchV1().Jobs("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("Jobs left behind: %d", len(jobs.Items))
	}
}

// A control-plane check run on a worker read nothing. It is listed as unread under the node, not
// reported as a failure of the cluster.
func TestKubeBenchJobListsAControlPlaneCheckOnAWorkerAsUnread(t *testing.T) {
	t.Parallel()
	c := clusterOf(nil, testNode("eks-node", false, true, "v1.34.0-eks-1"))
	s := jobScanner(c)
	s.logs = logsByRole(map[string]string{"": workerReadingThePlane})

	rep, err := s.Scan(context.Background(), plugin.KubernetesTarget{Cluster: "eks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "kube-bench/cis/4.1.1" {
		t.Errorf("findings = %+v, want only the worker's 4.1.1", rep.Results)
	}
	want := []sarif.Unchecked{{Scanner: kubeBenchJobScannerName, Check: "1.1.1", Group: "node eks-node",
		Reason: "not a control-plane node"}}
	if !slices.Equal(rep.Unchecked, want) {
		t.Errorf("unchecked = %+v, want %+v", rep.Unchecked, want)
	}
	for _, d := range rep.Decided {
		if d.ID == "1.1.1" {
			t.Error("a check that read nothing was counted as decided")
		}
	}
}

// With a nodeSelector the scheduler places the Job, and the pod says where it ran. A worker it
// landed on is named, and its control-plane checks are unread.
func TestKubeBenchJobNamesTheNodeASelectorChose(t *testing.T) {
	t.Parallel()
	c := clusterOf(nil,
		testNode("plane", true, true, ""),
		testNode("worker", false, true, ""),
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kb-pod",
				Labels: map[string]string{"job-name": "draugr-kube-bench-1700000000"}},
			Spec: corev1.PodSpec{NodeName: "worker"},
		})
	s := jobScanner(c)
	s.logs = logsByRole(map[string]string{"": workerReadingThePlane})

	rep, err := s.Scan(context.Background(), plugin.KubernetesTarget{Cluster: "c"},
		plugin.Config{"nodeSelector": "pool=general"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unchecked) != 1 || rep.Unchecked[0].Group != "node worker" {
		t.Errorf("unchecked = %+v, want 1.1.1 unread on node worker", rep.Unchecked)
	}
	want := "benchmark: cis-1.12 · nodes: worker · 1 of 2 nodes read"
	if got := rep.Provenance[0].Describe(); got != want {
		t.Errorf("provenance = %q, want %q", got, want)
	}
}

// One Job failing fails the scan, and the other Job is still removed.
func TestKubeBenchJobFailsWhenOneJobFails(t *testing.T) {
	t.Parallel()
	c := clusterOf(nil, testNode("plane", true, true, ""), testNode("worker", false, true, ""))
	s := jobScanner(c)
	s.logs = func(_ context.Context, _ kubernetes.Interface, _, job string) ([]byte, error) {
		if strings.HasSuffix(job, "-"+nodeJobRole) {
			return nil, context.DeadlineExceeded
		}
		return []byte(planeOutput), nil
	}
	if _, err := s.Scan(context.Background(), plugin.KubernetesTarget{}, nil); err == nil {
		t.Fatal("want the worker Job's failure to fail the scan")
	}
	jobs, err := c.BatchV1().Jobs("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs.Items) != 0 {
		t.Errorf("Jobs left behind: %d", len(jobs.Items))
	}
}

// Output that does not parse fails the scan rather than reporting nothing.
func TestKubeBenchJobRejectsOutputItCannotRead(t *testing.T) {
	t.Parallel()
	s := jobScanner(clusterOf(nil, testNode("solo", true, true, "")))
	s.logs = logsByRole(map[string]string{"": "not json"})
	if _, err := s.Scan(context.Background(), plugin.KubernetesTarget{}, nil); err == nil {
		t.Fatal("want an error for output that is not kube-bench's JSON")
	}
}

// The shapes below are kube-bench's own, from runs of the pinned image on k3s, where the image has
// no journalctl.
func TestCommandsNotFound(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		res  kubeBenchFinding
		want []string
	}{
		{"BusyBox's line", kubeBenchFinding{ActualValue: "/bin/sh: journalctl: not found"}, []string{"journalctl"}},
		{"bash's line", kubeBenchFinding{ActualValue: "bash: line 1: journalctl: command not found"}, []string{"journalctl"}},
		{
			"quoted in the reason of an audit that exited non-zero",
			kubeBenchFinding{Reason: `failed to run: "journalctl -m -u k3s | grep 'Running kube-apiserver' | tail -n1 | grep 'anonymous-auth'", output: "/bin/sh: journalctl: not found\n", error: exit status 1`},
			[]string{"journalctl"},
		},
		{
			"two commands",
			kubeBenchFinding{ActualValue: "/bin/sh: journalctl: not found\n/bin/sh: systemctl: not found\n/bin/sh: journalctl: not found"},
			[]string{"journalctl", "systemctl"},
		},
		{"a value after the error", kubeBenchFinding{ActualValue: "/bin/sh: journalctl: not found\n--anonymous-auth=false"}, nil},
		{"a value", kubeBenchFinding{ActualValue: "permissions=600"}, nil},
		{"nothing printed", kubeBenchFinding{}, nil},
		{"a reason with empty output", kubeBenchFinding{Reason: `failed to run: "grep x", output: "", error: exit status 1`}, nil},
		{"a reason that does not quote", kubeBenchFinding{Reason: `failed to run: "x", output: "\q", error: exit status 1`}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := commandsNotFound(c.res); !slices.Equal(got, c.want) {
				t.Errorf("commandsNotFound = %v, want %v", got, c.want)
			}
		})
	}
}

// On a k3s node, a check whose command was not found is unread whether kube-bench passed or failed
// it. A check that a flag is absent passes on an empty line. A WARN stays a finding for a person to
// review.
func TestAChecksMissingCommandMakesItUnread(t *testing.T) {
	t.Parallel()
	const out = `{"Controls":[{"id":"1","version":"k3s-cis-1.9","node_type":"master","tests":[
	 {"section":"1.2","results":[
	  {"test_number":"1.2.1","test_desc":"anonymous-auth","status":"FAIL","scored":true,"actual_value":"",
	   "reason":"failed to run: \"journalctl -m -u k3s | grep anonymous-auth\", output: \"/bin/sh: journalctl: not found\\n\", error: exit status 1"},
	  {"test_number":"1.2.2","test_desc":"token-auth-file","status":"PASS","scored":true,"actual_value":"/bin/sh: journalctl: not found"},
	  {"test_number":"1.2.3","test_desc":"DenyServiceExternalIPs","status":"WARN","scored":false,"actual_value":"/bin/sh: journalctl: not found"},
	  {"test_number":"1.1.13","test_desc":"admin.conf permissions","status":"PASS","scored":true,"actual_value":"permissions=600"}]}]}]}`
	doc, err := decodeKubeBench([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	rep := reportFromKubeBench(doc, kubeBenchJobScannerName, "kubernetes/k3s", false,
		kubeBenchRead{node: "k3s-server", roleKnown: true, controlPlane: true})

	var unread []string
	for _, u := range rep.Unchecked {
		unread = append(unread, u.Check)
		if u.Reason != "journalctl not found" || u.Group != "node k3s-server" {
			t.Errorf("unchecked %+v, want journalctl not found on node k3s-server", u)
		}
	}
	if !slices.Equal(unread, []string{"1.2.1", "1.2.2"}) {
		t.Errorf("unread = %v, want 1.2.1 and 1.2.2", unread)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "kube-bench/cis/1.2.3" {
		t.Errorf("findings = %+v, want only the WARN", rep.Results)
	}
	if len(rep.Decided) != 1 || rep.Decided[0].ID != "1.1.13" {
		t.Errorf("decided = %+v, want only 1.1.13", rep.Decided)
	}
}

// The read-only scanner reads no node, so what it could not read is listed under the cluster.
func TestUnreadChecksWithNoNodeAreListedUnderTheCluster(t *testing.T) {
	t.Parallel()
	if got := (kubeBenchRead{}).group("kubernetes/prod"); got != "kubernetes/prod" {
		t.Errorf("group = %q", got)
	}
	// A run whose node's role is unknown cannot say a control-plane check read nothing.
	res := kubeBenchFinding{Status: "FAIL"}
	if got := (kubeBenchRead{node: "n"}).unreadReason("master", res); got != "" {
		t.Errorf("unreadReason = %q, want none without the node's role", got)
	}
}
