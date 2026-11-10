package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// kubeBenchJobScannerName identifies the in-cluster variant of the CIS benchmark scanner.
const kubeBenchJobScannerName = "kube-bench-job"

// kubeBenchJobScanner audits the parts of the CIS Kubernetes Benchmark that can only be answered
// from inside the cluster, by running kube-bench there as a Job and collecting its output.
//
// A separate scanner from [kubeBenchScanner] rather than a mode on it, because the two have
// genuinely different contracts and the difference is the kind a user should be asked about
// rather than discover. This one creates an object in the cluster it is scanning and needs a pod
// with host access to do it; the other reads through the API and needs nothing. Effects are
// declared per scanner, so keeping them apart is what lets the read-only path stay unguarded
// while this one asks first.
//
// It also needs no local kube-bench or kubectl: the image carries both.
type kubeBenchJobScanner struct {
	info plugin.ScannerInfo
	// client builds a Kubernetes client for a context; injectable for tests.
	client func(kubeCtx string) (kubernetes.Interface, error)
	// now is the clock, so a job name is predictable under test.
	now func() time.Time
	// logs reads the Job's output. Injectable because a fake clientset cannot stream pod logs,
	// so without a seam here the whole path around it would go untested.
	logs func(ctx context.Context, c kubernetes.Interface, namespace, jobName string) ([]byte, error)
}

// kubeBenchJobConfigSchema is the JSON Schema for the in-cluster runner's Saga config
// (controllers.infrastructure.kubeBenchJob). additionalProperties:false rejects mistyped keys.
const kubeBenchJobConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "targets": {
      "type": "string",
      "default": "master,node,etcd,controlplane",
      "description": "Comma-separated kube-bench targets to run, e.g. \"master,node\"."
    },
    "namespace": {
      "type": "string",
      "default": "default",
      "description": "Namespace to create the Job in. It must already exist; Draugr does not create namespaces."
    },
    "image": {
      "type": "string",
      "description": "kube-bench image the Job runs. Pin it to a digest for a reproducible benchmark, and to an internal mirror where the cluster cannot reach a public registry."
    },
    "nodeSelector": {
      "type": "string",
      "description": "Node selector for the Job, as comma-separated key=value pairs. One Job runs every target on a node it matches. Unset, one Job runs on a control-plane node and one on a worker."
    },
    "timeout": {
      "type": "string",
      "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+)$",
      "default": "5m",
      "description": "How long to wait for the Job to finish, e.g. \"5m\"."
    }
  }
}`

// NewKubeBenchJob returns a Scanner that runs the CIS benchmark inside the cluster.
func NewKubeBenchJob() plugin.Scanner {
	return kubeBenchJobScanner{
		info: plugin.ScannerInfo{
			Name:   kubeBenchJobScannerName,
			Origin: "aquasecurity",
			// No Binary: the work happens in the cluster, from an image.
			Controls:    []string{"kubernetes"},
			TargetKinds: []plugin.TargetKind{plugin.TargetKubernetes},
			// The Job reads a node's own filesystem, which has no namespace. So a namespace scope is not
			// unimplemented here, it is meaningless.
			ClusterWide:  true,
			ConfigSchema: json.RawMessage(kubeBenchJobConfigSchema),
			Effects: []plugin.Effect{
				{
					Kind: plugin.EffectMutate,
					Detail: "creates a short-lived Job in the cluster and deletes it when the " +
						"scan finishes",
				},
				{
					Kind: plugin.EffectPrivilege,
					Detail: "that Job runs with hostPID and mounts host paths read-only, which " +
						"is what reading a node's kubelet and control-plane configuration requires",
				},
			},
		},
		client: clientForContext,
		now:    time.Now,
		logs:   jobLogs,
	}
}

// Info describes the scanner.
func (s kubeBenchJobScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion reports the pinned image (implements plugin.CacheVersioner).
//
// No probe needed and none wanted: this scanner runs kube-bench from an image pinned by digest, so
// the digest *is* the version, exactly, and without asking anything at run time.
func (s kubeBenchJobScanner) CacheVersion(context.Context) string {
	return "kube-bench-job@" + defaultKubeBenchImage
}

// Config keys specific to the in-cluster run.
const (
	// namespaceKey is where the Job is created.
	namespaceKey = "namespace"
	// imageKey is the kube-bench image to run. Pinned by default; a private registry or an
	// air-gapped mirror needs its own.
	imageKey = "image"
	// nodeSelectorKey places the Job on a node whose configuration you want audited.
	nodeSelectorKey = "nodeSelector"
	// jobTimeoutKey caps how long to wait before giving up and cleaning up.
	jobTimeoutKey = "timeout"
)

// Defaults for the in-cluster run.
const (
	defaultJobNamespace = "default"
	// defaultKubeBenchImage is pinned by digest, and the digest is the part that matters.
	//
	// A tag is a mutable pointer that can be repushed to different content, and a scan whose
	// result can change with nothing in the descriptor changing is the opposite of what a compliance
	// report is for. The digest makes the pull reproducible and lets the runtime reject content that
	// does not match, the same guarantee `draugr tools install` gets from verifying a checksum before
	// it puts a binary on your PATH.
	//
	// The tag is kept alongside it for readability: @sha256:… alone says nothing about which
	// version is running, and a reader of the descriptor should be able to tell.
	//
	// The tag is the release `draugr tools install` pins for the kube-bench scanner, so the two
	// scanners audit one cluster against the same benchmark definitions.
	// TestKubeBenchJobImageIsTheInstalledRelease holds it there, and its failure message says how
	// to read the digest and the commit when the binary moves.
	defaultKubeBenchImage = "docker.io/aquasec/kube-bench:v0.16.0@sha256:75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679"
	// defaultJobTargets are the sections worth running in-cluster: the ones that read a node's own
	// filesystem and cannot be answered any other way. `policies` is deliberately absent. The
	// read-only scanner already covers it without creating anything.
	defaultJobTargets = "master,node,etcd,controlplane"
	defaultJobTimeout = 5 * time.Minute
)

// Scan places a Job on a node of each role, waits for them, collects their output, and removes
// them.
func (s kubeBenchJobScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	cluster, ok := target.(plugin.KubernetesTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want a Kubernetes cluster)",
			kubeBenchJobScannerName, target)
	}
	// The Job reads a node's filesystem, which has no namespace. Honoring a scope is not merely
	// unimplemented here. It is meaningless, and silently ignoring it would report node-wide
	// findings against a component that asked for three namespaces.
	if err := refuseNamespaceScope(kubeBenchJobScannerName, cluster.Namespaces); err != nil {
		return sarif.Report{}, err
	}
	kubeCtx := kubeContext(target)
	client, err := s.client(kubeCtx)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", kubeBenchJobScannerName, err)
	}

	namespace := stringSetting(cfg, namespaceKey, defaultJobNamespace)
	plan := planJobs(ctx, client, cfg, cluster.Benchmark)

	// The Jobs run at once: each reads its own node, and a benchmark run takes seconds.
	runs := make([]jobRun, len(plan.placements))
	errs := make([]error, len(plan.placements))
	var wg sync.WaitGroup
	for i, p := range plan.placements {
		wg.Go(func() {
			runs[i], errs[i] = s.runJob(ctx, client, kubeCtx, namespace, cfg, cluster.Benchmark, plan, p)
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", kubeBenchJobScannerName, err)
	}

	// This scanner audits the node types a managed platform runs, so what the descriptor says
	// about who operates the cluster decides whether its findings are the team's to act on.
	report := sarif.Report{Tool: kubeBenchJobScannerName, Rules: map[string]sarif.Rule{}}
	benchmark := ""
	for _, run := range runs {
		doc, err := decodeKubeBench(run.out)
		if err != nil {
			return sarif.Report{}, err
		}
		part := reportFromKubeBench(doc, kubeBenchJobScannerName, clusterLabel(target),
			cluster.ProviderOperated, run.read)
		report.Results = append(report.Results, part.Results...)
		report.Decided = append(report.Decided, part.Decided...)
		report.Unchecked = append(report.Unchecked, part.Unchecked...)
		maps.Copy(report.Rules, part.Rules)
		if benchmark == "" && len(doc.Controls) > 0 {
			benchmark = doc.Controls[0].Version
		}
	}
	report.Provenance = []sarif.Provenance{{Tool: kubeBenchJobScannerName, Fields: plan.provenance(benchmark, runs)}}
	return report, nil
}

// jobRun is one Job's output and the node it read.
type jobRun struct {
	out  []byte
	read kubeBenchRead
}

// runJob creates one Job, waits for it, reads its output, and removes it.
func (s kubeBenchJobScanner) runJob(
	ctx context.Context, client kubernetes.Interface, kubeCtx, namespace string, cfg plugin.Config,
	benchmark string, plan jobPlan, p jobPlacement,
) (jobRun, error) {
	job := s.buildJob(cfg, benchmark, p, plan.rancher)
	// Before the create, so the policy scanner reading pods at the same time never sees this
	// Job's pod without knowing it is the scan's own.
	registerOwnJob(kubeCtx, namespace, job.Name)
	created, err := client.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return jobRun{}, fmt.Errorf("create job in %q: %w", namespace, err)
	}

	// Cleanup runs on every path, including a canceled scan, and with its own context: the
	// caller's may already be done, and a Job left behind in someone's cluster is the worst
	// thing this scanner could leave.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		policy := metav1.DeletePropagationBackground
		_ = client.BatchV1().Jobs(namespace).Delete(cleanupCtx, created.Name,
			metav1.DeleteOptions{PropagationPolicy: &policy})
	}()

	timeout := durationSetting(cfg, jobTimeoutKey, defaultJobTimeout)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := waitForJob(waitCtx, client, namespace, created.Name); err != nil {
		return jobRun{}, err
	}

	out, err := s.logs(ctx, client, namespace, created.Name)
	if err != nil {
		return jobRun{}, err
	}
	read := p.read
	if read.node == "" {
		// The scheduler chose, so the pod says where it ran, and the node list what that node is.
		read = plan.readOf(jobNode(ctx, client, namespace, created.Name))
	}
	return jobRun{out: out, read: read}, nil
}

// buildJob renders a Job, following kube-bench's own manifest: host PID so it can see the
// control-plane processes, and read-only host mounts for the files the benchmark inspects.
func (s kubeBenchJobScanner) buildJob(
	cfg plugin.Config, benchmark string, p jobPlacement, rancher bool,
) *batchv1.Job {
	args := []string{"run", "--json", "--targets", strings.Join(p.targets, ",")}
	if benchmark != "" {
		args = append(args, "--benchmark", benchmark)
	}

	// A named Job rather than GenerateName so the log lookup and the cleanup have something to
	// hold onto even if the create response is lost. The role tells apart two Jobs created in the
	// same second.
	name := fmt.Sprintf("draugr-kube-bench-%d", s.now().UTC().Unix())
	if p.role != "" {
		name += "-" + p.role
	}

	backoff := int32(0) // a failed benchmark run is a result, not something to retry
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "draugr"},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoff,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app.kubernetes.io/managed-by": "draugr"},
				},
				Spec: corev1.PodSpec{
					HostPID:       true,
					RestartPolicy: corev1.RestartPolicyNever,
					NodeSelector:  p.selector,
					NodeName:      p.nodeName,
					// Control-plane nodes are tainted, and their configuration is most of what
					// these sections check. Without tolerating that taint the Job is unschedulable
					// exactly where it is most useful.
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					Containers: []corev1.Container{{
						Name:         "kube-bench",
						Image:        stringSetting(cfg, imageKey, defaultKubeBenchImage),
						Command:      []string{"kube-bench"},
						Args:         args,
						VolumeMounts: hostMounts(rancher),
					}},
					Volumes: hostVolumes(rancher),
				},
			},
		},
	}
}

// Node role labels. kubeadm, k3s and RKE2 label a control-plane node with the first; clusters
// older than Kubernetes 1.24 used the second.
const (
	controlPlaneRoleLabel = "node-role.kubernetes.io/control-plane"
	legacyMasterRoleLabel = "node-role.kubernetes.io/master"
	hostnameLabel         = "kubernetes.io/hostname"
)

// Job roles, which name a Job when the run places one on each.
const (
	controlPlaneJobRole = "control-plane"
	nodeJobRole         = "node"
)

// nodeTarget is the kube-bench target that reads a worker's kubelet configuration. Every other
// target reads a control-plane node.
const nodeTarget = "node"

// jobPlacement is one Job: where it runs and which targets it runs there.
type jobPlacement struct {
	// role names the Job when the run has one per role, "" when it has one.
	role    string
	targets []string
	// selector and nodeName pin the pod. Both empty leaves the node to the scheduler.
	selector map[string]string
	nodeName string
	// read is the node the Job is pinned to, zero when the scheduler chooses.
	read kubeBenchRead
}

// jobPlan is the run's Jobs and what it learned about the cluster's nodes placing them.
type jobPlan struct {
	placements []jobPlacement
	// nodes are the cluster's nodes by name, nil when they could not be listed.
	nodes map[string]kubeBenchRead
	// listErr is why the nodes could not be listed.
	listErr error
	// rancher says the cluster is k3s or RKE2, whose benchmarks read /var/lib/rancher.
	rancher bool
}

// planJobs decides where the Jobs run.
//
// One Job reads one node, and kube-bench runs whatever targets it is given on the node it lands
// on. On a node without a control plane, a control-plane check finds no file and no process and
// fails, so where the Job runs decides what the report says. Left to the scheduler, the same
// descriptor reads a different node from one run to the next.
//
// So the control-plane targets run on a control-plane node and the node target on a worker, the
// split kube-bench's own manifests make. A cluster with one role gets one Job on it. A
// `nodeSelector` is the descriptor choosing the node, and gets one Job wherever it lands. When the
// nodes cannot be listed, the scheduler chooses, as it did before nodes were read.
func planJobs(ctx context.Context, client kubernetes.Interface, cfg plugin.Config, benchmark string) jobPlan {
	targets := splitTargets(stringSetting(cfg, targetsKey, defaultJobTargets))
	var plan jobPlan
	list, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		// A client may hand back an empty list beside the error, which would read as a cluster
		// with no nodes.
		list = nil
		plan.listErr = err
	} else {
		plan.nodes = make(map[string]kubeBenchRead, len(list.Items))
		for _, n := range list.Items {
			plan.nodes[n.Name] = kubeBenchRead{node: n.Name, roleKnown: true, controlPlane: isControlPlane(n)}
		}
	}
	plan.rancher = rancherCluster(client, benchmark, list)

	if sel := stringSetting(cfg, nodeSelectorKey, ""); sel != "" || list == nil || len(list.Items) == 0 {
		plan.placements = []jobPlacement{{targets: targets, selector: parseSelector(sel)}}
		return plan
	}

	var controlPlanes, workers []corev1.Node
	for _, n := range list.Items {
		if isControlPlane(n) {
			controlPlanes = append(controlPlanes, n)
		} else {
			workers = append(workers, n)
		}
	}
	var planeTargets, nodeTargets []string
	for _, t := range targets {
		if t == nodeTarget {
			nodeTargets = append(nodeTargets, t)
		} else {
			planeTargets = append(planeTargets, t)
		}
	}
	switch {
	case len(controlPlanes) > 0 && len(workers) > 0 && len(planeTargets) > 0 && len(nodeTargets) > 0:
		plan.placements = []jobPlacement{
			pinned(firstNode(controlPlanes), controlPlaneJobRole, planeTargets),
			pinned(firstNode(workers), nodeJobRole, nodeTargets),
		}
	case len(controlPlanes) > 0 && (len(workers) == 0 || len(nodeTargets) == 0):
		plan.placements = []jobPlacement{pinned(firstNode(controlPlanes), "", targets)}
	default:
		// No control-plane node, or only the node target asked for: a worker reads it all, and a
		// control-plane check it cannot answer is listed as unread.
		plan.placements = []jobPlacement{pinned(firstNode(workers), "", targets)}
	}
	return plan
}

// pinned is a Job pinned to a node by its hostname label, or by name where it has none.
func pinned(n corev1.Node, role string, targets []string) jobPlacement {
	p := jobPlacement{
		role: role, targets: targets,
		read: kubeBenchRead{node: n.Name, roleKnown: true, controlPlane: isControlPlane(n)},
	}
	if host := n.Labels[hostnameLabel]; host != "" {
		p.selector = map[string]string{hostnameLabel: host}
	} else {
		p.nodeName = n.Name
	}
	return p
}

// firstNode is the node a role's Job runs on: a Ready one where there is one, and the first by
// name among those, so repeated runs read the same node.
func firstNode(nodes []corev1.Node) corev1.Node {
	slices.SortFunc(nodes, func(a, b corev1.Node) int {
		if ra, rb := nodeReady(a), nodeReady(b); ra != rb {
			if ra {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return nodes[0]
}

func nodeReady(n corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func isControlPlane(n corev1.Node) bool {
	_, plane := n.Labels[controlPlaneRoleLabel]
	_, master := n.Labels[legacyMasterRoleLabel]
	return plane || master
}

// splitTargets reads "master, node" into its targets, dropping empty entries.
func splitTargets(s string) []string {
	var out []string
	for t := range strings.SplitSeq(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// rancherCluster says the cluster is k3s or RKE2: the benchmark named for it, a node's kubelet
// version, or, where nodes could not be listed, the API server's.
func rancherCluster(client kubernetes.Interface, benchmark string, nodes *corev1.NodeList) bool {
	if strings.HasPrefix(benchmark, "k3s-") || strings.HasPrefix(benchmark, "rke2-") {
		return true
	}
	rancherPlatform := func(version string) bool {
		p := platformFrom(version)
		return p == "k3s" || p == "rke2r"
	}
	if nodes != nil {
		for _, n := range nodes.Items {
			if rancherPlatform(n.Status.NodeInfo.KubeletVersion) {
				return true
			}
		}
		return false
	}
	info, err := client.Discovery().ServerVersion()
	return err == nil && rancherPlatform(info.GitVersion)
}

// readOf is what the plan knows about a node the scheduler chose, by name.
func (p jobPlan) readOf(node string) kubeBenchRead {
	if r, ok := p.nodes[node]; ok {
		return r
	}
	return kubeBenchRead{node: node}
}

// provenance states which nodes the run read and how many it did not. Names alone: which targets
// ran where follows from the node's role, and the line has to fit the console's evidence block.
func (p jobPlan) provenance(benchmark string, runs []jobRun) []sarif.Field {
	var fields []sarif.Field
	if benchmark != "" {
		fields = append(fields, sarif.Field{Key: "benchmark", Value: benchmark})
	}
	var read []string
	seen := map[string]bool{}
	for _, r := range runs {
		name := r.read.node
		if name == "" {
			name = "a node the scheduler chose"
		}
		if _, listed := p.nodes[r.read.node]; listed {
			seen[r.read.node] = true
		}
		read = append(read, name)
	}
	fields = append(fields, sarif.Field{Key: "nodes", Value: strings.Join(read, ", ")})
	switch {
	case p.listErr != nil:
		fields = append(fields, sarif.Field{Value: "node roles unknown, the nodes could not be listed"})
	case len(p.nodes) > len(seen):
		fields = append(fields, sarif.Field{Value: fmt.Sprintf("%d of %s read", len(seen), english.Count(len(p.nodes), "node"))})
	}
	return fields
}

// jobNode is the node a Job's pod ran on, "" when it cannot be read.
func jobNode(ctx context.Context, client kubernetes.Interface, namespace, jobName string) string {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + jobName})
	if err != nil || len(pods.Items) == 0 {
		return ""
	}
	return pods.Items[0].Spec.NodeName
}

// hostPaths are the directories kube-bench reads, from its own Job manifest. Mounted read-only:
// the benchmark inspects configuration, and a scan has no business being able to change it.
var hostPaths = []struct{ name, path string }{
	{"var-lib-cni", "/var/lib/cni"},
	{"var-lib-etcd", "/var/lib/etcd"},
	{"var-lib-kubelet", "/var/lib/kubelet"},
	{"var-lib-kube-scheduler", "/var/lib/kube-scheduler"},
	{"var-lib-kube-controller-manager", "/var/lib/kube-controller-manager"},
	{"etc-systemd", "/etc/systemd"},
	{"lib-systemd", "/lib/systemd"},
	{"srv-kubernetes", "/srv/kubernetes"},
	{"etc-kubernetes", "/etc/kubernetes"},
	{"usr-bin", "/usr/bin"},
	{"etc-cni-netd", "/etc/cni/net.d"},
	{"opt-cni-bin", "/opt/cni/bin"},
}

// usrBinMountPath is where kube-bench expects the host's binaries, which is not where they live
// on the host.
const usrBinMountPath = "/usr/local/mount-from-host/bin"

// rancherPath holds k3s's and RKE2's configuration, certificates and keys, which their benchmarks
// read in place of /etc/kubernetes. Mounted only on those clusters, because it holds the
// cluster's keys and nothing on any other cluster reads it.
var rancherPath = struct{ name, path string }{"var-lib-rancher", "/var/lib/rancher"}

// hostPathsFor are the paths a Job mounts, with /var/lib/rancher on k3s and RKE2.
func hostPathsFor(rancher bool) []struct{ name, path string } {
	if !rancher {
		return hostPaths
	}
	return append(slices.Clone(hostPaths), rancherPath)
}

func hostMounts(rancher bool) []corev1.VolumeMount {
	paths := hostPathsFor(rancher)
	mounts := make([]corev1.VolumeMount, 0, len(paths))
	for _, p := range paths {
		at := p.path
		if p.name == "usr-bin" {
			at = usrBinMountPath
		}
		mounts = append(mounts, corev1.VolumeMount{Name: p.name, MountPath: at, ReadOnly: true})
	}
	return mounts
}

func hostVolumes(rancher bool) []corev1.Volume {
	paths := hostPathsFor(rancher)
	vols := make([]corev1.Volume, 0, len(paths))
	for _, p := range paths {
		vols = append(vols, corev1.Volume{
			Name:         p.name,
			VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: p.path}},
		})
	}
	return vols
}

// parseSelector reads "k=v,k2=v2" into a node selector. Empty means no constraint.
func parseSelector(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	for pair := range strings.SplitSeq(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// durationSetting reads a duration, tolerating the plain seconds YAML sometimes produces.
func durationSetting(cfg plugin.Config, key string, fallback time.Duration) time.Duration {
	switch v := cfg[key].(type) {
	case string:
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			return d
		}
	case int:
		if v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return fallback
}

// jobPollInterval is how often the Job's status is checked. A benchmark run takes seconds, so
// this trades a little chattiness for not sitting idle after it has finished.
const jobPollInterval = 2 * time.Second

// waitForJob blocks until the Job succeeds, fails, or the context is done.
//
// Polling rather than a watch: the wait is bounded and short, a watch adds a connection to keep
// alive and re-establish, and the failure mode of a dropped watch is hanging until the timeout.
// Which is the one outcome that leaves a Job running in someone's cluster for longer than it has
// to.
func waitForJob(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	ticker := time.NewTicker(jobPollInterval)
	defer ticker.Stop()
	for {
		// Checked before the request, not only in the select below. Both cases of that select can be
		// ready at once, and Go picks between them at random, so half the time the loop went round and
		// asked the API with an expired context, which client-go refuses inside its rate limiter. That
		// surfaced as "client rate limiter Wait returned an error: context deadline exceeded", a message
		// about our own client, in place of the one below that says what to do.
		if err := ctx.Err(); err != nil {
			return timedOut(ctx, client, namespace, name, err)
		}
		job, err := client.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("watch job %s/%s: %w", namespace, name, err)
		}
		switch {
		case job.Status.Succeeded > 0:
			return nil
		case job.Status.Failed > 0:
			// kube-bench exits non-zero when checks fail, which is a result rather than an error, but with
			// backoffLimit 0 a genuine crash looks the same from here, so the logs are read either way and
			// the parse decides.
			return nil
		}
		select {
		case <-ctx.Done():
			return timedOut(ctx, client, namespace, name, ctx.Err())
		case <-ticker.C:
		}
	}
}

// timedOut explains a Job that never finished, naming what its pod was doing and what would help.
//
// "did not finish" on its own reads as a hang, and the usual cause is not one. The advice has to
// follow the diagnosis rather than list every possibility: telling somebody to raise the timeout
// for a pod the cluster refused sends them to change a number that was never the problem.
func timedOut(ctx context.Context, client kubernetes.Interface, namespace, name string, cause error) error {
	state, advice := podDiagnosis(ctx, client, namespace, name)
	base := fmt.Sprintf("job %s/%s did not finish", namespace, name)
	if state != "" {
		base += ", " + state
	}
	return fmt.Errorf("%s: %w. The Job has been removed. %s", base, cause, advice)
}

// podDiagnosis describes what the Job's pod was doing, and what would actually help.
//
// Three outcomes, and they need three different answers. No pod means nothing scheduled it. A
// warning from the cluster means the pod was refused, and no amount of waiting changes that. Only
// a pod quietly working, pulling an image, most often. Is a case where a longer timeout is the
// fix, and it is the only case where suggesting one is useful rather than misleading.
func podDiagnosis(ctx context.Context, client kubernetes.Interface, namespace, jobName string) (state, advice string) {
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), podStateTimeout)
	defer cancel()
	pods, err := client.CoreV1().Pods(namespace).List(readCtx, metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil {
		return "", "A longer `timeout` may help."
	}
	if len(pods.Items) == 0 {
		return "no pod was created for it",
			"Nothing scheduled it: check that a node matches the Job's `nodeSelector` and is schedulable."
	}

	pod := pods.Items[0]
	state = string(pod.Status.Phase)
	// The container's own reason first: "ContainerCreating" or "ImagePullBackOff" says which of
	// the two waits this is, where the pod phase says only "Pending" for both.
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			state += " (" + cs.State.Waiting.Reason + ")"
			break
		}
	}
	// Then the warning the cluster raised, which is the part that names a cause rather than a
	// condition. A pod refused a network sandbox sits in ContainerCreating indefinitely, and
	// reporting only that sends the reader to raise a timeout for something no timeout will fix.
	if w := latestWarning(readCtx, client, namespace, pod.Name); w != "" {
		return state + ": " + w,
			"The cluster refused the pod; a longer `timeout` will not change that. " +
				"`kubeBenchJob.namespace` runs it somewhere else."
	}
	return state, "A longer `timeout` may help."
}

// latestWarning returns the most recent Warning event for a pod, or "" when there is none.
func latestWarning(ctx context.Context, client kubernetes.Interface, namespace, pod string) string {
	events, err := client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + pod,
	})
	if err != nil {
		return ""
	}
	var newest *corev1.Event
	for i, e := range events.Items {
		if e.Type != corev1.EventTypeWarning {
			continue
		}
		if newest == nil || eventTime(e).After(eventTime(*newest)) {
			newest = &events.Items[i]
		}
	}
	if newest == nil {
		return ""
	}
	return newest.Reason + ", " + strings.TrimSpace(newest.Message)
}

// eventTime is when an event was last seen, falling back through the fields different cluster
// versions populate. An event with no time at all sorts oldest, which keeps it from displacing one
// that is genuinely current.
func eventTime(e corev1.Event) time.Time {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	return e.FirstTimestamp.Time
}

// podStateTimeout bounds the extra read. It runs after the wait has already given up, so it must
// not become a second wait of its own.
const podStateTimeout = 5 * time.Second

// jobLogs returns the output of the Job's pod.
func jobLogs(ctx context.Context, client kubernetes.Interface, namespace, jobName string) ([]byte, error) {
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "job-name=" + jobName,
	})
	if err != nil {
		return nil, fmt.Errorf("find the job's pod: %w", err)
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("job %s/%s produced no pod", namespace, jobName)
	}
	stream, err := client.CoreV1().Pods(namespace).
		GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("read logs from %s: %w", pods.Items[0].Name, err)
	}
	defer func() { _ = stream.Close() }()
	return io.ReadAll(stream)
}
