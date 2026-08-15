package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

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
      "description": "Comma-separated kube-bench targets to run, e.g. \"master,node\"."
    },
    "benchmark": {
      "type": "string",
      "description": "kube-bench benchmark to run, e.g. cis-1.9. Defaults to letting kube-bench detect the cluster's version."
    },
    "namespace": {
      "type": "string",
      "description": "Namespace to create the Job in. It must already exist; Draugr does not create namespaces."
    },
    "image": {
      "type": "string",
      "description": "kube-bench image the Job runs. Pin it to a digest for a reproducible benchmark, and to an internal mirror where the cluster cannot reach a public registry."
    },
    "nodeSelector": {
      "type": "string",
      "description": "Node selector for the Job, as comma-separated key=value pairs. Use it to benchmark a specific node pool."
    },
    "timeout": {
      "type": "string",
      "description": "How long to wait for the Job to finish, e.g. \"5m\". Plain seconds are accepted."
    },
    "context": {
      "type": "string",
      "description": "kubeconfig context to create the Job in. Defaults to the current context."
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
			Controls:    []string{"infrastructure"},
			TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
			// The Job reads a node's own filesystem, which has no namespace — so a
			// namespace scope is not unimplemented here, it is meaningless.
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
// No probe needed and none wanted: this scanner runs kube-bench from an image pinned by digest,
// so the digest *is* the version — exactly, and without asking anything at run time.
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
	// A tag is a mutable pointer: v0.15.6 can be repushed to different content, and a scan whose
	// result can change with nothing in the descriptor changing is the opposite of what a
	// compliance report is for. The digest makes the pull reproducible and lets the runtime
	// reject content that does not match — the same guarantee `draugr tools install` gets from
	// verifying a checksum before it puts a binary on your PATH.
	//
	// The tag is kept alongside it for readability: @sha256:… alone says nothing about which
	// version is running, and a reader of the descriptor should be able to tell.
	defaultKubeBenchImage = "docker.io/aquasec/kube-bench:v0.15.6@sha256:861900910eec45b54a97e4a2af81b16fae7203d768f7f8e7de3b7456807870f5"
	// defaultJobTargets are the sections worth running in-cluster: the ones that read a node's
	// own filesystem and cannot be answered any other way. `policies` is deliberately absent —
	// the read-only scanner already covers it without creating anything.
	defaultJobTargets = "master,node,etcd,controlplane"
	defaultJobTimeout = 5 * time.Minute
)

// Scan creates the Job, waits for it, collects its output, and removes it.
func (s kubeBenchJobScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	if infra, ok := target.(plugin.InfraTarget); ok {
		// The Job reads a node's filesystem, which has no namespace. Honouring a scope is not
		// merely unimplemented here — it is meaningless, and silently ignoring it would report
		// node-wide findings against a component that asked for three namespaces.
		if err := refuseNamespaceScope(kubeBenchJobScannerName, infra.Namespaces); err != nil {
			return sarif.Report{}, err
		}
	}
	if _, ok := target.(plugin.InfraTarget); !ok {
		return sarif.Report{}, fmt.Errorf("%s: unsupported target %T (want infrastructure)",
			kubeBenchJobScannerName, target)
	}
	kubeCtx := kubeContext(target, cfg)
	client, err := s.client(kubeCtx)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", kubeBenchJobScannerName, err)
	}

	namespace := stringSetting(cfg, namespaceKey, defaultJobNamespace)
	job := s.buildJob(cfg)

	created, err := client.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: create job in %q: %w", kubeBenchJobScannerName, namespace, err)
	}

	// Cleanup runs on every path, including a cancelled scan, and with its own context: the
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
		return sarif.Report{}, fmt.Errorf("%s: %w", kubeBenchJobScannerName, err)
	}

	out, err := s.logs(ctx, client, namespace, created.Name)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("%s: %w", kubeBenchJobScannerName, err)
	}
	// This scanner audits the node types a managed platform runs, so what the descriptor says
	// about who operates the cluster decides whether its findings are the team's to act on.
	providerOperated := false
	if infra, ok := target.(plugin.InfraTarget); ok {
		providerOperated = infra.ProviderOperated
	}
	return parseKubeBenchOperated(out, kubeBenchJobScannerName, clusterLabel(kubeCtx), providerOperated)
}

// buildJob renders the Job, following kube-bench's own manifest: host PID so it can see the
// control-plane processes, and read-only host mounts for the files the benchmark inspects.
func (s kubeBenchJobScanner) buildJob(cfg plugin.Config) *batchv1.Job {
	targets := stringSetting(cfg, targetsKey, defaultJobTargets)
	args := []string{"run", "--json", "--targets", targets}
	if benchmark := stringSetting(cfg, benchmarkKey, ""); benchmark != "" {
		args = append(args, "--benchmark", benchmark)
	}

	// A named Job rather than GenerateName so the log lookup and the cleanup have something to
	// hold onto even if the create response is lost.
	name := fmt.Sprintf("draugr-kube-bench-%d", s.now().UTC().Unix())

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
					NodeSelector:  parseSelector(stringSetting(cfg, nodeSelectorKey, "")),
					// Control-plane nodes are tainted, and their configuration is most of what
					// these sections check. Without tolerating that taint the Job is unschedulable
					// exactly where it is most useful.
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					Containers: []corev1.Container{{
						Name:         "kube-bench",
						Image:        stringSetting(cfg, imageKey, defaultKubeBenchImage),
						Command:      []string{"kube-bench"},
						Args:         args,
						VolumeMounts: hostMounts(),
					}},
					Volumes: hostVolumes(),
				},
			},
		},
	}
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

func hostMounts() []corev1.VolumeMount {
	mounts := make([]corev1.VolumeMount, 0, len(hostPaths))
	for _, p := range hostPaths {
		at := p.path
		if p.name == "usr-bin" {
			at = usrBinMountPath
		}
		mounts = append(mounts, corev1.VolumeMount{Name: p.name, MountPath: at, ReadOnly: true})
	}
	return mounts
}

func hostVolumes() []corev1.Volume {
	vols := make([]corev1.Volume, 0, len(hostPaths))
	for _, p := range hostPaths {
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
// alive and re-establish, and the failure mode of a dropped watch is hanging until the timeout —
// which is the one outcome that leaves a Job running in someone's cluster for longer than it has
// to.
func waitForJob(ctx context.Context, client kubernetes.Interface, namespace, name string) error {
	ticker := time.NewTicker(jobPollInterval)
	defer ticker.Stop()
	for {
		// Checked before the request, not only in the select below. Both cases of that select can
		// be ready at once, and Go picks between them at random — so half the time the loop went
		// round and asked the API with an expired context, which client-go refuses inside its rate
		// limiter. That surfaced as "client rate limiter Wait returned an error: context deadline
		// exceeded", a message about our own client, in place of the one below that says what to do.
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
			// kube-bench exits non-zero when checks fail, which is a result rather than an
			// error — but with backoffLimit 0 a genuine crash looks the same from here, so the
			// logs are read either way and the parse decides.
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
		base += " — " + state
	}
	return fmt.Errorf("%s: %w. The Job has been removed. %s", base, cause, advice)
}

// podDiagnosis describes what the Job's pod was doing, and what would actually help.
//
// Three outcomes, and they need three different answers. No pod means nothing scheduled it. A
// warning from the cluster means the pod was refused, and no amount of waiting changes that. Only
// a pod quietly working — pulling an image, most often — is a case where a longer timeout is the
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
	return newest.Reason + " — " + strings.TrimSpace(newest.Message)
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
