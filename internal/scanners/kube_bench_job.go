package scanners

import (
	"context"
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

// NewKubeBenchJob returns a Scanner that runs the CIS benchmark inside the cluster.
func NewKubeBenchJob() plugin.Scanner {
	return kubeBenchJobScanner{
		info: plugin.ScannerInfo{
			Name: kubeBenchJobScannerName,
			// No Binary: the work happens in the cluster, from an image.
			Controls:    []string{"infrastructure"},
			TargetKinds: []plugin.TargetKind{plugin.TargetInfra},
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
	// defaultKubeBenchImage is pinned rather than :latest. An unpinned image is a scan whose
	// result can change without anything in the descriptor changing, which is the opposite of
	// what a compliance report is for.
	defaultKubeBenchImage = "docker.io/aquasec/kube-bench:v0.15.6"
	// defaultJobTargets are the sections worth running in-cluster: the ones that read a node's
	// own filesystem and cannot be answered any other way. `policies` is deliberately absent —
	// the read-only scanner already covers it without creating anything.
	defaultJobTargets = "master,node,etcd,controlplane"
	defaultJobTimeout = 5 * time.Minute
)

// Scan creates the Job, waits for it, collects its output, and removes it.
func (s kubeBenchJobScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
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
	return parseKubeBench(out, kubeBenchJobScannerName, clusterLabel(kubeCtx))
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
			return fmt.Errorf("job %s/%s did not finish: %w — the Job has been removed; a "+
				"longer `timeout`, or a nodeSelector that matches a schedulable node, may help",
				namespace, name, ctx.Err())
		case <-ticker.C:
		}
	}
}

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
