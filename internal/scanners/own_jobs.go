package scanners

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// ownJob is a Job this process created, in the cluster a kube context reaches.
type ownJob struct{ kubeCtx, namespace, name string }

// ownJobs are the Jobs this process has created, so a scanner reading the cluster's pods can
// leave out the ones that are the scan's own.
//
// kube-bench-job's pod is privileged, mounts host paths and runs in whatever namespace it is
// given, and draugr-k8s-policies reads the cluster's pods while it runs. Read at the wrong moment,
// the scan reports its own pod as a finding about the cluster, and whether it does depends on
// timing.
//
// Keyed by the Job's name, which is registered before the Job is created, rather than by a label:
// any pod can carry a label, so a label anybody can set would be a way to keep a pod out of the
// policy checks. Entries are never removed, because the pod outlives its Job's deletion by however
// long the garbage collector takes.
var ownJobs = struct {
	sync.Mutex
	set map[ownJob]bool
}{set: map[ownJob]bool{}}

// registerOwnJob records a Job this process is about to create.
func registerOwnJob(kubeCtx, namespace, name string) {
	ownJobs.Lock()
	defer ownJobs.Unlock()
	ownJobs.set[ownJob{kubeCtx, namespace, name}] = true
}

// ownedByThisRun says a pod belongs to a Job this process created in the cluster kubeCtx reaches.
func ownedByThisRun(kubeCtx string, pod *corev1.Pod) bool {
	ownJobs.Lock()
	defer ownJobs.Unlock()
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "Job" && ref.APIVersion == "batch/v1" && ownJobs.set[ownJob{kubeCtx, pod.Namespace, ref.Name}] {
			return true
		}
	}
	return false
}
