package scanners

// platformBenchmark is the benchmark kube-bench 0.16.0 selects for a distribution and its
// Kubernetes version (major.minor), or "" where it selects none. It is kube-bench's own table,
// getPlatformBenchmarkVersion in its cmd/util.go, kept here because kube-bench's detection of the
// platform cannot be relied on from outside the cluster.
//
// kube-bench reads the platform from `kubectl version -o json`, taken with stderr, so a kubectl
// more than one minor version from the server prints a skew warning into the JSON, the parse
// fails, and kube-bench assumes Kubernetes 1.18 and audits cis-1.6. Draugr reads the version
// through its own client, so it names the benchmark rather than leaving kube-bench to find it.
//
// The table moves with kube-bench: TestThePlatformBenchmarksFollowThePinnedKubeBench fails when the
// pinned release changes, so the two are read together. verifyBenchmark still checks the result.
func platformBenchmark(platform, version string) string {
	switch platform {
	case "eks":
		switch version {
		case "1.15", "1.16", "1.17", "1.18", "1.19":
			return "eks-1.0.1"
		case "1.29", "1.30", "1.31":
			return "eks-1.7.0"
		case "1.32", "1.33", "1.34":
			return "eks-1.8.0"
		}
		return "eks-1.5.0"
	case "aks":
		switch version {
		case "1.19", "1.20", "1.21", "1.22", "1.23", "1.24":
			return "aks-1.0"
		case "1.29", "1.30", "1.31":
			return "aks-1.7"
		}
		return "aks-1.8"
	case "gke":
		switch version {
		case "1.15", "1.16", "1.17", "1.18", "1.19":
			return "gke-1.0"
		case "1.20", "1.21", "1.22", "1.23", "1.24", "1.25", "1.26", "1.27":
			return "gke-1.2.0"
		case "1.28", "1.29":
			return "gke-1.6.0"
		case "1.30":
			return "gke-1.8.0"
		}
		return "gke-1.9.0"
	case "k3s":
		switch version {
		case "1.22", "1.23":
			return "k3s-cis-1.23"
		case "1.24":
			return "k3s-cis-1.24"
		case "1.25":
			return "k3s-cis-1.7"
		case "1.26":
			return "k3s-cis-1.8"
		}
		return "k3s-cis-1.9"
	case "rancher":
		switch version {
		case "1.23":
			return "rke-cis-1.23"
		case "1.24":
			return "rke-cis-1.24"
		}
		return "rke-cis-1.7"
	case "rke2r":
		switch version {
		case "1.23":
			return "rke2-cis-1.23"
		case "1.24":
			return "rke2-cis-1.24"
		case "1.25":
			return "rke2-cis-1.7"
		case "1.26":
			return "rke2-cis-1.8"
		}
		return "rke2-cis-1.9"
	case "aliyun":
		return "ack-1.0"
	case "vmware":
		return "tkgi-1.2.53"
	}
	return ""
}

// platformBenchmarksFor is the kube-bench release platformBenchmark was read from.
const platformBenchmarksFor = "0.16.0"
