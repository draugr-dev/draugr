package scanners

// The CIS Kubernetes Benchmark's policies section, as a catalogue rather than a set of
// implementations.
//
// A scanner that evaluates some of a benchmark and stays quiet about the rest reports a clean
// result for checks it never ran, which is the failure this whole control exists to avoid. So
// the section is listed in full and every entry is answered: the ones this scanner can decide
// get a verdict, and the ones it cannot are reported as needing a human — the same answer
// kube-bench gives them, since CIS marks the entire section manual.
//
// That makes coverage additive rather than a trade. Moving a check from manual to decided is a
// strictly better answer for that check and changes nothing about the others.

// cisPolicyCheck is one check in the benchmark's policies section.
type cisPolicyCheck struct {
	// ID is the CIS check number, e.g. "5.1.1". It becomes the rule id, so an exclusion written
	// against the kube-bench scanner keeps working here.
	ID string
	// Title is the benchmark's own wording for the check.
	Title string
	// Remediation is what to do about a failure, kept short enough to read in a report.
	Remediation string
}

// cisPolicies is the policies section of cis-1.12.
//
// Pinned to a benchmark version deliberately: the section is renumbered between revisions, and a
// catalogue that silently tracked "whatever the latest is" would change the meaning of a rule id
// underneath an exclusion someone wrote. TestCISCatalogueMatchesKubeBench (integration) diffs
// this against kube-bench's own config so a revision cannot pass unnoticed.
var cisPolicies = []cisPolicyCheck{
	{"5.1.1", "Ensure that the cluster-admin role is only used where required", "Remove cluster-admin bindings and grant a role scoped to what the subject actually needs."},
	{"5.1.2", "Minimize access to secrets", "Remove get, list and watch on secrets from roles that do not require them."},
	{"5.1.3", "Minimize wildcard use in Roles and ClusterRoles", "Replace wildcards in apiGroups, resources and verbs with the specific values needed."},
	{"5.1.4", "Minimize access to create pods", "Remove create on pods from roles that do not require it."},
	{"5.1.5", "Ensure that default service accounts are not actively used", "Set automountServiceAccountToken: false on every default service account, and give workloads their own."},
	{"5.1.6", "Ensure that Service Account Tokens are only mounted where necessary", "Set automountServiceAccountToken: false on service accounts and pods that do not call the API."},
	{"5.1.7", "Avoid use of system:masters group", "Remove system:masters from certificates and bindings; it bypasses authorization entirely."},
	{"5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster", "Remove bind, impersonate and escalate from roles that do not require them."},
	{"5.1.9", "Minimize access to create persistent volumes", "Remove create on persistentvolumes from roles that do not require it."},
	{"5.1.10", "Minimize access to the proxy sub-resource of nodes", "Remove access to nodes/proxy from roles that do not require it."},
	{"5.1.11", "Minimize access to the approval sub-resource of certificatesigningrequests objects", "Remove access to certificatesigningrequests/approval from roles that do not require it."},
	{"5.1.12", "Minimize access to webhook configuration objects", "Remove access to validatingwebhookconfigurations and mutatingwebhookconfigurations from roles that do not require it."},
	{"5.1.13", "Minimize access to the service account token creation", "Remove create on serviceaccounts/token from roles that do not require it."},

	{"5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place", "Enable Pod Security Admission or an equivalent admission controller."},
	{"5.2.2", "Minimize the admission of privileged containers", "Reject pods that set securityContext.privileged: true."},
	{"5.2.3", "Minimize the admission of containers wishing to share the host process ID namespace", "Reject pods that set hostPID: true."},
	{"5.2.4", "Minimize the admission of containers wishing to share the host IPC namespace", "Reject pods that set hostIPC: true."},
	{"5.2.5", "Minimize the admission of containers wishing to share the host network namespace", "Reject pods that set hostNetwork: true."},
	{"5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation", "Reject pods that set allowPrivilegeEscalation: true."},
	{"5.2.7", "Minimize the admission of root containers", "Require runAsNonRoot, or a runAsUser greater than zero."},
	{"5.2.8", "Minimize the admission of containers with the NET_RAW capability", "Drop NET_RAW, or drop ALL capabilities and add back only what is needed."},
	{"5.2.9", "Minimize the admission of containers with capabilities assigned", "Drop ALL capabilities and add back only those the workload requires."},
	{"5.2.10", "Minimize the admission of Windows HostProcess containers", "Reject pods that set windowsOptions.hostProcess: true."},
	{"5.2.11", "Minimize the admission of HostPath volumes", "Replace hostPath volumes with a volume type that does not expose the node filesystem."},
	{"5.2.12", "Minimize the admission of containers which use HostPorts", "Remove hostPort from container ports and route through a Service."},

	{"5.3.1", "Ensure that the CNI in use supports NetworkPolicies", "Use a CNI plugin that implements NetworkPolicy."},
	{"5.3.2", "Ensure that all Namespaces have NetworkPolicies defined", "Add a default-deny NetworkPolicy to every namespace and allow only required traffic."},

	{"5.4.1", "Prefer using Secrets as files over Secrets as environment variables", "Mount secrets as files; environment variables are readable from the process listing and crash dumps."},
	{"5.4.2", "Consider external secret storage", "Hold secrets in a dedicated secret manager rather than in the cluster."},

	{"5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller", "Enable an admission controller that verifies image provenance."},

	{"5.6.1", "Create administrative boundaries between resources using namespaces", "Separate workloads into namespaces rather than sharing one."},
	{"5.6.2", "Ensure that the seccomp profile is set to docker/default in your Pod definitions", "Set seccompProfile.type to RuntimeDefault."},
	{"5.6.3", "Apply SecurityContext to your Pods and Containers", "Set a securityContext on every pod and container."},
	{"5.6.4", "The default namespace should not be used", "Move workloads out of the default namespace."},
}

// cisPolicyByID indexes the catalogue for lookup by rule id.
var cisPolicyByID = func() map[string]cisPolicyCheck {
	m := make(map[string]cisPolicyCheck, len(cisPolicies))
	for _, c := range cisPolicies {
		m[c.ID] = c
	}
	return m
}()
