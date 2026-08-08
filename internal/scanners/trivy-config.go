package scanners

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// NewTrivyConfig returns a Scanner that runs Trivy's misconfiguration scanner over a
// checked-out repository to find insecure Infrastructure-as-Code (Terraform, Kubernetes
// manifests, Dockerfiles, Helm, …). It serves the "iac" control.
func NewTrivyConfig() plugin.Scanner {
	s := newRepoScanner(
		plugin.ScannerInfo{
			Name:         "trivy-config",
			Origin:       "aquasecurity",
			Binary:       "trivy",
			Controls:     []string{"iac"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		trivyConfigArgs,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	s.prewarm = sharedTrivyDB.warm
	return s
}

// trivyConfigArgs builds `trivy config --quiet --format sarif <dir>`. Trivy exits 0 even
// when misconfigurations are found (findings live in the SARIF report, not the exit code;
// the iac controller judges severity).
func trivyConfigArgs(dir string, _ plugin.Config) []string {
	return offlineTrivyArgs([]string{"trivy", "config", "--quiet", "--format", "sarif", dir})
}
