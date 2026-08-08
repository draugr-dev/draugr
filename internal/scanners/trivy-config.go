package scanners

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// trivyConfigCheckSchema is the JSON Schema for trivy-config's Saga config
// (controllers.iac.trivyConfig). additionalProperties:false rejects mistyped keys.
//
// Custom Rego is the main reason teams pick this over a fixed checklist: the misconfigurations
// that matter to an organisation are usually the ones nobody else has written a rule for. Both
// options add checks; neither removes findings.
const trivyConfigCheckSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "checks": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Paths to Rego check files, or directories of them, relative to where Draugr runs. Adds your own misconfiguration rules to Trivy's built-in ones."
    },
    "namespaces": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Rego namespaces to evaluate, e.g. [\"user\"]. Needed when your checks declare a namespace Trivy does not scan by default."
    }
  }
}`

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
			ConfigSchema: json.RawMessage(trivyConfigCheckSchema),
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
func trivyConfigArgs(dir string, cfg plugin.Config) []string {
	argv := []string{"trivy", "config", "--quiet", "--format", "sarif"}
	for _, path := range stringList(cfg, "checks") {
		if abs := absPath(path); abs != "" {
			argv = append(argv, "--config-check", abs)
		}
	}
	if v := commaList(cfg, "namespaces"); v != "" {
		argv = append(argv, "--check-namespaces", v)
	}
	return offlineTrivyArgs(append(argv, dir))
}
