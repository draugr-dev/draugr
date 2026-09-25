package scanners

import (
	"context"
	"encoding/json"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// trivyConfigCheckSchema is the JSON Schema for trivy-config's Saga config
// (controllers.iac.trivyConfig). additionalProperties:false rejects mistyped keys.
//
// Custom Rego is the main reason teams pick this over a fixed checklist: the misconfigurations
// that matter to an organization are usually the ones nobody else has written a rule for. Both
// options add checks; neither removes findings. The iac controller derives namespaces from the
// checks' package lines when a descriptor names none, because Trivy evaluates no custom namespace
// unless told to.
const trivyConfigCheckSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "checks": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Paths to Rego check files, or directories of them, relative to where Draugr runs. Adds your own misconfiguration rules to Trivy's built-in ones. Without namespaces, every check must declare a package, and the package's first name is the namespace it runs under."
    },
    "namespaces": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Top-level Rego package names whose checks Trivy evaluates, e.g. [\"user\"] for package user.tags. Unset, Draugr derives the list from the package lines in checks; set, only the listed namespaces run."
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
			Data:         trivyChecksData,
			Binary:       "trivy",
			Controls:     []string{"iac"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(trivyConfigCheckSchema),
		},
		trivyConfigArgs,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	// The checks bundle and nothing else: misconfiguration scanning never reads the vulnerability
	// database, so warming it here would download one for a run that may not use it.
	s.prewarm = func(ctx context.Context) error { return sharedTrivyChecks.warm(ctx) }
	s.run = trivyConfigRun(retryingRunInDir("trivy", s.run))
	return s
}

// trivyConfigArgs builds the misconfiguration scan. Trivy exits 0 even when misconfigurations are
// found (findings live in the report, not the exit code; the iac controller judges severity).
//
// On a Trivy with --show-suppressed it is `trivy fs --scanners misconfig --format json
// --show-suppressed <dir>`, the same checks plus the list of what `.trivyignore` excluded, which
// trivyConfigRun converts to SARIF. On an older one it is `trivy config --format sarif <dir>`, and
// an exclusion leaves no record.
func trivyConfigArgs(dir string, cfg plugin.Config) []string {
	argv := []string{"trivy", "config", "--quiet", "--format", "sarif"}
	if sharedTrivyVersion.showsSuppressed() {
		argv = []string{"trivy", "fs", "--quiet", "--scanners", "misconfig", "--format", "json", trivyConfigExclusionsArg}
	}
	for _, path := range stringList(cfg, "checks") {
		if abs := absPath(path); abs != "" {
			argv = append(argv, "--config-check", abs)
		}
	}
	if v := commaList(cfg, "namespaces"); v != "" {
		argv = append(argv, "--check-namespaces", v)
	}
	// Offline, the checks built into the binary instead of an update from the registry.
	// --skip-db-update belongs to the vulnerability scanners and `trivy config` refuses it.
	if netpolicy.Offline() {
		argv = append(argv, "--skip-check-update")
	}
	return append(argv, dir)
}
