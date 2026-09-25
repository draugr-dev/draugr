package scanners

import "github.com/draugr-dev/draugr/pkg/plugin"

// The reference data each tool reads, declared once and shared by the scanners that run the same
// tool. Four Trivy-backed scanners pull one database; two Grype-backed scanners pull another.
//
// Hosts are what somebody puts in an egress allowlist, which is the common case rather than a
// disconnected machine: a CI runner that blocks outbound by default needs the list, and `draugr
// doctor` is where they will look for it. Where a tool can be pointed at a copy already on disk,
// Local says so in the tool's own spelling, because that is what goes in the pipeline.
var (
	// Trivy tries the mirror first and falls back to GitHub's registry; both are defaults of the
	// tool rather than Draugr's choice, and `config.controls.<c>.trivy.dbRepository` replaces them
	// with an internal one.
	trivyData = []plugin.DataSource{{
		Name:  "vulnerability database",
		Hosts: []string{"mirror.gcr.io", "ghcr.io"},
		Local: "--skip-db-update, which Draugr passes when offline",
	}}
	// Misconfiguration checks, published as an OCI bundle. Trivy falls back to the checks compiled
	// into the binary when it cannot fetch one.
	trivyChecksData = []plugin.DataSource{{
		Name:  "checks bundle",
		Hosts: []string{"mirror.gcr.io"},
		Local: "--skip-check-update, which Draugr passes when offline, to use the checks built into Trivy",
	}}
	grypeData = []plugin.DataSource{{
		Name:  "vulnerability database",
		Hosts: []string{"grype.anchore.io"},
		Local: "GRYPE_DB_AUTO_UPDATE=false with a populated cache",
	}}
	nucleiData = []plugin.DataSource{{
		Name:  "template set",
		Hosts: []string{"github.com"},
		Local: "a populated template directory; nuclei reads it without asking",
	}}
	retireJSData = []plugin.DataSource{{
		Name:  "advisory database",
		Hosts: []string{"raw.githubusercontent.com"},
		Local: "--jsrepo <file>, which Draugr passes when offline",
	}}
	// The Go vulnerability database has a local form that is not safe to pass unchecked: an empty
	// or stale directory behind `-db file://` makes govulncheck report no vulnerabilities and exit
	// 0. Draugr passes one only after checking its age and index.
	govulncheckData = []plugin.DataSource{{
		Name:    "vulnerability database",
		Hosts:   []string{"vuln.go.dev"},
		Local:   "draugr feeds update govulndb, checked before each scan and passed as -db file://<dir>",
		PerScan: true,
	}}
	semgrepData = []plugin.DataSource{{
		Name:    "rule pack",
		Hosts:   []string{"semgrep.dev"},
		Local:   "--config <dir> against rules on disk, set through the scanner's own config",
		PerScan: true,
	}}
)
