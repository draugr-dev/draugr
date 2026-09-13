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
	// The Go vulnerability database has a local form and it is not safe to reach for blindly: an
	// empty or stale directory behind `-db file://` makes govulncheck report no vulnerabilities and
	// exit 0. Named here so the fact travels, and deliberately not wired.
	govulncheckData = []plugin.DataSource{{
		Name:    "vulnerability database",
		Hosts:   []string{"vuln.go.dev"},
		Local:   "-db file://<dir>, which reports clean rather than failing on an unusable copy",
		PerScan: true,
	}}
	semgrepData = []plugin.DataSource{{
		Name:    "rule pack",
		Hosts:   []string{"semgrep.dev"},
		Local:   "--config <dir> against rules on disk, set through the scanner's own config",
		PerScan: true,
	}}
)
