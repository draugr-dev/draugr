package scanners

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// trivyConfigSchema is the JSON Schema for the two vulnerability scanners' Saga config
// (controllers.images.trivy and controllers.sca.trivyFs). additionalProperties:false rejects
// mistyped keys.
//
// Neither option filters findings. `--severity` and `--ignorefile` are the two Trivy flags people
// reach for first and are deliberately absent: both drop findings inside the tool, where Draugr
// cannot mark them suppressed or record who accepted them. `exclusions` in the Saga does that and
// keeps the evidence; the gate thresholds decide what fails.
const trivyConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "pkgTypes": {
      "type": "array",
      "items": { "type": "string", "enum": ["os", "library"] },
      "description": "Which package types to analyse. Defaults to both. Narrow it to [\"library\"] when the OS layer is somebody else's responsibility — a base image maintained by a platform team — so the report covers what this component controls."
    },
    "dbRepository": {
      "type": "array",
      "items": { "type": "string" },
      "description": "OCI repositories to pull the vulnerability database from, in priority order. Point it at an internal mirror where the runner cannot reach a public registry."
    }
  }
}`

// NewTrivy returns a Scanner that runs Aqua Trivy against container images and returns
// its native SARIF output. It serves the "images" control.
func NewTrivy() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:         "trivy",
		Origin:       "aquasecurity",
		Binary:       "trivy",
		Controls:     []string{"images"},
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		ConfigSchema: json.RawMessage(trivyConfigSchema),
		Argv:         trivyArgv,
		Run:          retryingRun("trivy", execArgv),
		CacheVersion: sharedTrivyVersion.cacheVersion,
		Prewarm:      sharedTrivyDB.warm,
		Refine:       trivyImageLocations,
	})
}

// NewTrivyFS returns a Scanner that runs Trivy in filesystem mode over a checked-out
// repository to find dependency vulnerabilities (SCA). It serves the "sca" control.
// (License findings are not included in Trivy's SARIF output and are tracked separately.)
func NewTrivyFS() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         "trivy-fs",
			Origin:       "aquasecurity",
			Binary:       "trivy",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(trivyConfigSchema),
		},
		trivyFSArgs,
		parseTrivyVulns,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	s.prewarm = sharedTrivyDB.warm
	s.run = retryingRunInDir("trivy", s.run)
	return s
}

// trivyFSArgs builds `trivy fs --quiet --scanners vuln --format json <dir>`.
//
// JSON rather than SARIF because the SARIF says which package only in prose. See
// trivy_vuln_json.go for what that costs and what it buys.
func trivyFSArgs(dir string, cfg plugin.Config) []string {
	argv := []string{"trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "json"}
	return offlineTrivyArgs(append(trivyOptions(argv, cfg), dir))
}

// trivyOptions appends the descriptor's options to a Trivy command line, before its positional
// target. Shared by the image and filesystem scanners: the same two options mean the same thing
// to both, and a database mirror that is right for one is right for the other.
func trivyOptions(argv []string, cfg plugin.Config) []string {
	if v := commaList(cfg, "pkgTypes"); v != "" {
		argv = append(argv, "--pkg-types", v)
	}
	if v := commaList(cfg, "dbRepository"); v != "" {
		argv = append(argv, "--db-repository", v)
	}
	return argv
}

// offlineTrivyArgs adds --skip-db-update when this process must make no network calls.
//
// Skipping the prewarm is not enough on its own: Trivy refreshes its database at scan time too,
// so without this an offline run still reaches out — several times, once per job. With it, Trivy
// uses its local cache and says plainly when there isn't one, which is a better message than
// anything Draugr could write on its behalf.
func offlineTrivyArgs(argv []string) []string {
	if !netpolicy.Offline() {
		return argv
	}
	// Before the positional argument: Trivy takes flags ahead of the target.
	out := make([]string, 0, len(argv)+2)
	out = append(out, argv[:len(argv)-1]...)
	out = append(out, "--skip-db-update", "--skip-java-db-update")
	return append(out, argv[len(argv)-1])
}

// trivyArgv builds `trivy image --quiet --format sarif <ref>` for an image target.
func trivyArgv(target plugin.Target, cfg plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("trivy: unsupported target %T (want image)", target)
	}
	ref := img.PinnedRef()
	if ref == "" {
		return nil, errors.New("trivy: image target has neither ref nor digest")
	}
	argv := []string{"trivy", "image", "--quiet", "--format", "sarif"}
	return offlineTrivyArgs(append(trivyOptions(argv, cfg), ref)), nil
}

// trivyImageLocations restates an image finding's location as the image that was scanned.
//
// Trivy reports one at "library/python", line 1: the registry path with the tag dropped, and a
// line number that means nothing for a container image. Three things go wrong with that. A
// component shipping two images produces findings you can't tell apart. The console renders the
// pair as "library/python:1", which reads like a file. And because the tag is what made the
// string look like an image rather than a path, the SARIF writer took it for a repo-relative
// path and declared it against %SRCROOT%, so a viewer would go looking for it in the workspace.
//
// The reference we pulled is the honest answer to "where is this", and we already have it.
func trivyImageLocations(target plugin.Target, report sarif.Report) sarif.Report {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return report
	}
	ref := img.PinnedRef()
	if ref == "" {
		return report
	}
	for i := range report.Results {
		report.Results[i].Location = sarif.Location{URI: ref}
	}
	return report
}
