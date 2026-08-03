package scanners

import (
	"errors"
	"fmt"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// NewTrivy returns a Scanner that runs Aqua Trivy against container images and returns
// its native SARIF output. It serves the "images" control.
func NewTrivy() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:         "trivy",
		Origin:       "aquasecurity",
		Binary:       "trivy",
		Controls:     []string{"images"},
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		Argv:         trivyArgv,
		Run:          execArgv,
		CacheVersion: sharedTrivyVersion.cacheVersion,
		Prewarm:      sharedTrivyDB.warm,
		Refine:       trivyImageLocations,
	})
}

// NewTrivyFS returns a Scanner that runs Trivy in filesystem mode over a checked-out
// repository to find dependency vulnerabilities (SCA). It serves the "sca" control.
// (License findings are not included in Trivy's SARIF output and are tracked separately.)
func NewTrivyFS() plugin.Scanner {
	s := newRepoScanner(
		plugin.ScannerInfo{
			Name:        "trivy-fs",
			Origin:      "aquasecurity",
			Binary:      "trivy",
			Controls:    []string{"sca"},
			TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
		},
		trivyFSArgs,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	s.prewarm = sharedTrivyDB.warm
	return s
}

// trivyFSArgs builds `trivy fs --quiet --scanners vuln --format sarif <dir>`.
func trivyFSArgs(dir string, _ plugin.Config) []string {
	return offlineTrivyArgs([]string{"trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "sarif", dir})
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
func trivyArgv(target plugin.Target, _ plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("trivy: unsupported target %T (want image)", target)
	}
	ref := img.PinnedRef()
	if ref == "" {
		return nil, errors.New("trivy: image target has neither ref nor digest")
	}
	return offlineTrivyArgs([]string{"trivy", "image", "--quiet", "--format", "sarif", ref}), nil
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
