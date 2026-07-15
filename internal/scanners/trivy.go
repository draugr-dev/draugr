package scanners

import (
	"errors"
	"fmt"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// NewTrivy returns a Scanner that runs Aqua Trivy against container images and returns
// its native SARIF output. It serves the "images" control.
func NewTrivy() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:         "trivy",
		Binary:       "trivy",
		Controls:     []string{"images"},
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		Argv:         trivyArgv,
		CacheVersion: sharedTrivyVersion.cacheVersion,
	})
}

// NewTrivyFS returns a Scanner that runs Trivy in filesystem mode over a checked-out
// repository to find dependency vulnerabilities (SCA). It serves the "sca" control.
// (License findings are not included in Trivy's SARIF output and are tracked separately.)
func NewTrivyFS() plugin.Scanner {
	s := newRepoScanner(
		plugin.ScannerInfo{
			Name:        "trivy-fs",
			Binary:      "trivy",
			Controls:    []string{"sca"},
			TargetKinds: []plugin.TargetKind{plugin.TargetRepository},
		},
		trivyFSArgs,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	return s
}

// trivyFSArgs builds `trivy fs --quiet --scanners vuln --format sarif <dir>`.
func trivyFSArgs(dir string, _ plugin.Config) []string {
	return []string{"trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "sarif", dir}
}

// trivyArgv builds `trivy image --quiet --format sarif <ref>` for an image target.
func trivyArgv(target plugin.Target, _ plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("trivy: unsupported target %T (want image)", target)
	}
	ref := img.Ref
	if ref == "" {
		ref = img.Digest
	}
	if ref == "" {
		return nil, errors.New("trivy: image target has neither ref nor digest")
	}
	return []string{"trivy", "image", "--quiet", "--format", "sarif", ref}, nil
}
