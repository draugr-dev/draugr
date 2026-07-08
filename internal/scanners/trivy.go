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
		Name:        "trivy",
		Controls:    []string{"images"},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage},
		Argv:        trivyArgv,
	})
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
