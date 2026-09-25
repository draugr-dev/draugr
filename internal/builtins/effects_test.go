package builtins

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// TestEveryHostScannerDeclaresAnEffect holds scanners of a host to saying what they do with it.
//
// A repository or an image is an artifact, and reading one is what a scanner does by default. A
// host is not: there is nothing to read without contacting the host itself or asking somebody else
// about it, so a host scanner has at least one effect by construction. One declaring none reads,
// in `draugr controls`, in the report and in the approval the MCP server asks for, as a scanner
// that touches nothing, which is the understatement the Effects contract rules out.
func TestEveryHostScannerDeclaresAnEffect(t *testing.T) {
	for _, s := range Registry().Scanners() {
		info := s.Info()
		if !slices.Contains(info.TargetKinds, plugin.TargetHost) {
			continue
		}
		if !slices.ContainsFunc(info.Effects, func(e plugin.Effect) bool {
			return e.Kind == plugin.EffectNetwork || e.Kind == plugin.EffectDisclosure
		}) {
			t.Errorf("%s scans a host and declares neither network (traffic to the host) nor "+
				"disclosure (the host named to a third party)", info.Name)
		}
	}
}
