package scanners

import (
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// The image scanner names the metadata address where an allowlist is written, the scanners that
// read a checkout do not reach it, and it stays out of what a run refreshes.
func TestOnlyTheTrivyImageScannerNamesTheMetadataAddress(t *testing.T) {
	const address = "169.254.169.254"
	names := func(data []plugin.DataSource) (hosts []string) {
		for _, d := range data {
			hosts = append(hosts, d.Hosts...)
		}
		return hosts
	}
	if !slices.Contains(names(NewTrivy().Info().Data), address) {
		t.Errorf("trivy declares %v, want the metadata address", NewTrivy().Info().Data)
	}
	if slices.Contains(names(NewTrivyFS().Info().Data), address) {
		t.Errorf("trivy-fs declares the metadata address, and reads a checkout")
	}
	for _, d := range trivyImageData {
		if slices.Contains(d.Hosts, address) && !d.PerScan {
			t.Error("the metadata address has no copy to warm, and is not marked per scan")
		}
	}
}
