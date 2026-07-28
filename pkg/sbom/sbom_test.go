package sbom

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestDefaultFormatIsAValidFormat(t *testing.T) {
	// The default is resolved from the empty string at generation time. If it ever stopped
	// being a format the Saga accepts, a Saga saying only `sbom: {enabled: true}` would fail —
	// the one configuration most people will write.
	if !DefaultFormat.Valid() {
		t.Errorf("DefaultFormat %q is not a valid saga.SBOMFormat", DefaultFormat)
	}
	if saga.SBOMFormat("").Valid() {
		t.Error("the empty format is not itself valid; callers resolve it to DefaultFormat")
	}
}
