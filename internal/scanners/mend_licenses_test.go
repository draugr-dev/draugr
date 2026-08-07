package scanners

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/mendapi"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func lib(name, licName, spdx string) mendapi.InventoryLibrary {
	return mendapi.InventoryLibrary{
		Name:     name,
		Licenses: []mendapi.InventoryLicense{{Name: licName, SPDXName: spdx}},
	}
}

func TestMendLicensesInfo(t *testing.T) {
	info := NewMendLicenses().Info()
	if info.Name != mendLicensesScannerName || len(info.Controls) != 1 || info.Controls[0] != "licenses" {
		t.Errorf("info = %+v", info)
	}
	if len(info.Effects) != 2 {
		t.Errorf("it makes the same upload as mend-sca, so it declares the same effects: %+v", info.Effects)
	}
}

// Where Mend gives an SPDX name it is used, so policies already written keep matching.
func TestMendLicenseUsesSPDXWhenGiven(t *testing.T) {
	rep := mendLicenseReport(context.Background(),
		[]mendapi.InventoryLibrary{lib("requests", "Apache 2.0", "Apache-2.0")},
		plugin.Config{denyKey: []any{"Apache-2.0"}})
	if len(rep.Results) != 1 {
		t.Fatalf("results = %d", len(rep.Results))
	}
	if got := rep.Results[0].RuleID; got != "license/Apache-2.0/requests" {
		t.Errorf("ruleID = %q", got)
	}
}

// Where it does not, the finding carries Mend's own name rather than an invented SPDX id — a
// mapping would be consulted exactly where there is least evidence, and a wrong entry applies a
// policy to the wrong licence.
func TestMendLicenseKeepsMendsNameWhenNoSPDX(t *testing.T) {
	rep := mendLicenseReport(context.Background(),
		[]mendapi.InventoryLibrary{lib("Jinja2", "BSD 3", "")},
		plugin.Config{denyKey: []any{"BSD 3"}})
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "license/BSD 3/Jinja2" {
		t.Fatalf("results = %+v", rep.Results)
	}
}

// The failure this scanner must not have: a policy in SPDX silently covering nothing.
func TestMendLicenseSPDXPolicyDoesNotMatchAMendName(t *testing.T) {
	rep := mendLicenseReport(context.Background(),
		[]mendapi.InventoryLibrary{lib("Jinja2", "BSD 3", "")},
		plugin.Config{denyKey: []any{"BSD-3-Clause"}})
	if len(rep.Results) != 0 {
		t.Errorf("an SPDX rule matched a non-SPDX name — the mapping is back: %+v", rep.Results)
	}
	// The warning is what makes that visible; it is asserted through mendLicenseID below and by
	// the identifier being reported unchanged, which is what an operator writes a rule against.
}

func TestMendLicenseIDReportsWhetherItIsSPDX(t *testing.T) {
	if id, ok := mendLicenseID(mendapi.InventoryLicense{Name: "BSD 3", SPDXName: "BSD-3-Clause"}); id != "BSD-3-Clause" || !ok {
		t.Errorf("id=%q spdx=%v", id, ok)
	}
	if id, ok := mendLicenseID(mendapi.InventoryLicense{Name: "BSD 3"}); id != "BSD 3" || ok {
		t.Errorf("id=%q spdx=%v", id, ok)
	}
}

// Mend carries no licence category, so this scanner reports what the policy names and nothing
// else. Without a policy it is silent — stated in the doc so it is not discovered.
func TestMendLicenseReportsOnlyWhatThePolicyNames(t *testing.T) {
	libs := []mendapi.InventoryLibrary{lib("a", "MIT", "MIT"), lib("b", "GPL-3.0-only", "GPL-3.0-only")}
	if rep := mendLicenseReport(context.Background(), libs, plugin.Config{}); len(rep.Results) != 0 {
		t.Errorf("no policy should mean no findings, got %+v", rep.Results)
	}
	rep := mendLicenseReport(context.Background(), libs, plugin.Config{warnKey: []any{"GPL-3.0-only"}})
	if len(rep.Results) != 1 || rep.Results[0].Level != sarif.LevelWarning {
		t.Errorf("results = %+v", rep.Results)
	}
}

func TestMendLicenseLevels(t *testing.T) {
	deny, warn := []string{"GPL-3.0-only"}, []string{"MPL-2.0"}
	if l, _, ok := mendLicenseLevel("GPL-3.0-only", deny, warn); !ok || l != sarif.LevelError {
		t.Errorf("deny = %v %v", l, ok)
	}
	if l, _, ok := mendLicenseLevel("MPL-2.0", deny, warn); !ok || l != sarif.LevelWarning {
		t.Errorf("warn = %v %v", l, ok)
	}
	if _, _, ok := mendLicenseLevel("MIT", deny, warn); ok {
		t.Error("an unlisted licence is inventory, not a finding")
	}
}

func TestMendPackageNamePrefersCoordinates(t *testing.T) {
	if got := mendPackageName(mendapi.InventoryLibrary{GroupID: "org.acme", ArtifactID: "api"}); got != "org.acme:api" {
		t.Errorf("got %q", got)
	}
	if got := mendPackageName(mendapi.InventoryLibrary{Filename: "x.whl"}); got != "x.whl" {
		t.Errorf("got %q", got)
	}
}

func TestMendLicensesRejectsANonRepositoryTarget(t *testing.T) {
	_, err := NewMendLicenses().Scan(context.Background(), plugin.ImageTarget{Ref: "alpine:3"}, plugin.Config{})
	if err == nil || !strings.Contains(err.Error(), "repositories") {
		t.Errorf("err = %v", err)
	}
}

// The upload is shared, so a second control asking for the same repository and project must reuse
// it — an upload replaces a project's inventory, so two would race.
func TestSharedUploadRunsOncePerRepositoryAndProject(t *testing.T) {
	sharedMendUploads.reset()
	calls := 0
	fn := func(context.Context) (uaSummary, error) {
		calls++
		return uaSummary{resolved: 3, sawSummary: true}, nil
	}
	for i := 0; i < 3; i++ {
		if _, err := sharedMendUploads.upload(context.Background(), "repo→prod/proj", fn); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("uploaded %d times for one repository and project", calls)
	}
	if _, err := sharedMendUploads.upload(context.Background(), "other→prod/proj", fn); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("a different repository should upload again, calls = %d", calls)
	}
	sharedMendUploads.reset()
}
