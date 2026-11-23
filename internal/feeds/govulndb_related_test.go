package feeds

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/exploit"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A record's aliases are the same vulnerability in other databases; its related ids are other
// vulnerabilities. Only aliases are read, so a CVE a record lists only as related gives a finding no
// CVE, and nothing can be joined or matched on it. The record listing the CVE as an alias does.
func TestOnlyARecordsAliasesGiveAFindingItsCVE(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "index"), 0o750); err != nil {
		t.Fatal(err)
	}
	vulns := `[
		{"id":"GO-2026-7001","aliases":["GHSA-3c6w-j9xm-8h2h"],"related":["CVE-2026-107833"]},
		{"id":"GO-2026-7002","aliases":["GHSA-9xq2-qq5v-7r4m","CVE-2026-107900"]}
	]`
	if err := os.WriteFile(filepath.Join(dir, "index", "vulns.json"), []byte(vulns), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := GoVulnAliases(dir)
	if err != nil {
		t.Fatal(err)
	}
	db := exploit.NewAdvisories(exploit.DatasetGoVulnDB, time.Now(), records)
	finding := func(ghsa string) sarif.Result {
		return sarif.Result{RuleID: ghsa, Package: &sarif.Package{Name: "github.com/corazawaf/coraza/v3", Ecosystem: "gomod"}}
	}
	if l := db.Lookup(finding("GHSA-3c6w-j9xm-8h2h")); l != nil {
		t.Errorf("a CVE listed only as related was given to the finding: %+v", l)
	}
	if l := db.Lookup(finding("GHSA-9xq2-qq5v-7r4m")); l == nil || len(l.CVEs) != 1 || l.CVEs[0] != "CVE-2026-107900" {
		t.Errorf("lookup = %+v, want the CVE its record lists as an alias", l)
	}
}
