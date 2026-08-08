package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/mendapi"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// mendLicensesScannerName identifies the Mend scanner behind the "licenses" control.
const mendLicensesScannerName = "mend-licenses"

// mendLicensesScanner reports the licence of every dependency Mend resolved.
//
// The same upload as mend-sca, read differently: vulnerabilities come from the project's alerts,
// licences from its inventory. Both go through the shared upload, so a component scanned by both
// controls is sent once — which matters because an upload replaces a project's inventory rather
// than adding to it.
//
// It also means this control works with `sca` turned off, or served by Trivy. The upload belongs
// to neither scanner.
type mendLicensesScanner struct {
	info plugin.ScannerInfo
	run  func(ctx context.Context, dir string, argv, env []string) ([]byte, error)
	api  func(baseURL, userKey string) mendInventory
	env  func(string) string
}

// mendInventory is the part of the API client this scanner uses.
type mendInventory interface {
	Await(ctx context.Context, opts mendapi.AwaitOpts) ([]mendapi.Alert, error)
	Inventory(ctx context.Context, projectToken string) ([]mendapi.InventoryLibrary, error)
	ProjectByName(ctx context.Context, productToken, name string) (mendapi.Project, error)
}

// NewMendLicenses returns a Scanner for the "licenses" control backed by Mend.
func NewMendLicenses() plugin.Scanner {
	return mendLicensesScanner{
		info: plugin.ScannerInfo{
			Name:         mendLicensesScannerName,
			Origin:       "mend.io",
			Binary:       "mend",
			Controls:     []string{"licenses"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(mendLicensesConfigSchema),
			Effects: []plugin.Effect{
				{Kind: plugin.EffectDisclosure, Detail: "uploads this component's resolved " +
					"dependency inventory to Mend — names, versions, checksums, and the absolute " +
					"paths they were found at"},
				{Kind: plugin.EffectMutate, Detail: "creates or updates a project inside your " +
					"Mend product, which outlives the scan"},
			},
		},
		run: toolexec.RunWithEnv,
		api: func(baseURL, userKey string) mendInventory { return mendapi.New(baseURL, userKey) },
		env: os.Getenv,
	}
}

// Info describes the scanner.
func (s mendLicensesScanner) Info() plugin.ScannerInfo { return s.info }

// Scan reports the licence of every dependency in this repository.
func (s mendLicensesScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	repo, ok := target.(plugin.RepositoryTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("%s scans repositories, not a %s", mendLicensesScannerName, target.Kind())
	}
	settings, err := mendSettings(cfg, s.env)
	if err != nil {
		return sarif.Report{}, err
	}
	settings.project = mendProjectName(settings.project, repo.Source())

	tree, cleanup, err := git.Checkout(ctx, repo.URL, repo.Revision,
		git.Scope{Paths: repo.Paths, Ignore: repo.Ignore})
	if err != nil {
		return sarif.Report{}, fmt.Errorf("checkout %s: %w", repo.Source(), err)
	}
	defer cleanup()

	// The same upload mend-sca would make. Whichever control runs first performs it.
	uploader := mendSCAScanner{run: s.run, env: s.env}
	summary, err := sharedMendUploads.upload(ctx, mendUploadKey(repo, settings),
		func(ctx context.Context) (uaSummary, error) { return uploader.upload(ctx, tree.Dir, settings) })
	if err != nil {
		return sarif.Report{}, err
	}
	if err := summary.check(tree.Dir); err != nil {
		return sarif.Report{}, err
	}

	client := s.api(settings.url, settings.userKey)
	// Wait for the upload to be applied before reading the inventory, for the same reason the
	// alerts are waited for: an inventory read too early is answered honestly with nothing, and
	// nothing reads as a project with no dependencies rather than one not yet processed.
	if _, err := client.Await(ctx, mendapi.AwaitOpts{
		ProductToken:    settings.productToken,
		ProjectName:     settings.project,
		RequestToken:    summary.requestToken,
		ExpectLibraries: summary.resolved,
		Timeout:         settings.resultTimeout,
	}); err != nil {
		return sarif.Report{}, err
	}
	project, err := client.ProjectByName(ctx, settings.productToken, settings.project)
	if err != nil {
		return sarif.Report{}, err
	}
	libs, err := client.Inventory(ctx, project.Token)
	if err != nil {
		return sarif.Report{}, err
	}
	return mendLicenseReport(ctx, libs, cfg), nil
}

// mendLicenseReport turns an inventory into licence findings.
func mendLicenseReport(ctx context.Context, libs []mendapi.InventoryLibrary, cfg plugin.Config) sarif.Report {
	deny, warn := stringList(cfg, denyKey), stringList(cfg, warnKey)
	var rep sarif.Report
	unmapped := map[string]bool{}

	for _, lib := range libs {
		pkg := mendPackageName(lib)
		for _, lic := range lib.Licenses {
			id, isSPDX := mendLicenseID(lic)
			if !isSPDX && id != "" {
				unmapped[id] = true
			}
			level, why, matched := mendLicenseLevel(id, deny, warn)
			if !matched {
				continue
			}
			rep.Results = append(rep.Results, sarif.Result{
				Tool:     "Mend",
				RuleID:   licenseRuleID(id, pkg),
				Level:    level,
				Message:  fmt.Sprintf("%s is licensed %s. %s", pkg, id, why),
				Location: sarif.Location{URI: pkg},
			})
		}
	}
	warnUnmappedLicences(ctx, unmapped)
	return rep
}

// mendLicenseLevel decides how loudly to report a licence.
//
// Only what the policy names. Trivy also carries a category, so it can flag a copyleft licence a
// project never listed; Mend supplies none, so this scanner reports exactly the licences a
// descriptor asked about and nothing else. That is a real difference between the two scanners on
// one control, and the colocated doc says so — a project running only this one and expecting
// category-based flagging would get silence.
func mendLicenseLevel(id string, deny, warn []string) (sarif.Level, string, bool) {
	switch {
	case slices.Contains(deny, id):
		return sarif.LevelError, "Denied by this project's licence policy (config.controllers.licenses.deny).", true
	case slices.Contains(warn, id):
		return sarif.LevelWarning, "Flagged by this project's licence policy (config.controllers.licenses.warn).", true
	}
	return "", "", false
}

// mendLicenseID is the identifier a finding is keyed on, and whether it is really SPDX.
//
// Mend's own vocabulary is used when it offers no SPDX name — "BSD 3" rather than "BSD-3-Clause".
// Translating it was the first design and is the wrong one: a mapping table is consulted exactly
// where there is least evidence, and a wrong entry applies a policy to the *wrong* licence, which
// is worse than one applying to nothing. So the finding says what Mend said, and the operator is
// told that it did.
func mendLicenseID(lic mendapi.InventoryLicense) (id string, isSPDX bool) {
	if s := strings.TrimSpace(lic.SPDXName); s != "" {
		return s, true
	}
	return strings.TrimSpace(lic.Name), false
}

// warnUnmappedLicences tells the operator, once per scan, which identifiers this run produced.
//
// The failure being avoided is not that names differ from SPDX — it is a policy that silently
// covers less than it claims. Naming the strings that will actually appear turns that into a
// decision somebody makes with the facts, in the vocabulary their descriptor uses.
func warnUnmappedLicences(ctx context.Context, ids map[string]bool) {
	if len(ids) == 0 {
		return
	}
	names := make([]string, 0, len(ids))
	for id := range ids {
		names = append(names, `"`+id+`"`)
	}
	sort.Strings(names)
	slog.WarnContext(ctx, "mend reports these licences by its own names rather than SPDX "+
		"identifiers, so a policy written in SPDX will not match them — write rules against these "+
		"strings, or use the licences control's Trivy scanner, which reports SPDX",
		"licences", strings.Join(names, ", "))
}

// mendPackageName names the dependency a licence belongs to.
func mendPackageName(lib mendapi.InventoryLibrary) string {
	switch {
	case lib.GroupID != "" && lib.ArtifactID != "":
		return lib.GroupID + ":" + lib.ArtifactID
	case lib.Name != "":
		return lib.Name
	default:
		return lib.Filename
	}
}
