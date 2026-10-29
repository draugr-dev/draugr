package needs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// write puts a descriptor in a temporary directory and returns its path.
func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "draugr.saga.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const sagaRepoAndImage = `project: app
release:
  version: "1.0"
config:
  controls:
    sca:
      enabled: true
    images:
      enabled: true
components:
  - name: web
    repositories:
      - url: .
    images:
      - image: alpine:3.19
`

const sagaProvenanceSigstore = `project: app
release:
  version: "1.0"
config:
  controls:
    provenance:
      enabled: true
      signers:
        - name: our-ci
          images: ["ghcr.io/acme/*"]
          keyless:
            issuer: https://token.actions.githubusercontent.com
            identity: https://github.com/acme/ci/.github/workflows/r.yml@refs/heads/main
components:
  - name: web
    images:
      - image: ghcr.io/acme/web:1
`

const sagaProvenanceX509 = `project: app
release:
  version: "1.0"
config:
  controls:
    provenance:
      enabled: true
      signers:
        - name: acme-pki
          images: ["acme.azurecr.io/*"]
          x509:
            trustStore: roots.pem
            subject: "C=US, O=Acme, CN=Acme Release Signing"
components:
  - name: web
    images:
      - image: acme.azurecr.io/web:1
`

const sagaProvenance = `project: app
release:
  version: "1.0"
config:
  controls:
    provenance:
      enabled: true
components:
  - name: web
    images:
      - image: ghcr.io/acme/web:1
`

const sagaImagesOnly = `project: app
release:
  version: "1.0"
config:
  controls:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
`

func TestToolsDerivation(t *testing.T) {
	reg := builtins.Registry()

	// Repo + image controls → trivy and git.
	model, err := saga.LoadFile(write(t, sagaRepoAndImage))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(Tools(reg, model)); !slices.Equal(got, []string{"git", "trivy"}) {
		t.Errorf("repo+image required = %v, want [git trivy]", got)
	}

	// Images only → trivy, no git.
	model, err = saga.LoadFile(write(t, sagaImagesOnly))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(Tools(reg, model)); !slices.Equal(got, []string{"trivy"}) {
		t.Errorf("images-only required = %v, want [trivy]", got)
	}
}

// A tool the descriptor selected is required, whatever the catalog calls it. cosign is optional in
// the inventory view, where nothing has been chosen and the question is what Draugr could use. Once
// a descriptor turns on the control cosign is the scanner for, a doctor that still calls it
// optional reports a clean environment for a scan that cannot run.
func TestASelectedToolIsRequiredEvenIfTheCatalogCallsItOptional(t *testing.T) {
	reg := builtins.Registry()
	model, err := saga.LoadFile(write(t, sagaProvenance))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tl := range Tools(reg, model) {
		if tl.Binary != "cosign" {
			continue
		}
		found = true
		if tl.Optional {
			t.Error("cosign is provenance's scanner here, so a missing one has to fail doctor")
		}
	}
	if !found {
		t.Fatal("provenance is enabled, so cosign should be required")
	}
}

func binaries(ts []tools.Tool) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Binary
	}
	return out
}

func TestToolsIncludesSyftOnlyWhenSBOMIsEnabled(t *testing.T) {
	// SBOM generation is not a control, so no scanner declares syft. Without the explicit hook
	// a Saga could ask for SBOMs and doctor would report a ready environment.
	reg := builtins.Registry()

	off := &saga.Model{Release: saga.Release{Version: "1"}}
	for _, tl := range Tools(reg, off) {
		if tl.Binary == "syft" {
			t.Error("syft should not be required when config.sbom is absent")
		}
	}

	on := &saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: true}},
	}
	var found bool
	for _, tl := range Tools(reg, on) {
		if tl.Binary == "syft" {
			found = true
		}
	}
	if !found {
		t.Error("syft should be required when config.sbom is enabled")
	}

	// enabled:false is a deliberate off switch, not a request.
	paused := &saga.Model{
		Release: saga.Release{Version: "1"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: false}},
	}
	for _, tl := range Tools(reg, paused) {
		if tl.Binary == "syft" {
			t.Error("syft should not be required when sbom is explicitly disabled")
		}
	}
}

// TestRequiredToolsIncludesAReachabilityAnalyzer is the mirror of the syft test above, for the
// other requirement no scanner block declares. A reachability analyzer is named in
// config.reachability and is deliberately not selectable from a scanner block, so the scanner
// selection filters it out with everything the control will not run, and doctor reported a ready
// environment for a descriptor whose scan then stopped on a missing analyzer.
func TestToolsIncludesAReachabilityAnalyzer(t *testing.T) {
	reg := builtins.Registry()
	sca := saga.Config{
		Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}},
	}
	requires := func(m *saga.Model, binary string) bool {
		for _, tl := range Tools(reg, m) {
			if tl.Binary == binary {
				return true
			}
		}
		return false
	}

	t.Run("named, with its control enabled", func(t *testing.T) {
		on := &saga.Model{Release: saga.Release{Version: "1"}, Config: sca}
		on.Config.Reachability = &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}}
		if !requires(on, "govulncheck") {
			t.Error("an analyzer named in config.reachability is a tool the scan will run")
		}
	})

	t.Run("not named", func(t *testing.T) {
		off := &saga.Model{Release: saga.Release{Version: "1"}, Config: sca}
		if requires(off, "govulncheck") {
			t.Error("govulncheck is opt-in; an absent reachability block does not ask for it")
		}
	})

	// config.reachability is project-wide, so an analyzer whose control is switched off is a tool
	// this scan will never reach for. Asking for it sends somebody to install a scanner that would
	// not have run.
	t.Run("named, with its control disabled", func(t *testing.T) {
		paused := &saga.Model{
			Release: saga.Release{Version: "1"},
			Config: saga.Config{
				Controls:     map[string]saga.ControllerSettings{"sca": {"enabled": false}},
				Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}},
			},
		}
		if requires(paused, "govulncheck") {
			t.Error("an analyzer for a disabled control is not required")
		}
	})

	// An empty list is the same as omitting the block, which is what the field documents.
	t.Run("named as an empty list", func(t *testing.T) {
		empty := &saga.Model{Release: saga.Release{Version: "1"}, Config: sca}
		empty.Config.Reachability = &saga.ReachabilityConfig{}
		if requires(empty, "govulncheck") {
			t.Error("no analyzers named means none required")
		}
	})
}

const sagaInfrastructure = `project: platform
release: {version: "1.0"}
config:
  controls:
    kubernetes:
      enabled: true
      kubeBench: {enabled: true}
clusters:
  prod: {context: prod}
components:
  - name: cluster
    kubernetes: [{cluster: prod}]
`

// The same control with its default scanner, which reads the Kubernetes API and shells out to
// nothing.
const sagaInfrastructureDefault = `project: platform
release: {version: "1.0"}
config:
  controls:
    kubernetes: {enabled: true}
clusters:
  prod: {context: prod}
components:
  - name: cluster
    kubernetes: [{cluster: prod}]
`

// Some tools shell out in turn. kube-bench's CIS policy checks are scripts that invoke kubectl, so
// a machine with kube-bench and no kubectl fails at scan time, after a preflight that said
// everything was fine.
func TestToolsIncludesASecondaryBinary(t *testing.T) {
	model, err := saga.LoadFile(write(t, sagaInfrastructure))
	if err != nil {
		t.Fatal(err)
	}
	got := binaries(Tools(builtins.Registry(), model))
	if !slices.Equal(got, []string{"kube-bench", "kubectl"}) {
		t.Errorf("infrastructure required = %v, want [kube-bench kubectl]", got)
	}
}

// The other half of the same idea: a control requires the scanners it will run, not every one that
// could serve it. The default here needs no binary at all, so demanding kube-bench and kubectl
// would send someone to install tools the scan never uses, and report a control as unable to run
// when it can.
func TestToolsFollowsScannerSelection(t *testing.T) {
	model, err := saga.LoadFile(write(t, sagaInfrastructureDefault))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(Tools(builtins.Registry(), model)); len(got) != 0 {
		t.Errorf("infrastructure required = %v, want none, the default scanner execs nothing", got)
	}
}

// A scanner needing a tool the catalog has never heard of must not vanish from the check: a
// `doctor` that drops the names it does not recognize reports "all required tools present" for
// a control that cannot run. The one command whose job is answering "will a scan work?" would
// be answering yes because it did not recognize the name.
func TestToolsKeepsBinariesTheCatalogDoesNotKnow(t *testing.T) {
	reg := engine.NewRegistry()
	reg.RegisterController(unknownToolController{})
	reg.RegisterScanner(unknownToolScanner{})

	model, err := saga.LoadFile(write(t, sagaRepoAndImage))
	if err != nil {
		t.Fatal(err)
	}
	got := binaries(Tools(reg, model))
	if !slices.Contains(got, "some-future-tool") {
		t.Errorf("a scanner's binary should be checked even when Draugr does not package it: %v", got)
	}
}

// unknownToolScanner needs a binary that is deliberately not in the tool catalog.
type unknownToolScanner struct{}

func (unknownToolScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{
		Name:        "future",
		Binary:      "some-future-tool",
		Controls:    []string{"images"},
		TargetKinds: []plugin.TargetKind{plugin.TargetImage},
	}
}

func (unknownToolScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, nil
}

type unknownToolController struct{}

func (unknownToolController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent, DefaultScanners: []string{"future"}}
}

// Plans a job, because the selection now asks a control what it would run rather than working it
// out from its scanner blocks, and a controller that plans nothing needs nothing. A real one with
// its control enabled and a target to point at plans something.
func (unknownToolController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: "future", Target: plugin.ImageTarget{Ref: "example.test/app"}}}, nil
}

func (unknownToolController) Aggregate([]sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images"}, nil
}

// provenance picks its verifier per image from the matched signer's trust model, so which scanners
// it needs cannot be read off the descriptor's scanner blocks. Both halves, because a check that
// only proves notation is absent would pass against a build that never asks for it at all.
func TestProvenanceRequiresOnlyTheVerifierItsSignersUse(t *testing.T) {
	reg := builtins.Registry()

	sigstore, err := saga.LoadFile(write(t, sagaProvenanceSigstore))
	if err != nil {
		t.Fatal(err)
	}
	got := binaries(Tools(reg, sigstore))
	if slices.Contains(got, "notation") {
		t.Errorf("no x509 signer, so notation never runs and must not be demanded: %v", got)
	}
	if !slices.Contains(got, "cosign") {
		t.Errorf("a keyless signer is verified with cosign: %v", got)
	}

	x509, err := saga.LoadFile(write(t, sagaProvenanceX509))
	if err != nil {
		t.Fatal(err)
	}
	if got := binaries(Tools(reg, x509)); !slices.Contains(got, "notation") {
		t.Errorf("an x509 signer is verified with notation, which has to be installed: %v", got)
	}
}

// TestEveryScannerBinaryIsInstallableOrSourced closes the third gap unit tests cannot see.
//
// `draugr tools install` fetches pinned releases Draugr verified, which it can only do for tools
// it vouched for. A scanner whose binary is neither in that catalog nor named here leaves doctor
// telling somebody to run a command that will never find it, advice worse than none, because it
// sends them looking for a bug in Draugr rather than at the tool's own documentation.
//
// Crossed against the live registry, so registering a scanner is what triggers the requirement.
func TestEveryScannerBinaryIsInstallableOrSourced(t *testing.T) {
	t.Parallel()

	catalog := tools.Catalog()
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		for _, binary := range append([]string{info.Binary}, info.AlsoRequires...) {
			if binary == "" || binary == "git" {
				continue // git is assumed present, not provisioned
			}
			if _, installable := catalog[binary]; installable {
				continue
			}
			if _, sourced := externalTools[binary]; sourced {
				continue
			}
			t.Errorf("scanner %q needs %q, which Draugr neither installs nor knows a source for: "+
				"doctor will suggest `draugr tools install %s`, and that will never find it. Add "+
				"it to externalTools in internal/needs/needs.go, or to the tool catalog",
				info.Name, binary, binary)
		}
	}
}

// TestEveryExternalToolIsStillNeeded keeps the list from outliving the scanner that required it.
// A stale entry is harmless at runtime and misleading to read, which is how a list stops being
// trusted as a description of anything.
func TestEveryExternalToolIsStillNeeded(t *testing.T) {
	t.Parallel()

	needed := map[string]bool{}
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		needed[info.Binary] = true
		for _, extra := range info.AlsoRequires {
			needed[extra] = true
		}
	}
	for binary := range externalTools {
		if !needed[binary] {
			t.Errorf("externalTools names %q, which no registered scanner requires", binary)
		}
	}
}

// sagaSemgrepTwoComponents selects semgrep for sast by its block, leaves SBOM off, and enables
// secrets on one component only.
const sagaSemgrepTwoComponents = `project: shop
config:
  controls:
    sast:
      enabled: true
      semgrep:
        config: rules.yaml
components:
  - name: api
    repositories:
      - url: .
        paths: [services/api]
    controls:
      secrets:
        enabled: true
  - name: web
    repositories:
      - url: .
        paths: [services/web]
`

// A control with several scanners requires the one it selects, and syft is required only when
// config.sbom asks for SBOMs. gosec can serve sast and syft is a catalog tool, and this scan runs
// neither.
func TestToolsAreWhatTheScanRuns(t *testing.T) {
	model, err := saga.LoadFile(write(t, sagaSemgrepTwoComponents))
	if err != nil {
		t.Fatal(err)
	}
	got := binaries(Tools(builtins.Registry(), model))
	if want := []string{"git", "gitleaks", "semgrep"}; !slices.Equal(got, want) {
		t.Errorf("required = %v, want %v", got, want)
	}
}

// Each scanner carries the controls it runs for, across both components: secrets is enabled on one
// of them and sast on the project, and neither may be dropped or credited to the other.
func TestUsesNameTheControlsEachScannerRunsFor(t *testing.T) {
	model, err := saga.LoadFile(write(t, sagaSemgrepTwoComponents))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, u := range Uses(builtins.Registry(), model) {
		got[u.Info.Name] = u.Controls
	}
	if !slices.Equal(got["gitleaks"], []string{"secrets"}) {
		t.Errorf("gitleaks runs for %v, want [secrets]", got["gitleaks"])
	}
	if !slices.Equal(got["semgrep"], []string{"sast"}) {
		t.Errorf("semgrep runs for %v, want [sast]", got["semgrep"])
	}
	if _, ok := got["gosec"]; ok {
		t.Errorf("gosec is not selected for sast, and was counted: %v", got)
	}
}

// A tool Draugr does not fetch is named with where it comes from; one nobody has described still
// says what asked for it.
func TestExternalInstallHint(t *testing.T) {
	if got := ExternalInstallHint("mend"); got != externalTools["mend"] {
		t.Errorf("mend hint = %q, want the entry in externalTools", got)
	}
	if got := ExternalInstallHint("some-future-tool"); got == "" || got == externalTools["mend"] {
		t.Errorf("an unknown tool's hint = %q, want the generic source line", got)
	}
}
