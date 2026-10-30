package skald

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// renderRun writes report.json for a run and decodes it.
func renderRun(t *testing.T, run engine.Result) map[string]json.RawMessage {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderJSONFor(&buf, "shop", saga.Release{Version: "2.0.0"}, run,
		norn.Result{Verdict: norn.Pass}, "", nil, sarif.MarshalOptions{}, Provenance{}); err != nil {
		t.Fatalf("RenderJSONFor: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("report.json does not parse: %v\n%s", err, buf.String())
	}
	return doc
}

// themeFails inventories every target but one repository, whose checkout fails.
type themeFails struct{}

func (themeFails) Generate(_ context.Context, component string, t plugin.Target, format saga.SBOMFormat) (sbom.Document, error) {
	name := sbom.TargetName(t)
	if strings.HasSuffix(name, "storefront-theme") {
		return sbom.Document{}, errors.New("checkout " + name + ": repository not found")
	}
	if format == "" {
		format = sbom.DefaultFormat // as the generator does for a descriptor naming no format
	}
	return sbom.Document{Component: component, Target: name, Format: format, Bytes: []byte(`{"bomFormat":"CycloneDX","target":"` + name + `"}`)}, nil
}

// TestReportJSONListsTheSBOMsWrittenAndTheOneThatFailed: of two repositories in one component, one
// inventory is written and one fails. report.json names the written one with its file and digest,
// and the failed one with its reason, where the descriptor alone would read as both written.
func TestReportJSONListsTheSBOMsWrittenAndTheOneThatFailed(t *testing.T) {
	model := saga.Model{
		Project: "shop",
		Release: saga.Release{Version: "2.0.0"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: true}},
		Components: []saga.Component{{Name: "storefront", Repositories: []saga.Repository{
			{URL: "https://github.com/acme/storefront"},
			{URL: "https://github.com/acme/storefront-theme"},
		}}},
	}
	run, err := engine.New(engine.NewRegistry(), engine.WithSBOM(themeFails{})).Run(context.Background(), model)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got sbomsReport
	if err := json.Unmarshal(renderRun(t, run)["sboms"], &got); err != nil {
		t.Fatalf("sboms: %v", err)
	}
	want := sbomsReport{
		Documents: []sbomDocument{{
			Scope: saga.SBOMScopeComponent, Component: "storefront", Target: "https://github.com/acme/storefront",
			Format: saga.SBOMCycloneDXJSON, File: "sbom-storefront-https-github-com-acme-storefront.cdx.json",
			Digest: run.SBOMs[0].Digest(),
		}},
		Failed: []sbomFailure{{
			Scope: saga.SBOMScopeComponent, Component: "storefront", Target: "https://github.com/acme/storefront-theme",
			Format: saga.SBOMCycloneDXJSON, Reason: "checkout https://github.com/acme/storefront-theme: repository not found",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sboms =\n%+v\nwant\n%+v", got, want)
	}
	if !strings.HasPrefix(got.Documents[0].Digest, "sha256:") {
		t.Errorf("digest %q is not in the report's sha256:<hex> form", got.Documents[0].Digest)
	}
}

// TestReportJSONNamesTheProjectDocumentByItsScope: the assembled document describes no one target,
// and says it is the project's.
func TestReportJSONNamesTheProjectDocumentByItsScope(t *testing.T) {
	run := engine.Result{SBOMs: []sbom.Document{
		{Component: "api", Target: "ghcr.io/acme/api:2.0.0", Format: saga.SBOMCycloneDXJSON, Bytes: []byte("{}")},
		{Project: true, Format: saga.SBOMCycloneDXJSON, Bytes: []byte(`{"assembled":true}`)},
	}}
	var got sbomsReport
	if err := json.Unmarshal(renderRun(t, run)["sboms"], &got); err != nil {
		t.Fatalf("sboms: %v", err)
	}
	if len(got.Documents) != 2 {
		t.Fatalf("documents = %+v, want two", got.Documents)
	}
	project := got.Documents[1]
	if project.Scope != saga.SBOMScopeProject || project.Component != "" || project.Target != "" ||
		project.File != "sbom-project.cdx.json" {
		t.Errorf("project document = %+v", project)
	}
	if got.Documents[0].Scope != saga.SBOMScopeComponent {
		t.Errorf("a target's document has scope %q, want component", got.Documents[0].Scope)
	}
}

// TestReportJSONStatesTheEffectsTheFlagAllowed: --allow-effects accepts privilege for one run on top
// of a descriptor that accepts mutate, and the document says both.
func TestReportJSONStatesTheEffectsTheFlagAllowed(t *testing.T) {
	run := engine.Result{
		Consent: engine.EffectConsent{
			Declared: []plugin.EffectKind{plugin.EffectMutate},
			Allowed:  []plugin.EffectKind{plugin.EffectMutate, plugin.EffectPrivilege},
		},
		Effects: []plugin.Effect{{Kind: plugin.EffectPrivilege, Detail: "reads the host filesystem"}},
	}
	var got effectsReport
	if err := json.Unmarshal(renderRun(t, run)["effects"], &got); err != nil {
		t.Fatalf("effects: %v", err)
	}
	want := effectsReport{
		Declared: []plugin.EffectKind{plugin.EffectMutate},
		Allowed:  []plugin.EffectKind{plugin.EffectMutate, plugin.EffectPrivilege},
		Used:     []effectUsed{{Kind: plugin.EffectPrivilege, Detail: "reads the host filesystem"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("effects = %+v, want %+v", got, want)
	}
}

// TestReportJSONStatesEffectsWhenNoneWereAccepted: a run that accepted nothing says so with empty
// lists, and a run that asked for no SBOM carries no sboms block.
func TestReportJSONStatesEffectsWhenNoneWereAccepted(t *testing.T) {
	doc := renderRun(t, engine.Result{})
	var compact bytes.Buffer
	if err := json.Compact(&compact, doc["effects"]); err != nil {
		t.Fatalf("effects: %v", err)
	}
	if got := compact.String(); got != `{"declared":[],"allowed":[],"used":[]}` {
		t.Errorf("effects = %s, want three empty lists", got)
	}
	if _, ok := doc["sboms"]; ok {
		t.Errorf("a run that asked for no SBOM carries %s", doc["sboms"])
	}
}
