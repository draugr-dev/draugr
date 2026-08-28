package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// partsOnlyGen produces one document per target and cannot assemble.
type partsOnlyGen struct{}

func (partsOnlyGen) Generate(_ context.Context, component string, t plugin.Target, f saga.SBOMFormat) (sbom.Document, error) {
	return sbom.Document{Component: component, Target: t.Identity(), Format: f, Bytes: []byte("{}")}, nil
}

// assemblingGen also implements sbom.Assembler.
type assemblingGen struct{ partsOnlyGen }

func (assemblingGen) Assemble(_ saga.Release, f saga.SBOMFormat, _ []sbom.Document) (sbom.Document, error) {
	return sbom.Document{Project: true, Format: f, Bytes: []byte("{assembled}")}, nil
}

func scopeModel(scope saga.SBOMScope) saga.Model {
	return saga.Model{
		Release: saga.Release{Name: "acme", Version: "1.0.0"},
		Config:  saga.Config{SBOM: &saga.SBOMConfig{Enabled: true, Scope: scope}},
		Components: []saga.Component{{
			Name: "api", Criticality: saga.Unstated(saga.Criticality("supporting")), Exposure: saga.Unstated(saga.Exposure("internal")),
			Repositories: []saga.Repository{{URL: "repo-a"}, {URL: "repo-b"}},
		}},
	}
}

func generate(t *testing.T, gen sbom.Generator, scope saga.SBOMScope) ([]sbom.Document, []string) {
	t.Helper()
	e := New(NewRegistry(), WithSBOM(gen))
	return e.generateSBOMs(context.Background(), scopeModel(scope))
}

func countProject(docs []sbom.Document) (project, parts int) {
	for _, d := range docs {
		if d.Project {
			project++
			continue
		}
		parts++
	}
	return
}

// The default is unchanged behavior: a descriptor written before scope existed keeps working.
func TestSBOMScopeDefaultsToPerTarget(t *testing.T) {
	docs, errs := generate(t, assemblingGen{}, "")
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	project, parts := countProject(docs)
	if project != 0 || parts != 2 {
		t.Errorf("got %d project + %d parts, want 0 + 2", project, parts)
	}
}

// scope: project asked for a document covering the product. Delivering the per-repository parts
// as well would be answering a different question alongside the one that was asked.
func TestSBOMScopeProjectReplacesTheParts(t *testing.T) {
	docs, errs := generate(t, assemblingGen{}, saga.SBOMScopeProject)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	project, parts := countProject(docs)
	if project != 1 || parts != 0 {
		t.Errorf("got %d project + %d parts, want 1 + 0", project, parts)
	}
}

func TestSBOMScopeBothKeepsTheEvidence(t *testing.T) {
	docs, errs := generate(t, assemblingGen{}, saga.SBOMScopeBoth)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	project, parts := countProject(docs)
	if project != 1 || parts != 2 {
		t.Errorf("got %d project + %d parts, want 1 + 2", project, parts)
	}
}

// A generator that cannot assemble must not quietly deliver the parts: the descriptor asked for
// a document covering the product, and seven documents covering repositories is a green run that
// answered something else.
func TestSBOMScopeProjectFailsRatherThanFallingBack(t *testing.T) {
	_, errs := generate(t, partsOnlyGen{}, saga.SBOMScopeProject)
	if len(errs) == 0 {
		t.Fatal("a generator that cannot assemble produced no error")
	}
	if !strings.Contains(strings.Join(errs, " "), "assemble") {
		t.Errorf("error should say what could not be done, got: %v", errs)
	}
}
