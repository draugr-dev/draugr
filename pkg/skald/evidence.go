package skald

import (
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// effectsReport is which scanner effects the run accepted, and which its scanners had.
//
// The descriptor's declaration is kept beside what the run accepted because the two differ
// whenever --allow-effects was passed, and a reader judging the run against a policy has to see
// the run's answer rather than the descriptor's.
type effectsReport struct {
	// Declared is config.allowEffects in the descriptor the run read.
	Declared []plugin.EffectKind `json:"declared"`
	// Allowed is what the run accepted: Declared together with --allow-effects.
	Allowed []plugin.EffectKind `json:"allowed"`
	// Used is each effect declared by a scanner that executed in this run. A result reused from the
	// cache does not count, because nothing was sent to produce it. Network and disclosure run
	// without being accepted, so Used can name a kind Allowed does not.
	Used []effectUsed `json:"used"`
}

// effectUsed is one effect a scanner had on a target.
type effectUsed struct {
	Kind plugin.EffectKind `json:"kind"`
	// Detail is the scanner's own statement of what happens, the sentence `draugr controls` lists.
	Detail string `json:"detail"`
}

// effectsOf renders what the engine recorded about effects.
//
// Every list is present, empty where nothing applies. A reader judging a policy treats an empty
// list as an answer, and a missing key as a document that does not say.
func effectsOf(run engine.Result) effectsReport {
	out := effectsReport{
		Declared: nonNil(run.Consent.Declared),
		Allowed:  nonNil(run.Consent.Allowed),
		Used:     make([]effectUsed, 0, len(run.Effects)),
	}
	for _, e := range run.Effects {
		out.Used = append(out.Used, effectUsed{Kind: e.Kind, Detail: e.Detail})
	}
	return out
}

func nonNil(kinds []plugin.EffectKind) []plugin.EffectKind {
	if kinds == nil {
		return []plugin.EffectKind{}
	}
	return kinds
}

// sbomsReport is the SBOM documents config.sbom asked for: the ones the run wrote, and the ones it
// could not produce.
type sbomsReport struct {
	Documents []sbomDocument `json:"documents,omitempty"`
	Failed    []sbomFailure  `json:"failed,omitempty"`
}

// sbomDocument is one SBOM the run wrote.
type sbomDocument struct {
	// Scope is `component` for one target's inventory and `project` for the document assembled
	// from them.
	Scope saga.SBOMScope `json:"scope"`
	// Component and Target are what the document describes, absent on a project document.
	Component string          `json:"component,omitempty"`
	Target    string          `json:"target,omitempty"`
	Format    saga.SBOMFormat `json:"format"`
	// File is the name the document is written under, in the -o directory and by every publisher.
	File string `json:"file"`
	// Digest is the SHA-256 of the file's contents.
	Digest string `json:"digest"`
}

// sbomFailure is one SBOM the run asked for and did not produce.
type sbomFailure struct {
	Scope     saga.SBOMScope  `json:"scope"`
	Component string          `json:"component,omitempty"`
	Target    string          `json:"target,omitempty"`
	Format    saga.SBOMFormat `json:"format"`
	Reason    string          `json:"reason"`
}

// sbomsOf renders the documents a run wrote and the ones it could not produce, or nil when it was
// asked for none.
func sbomsOf(run engine.Result) *sbomsReport {
	if len(run.SBOMs) == 0 && len(run.SBOMFailures) == 0 {
		return nil
	}
	out := &sbomsReport{}
	files := sbom.Filenames(run.SBOMs)
	for i, d := range run.SBOMs {
		scope := saga.SBOMScopeComponent
		if d.Project {
			scope = saga.SBOMScopeProject
		}
		out.Documents = append(out.Documents, sbomDocument{
			Scope: scope, Component: d.Component, Target: d.Target, Format: d.Format,
			File: files[i], Digest: d.Digest(),
		})
	}
	for _, f := range run.SBOMFailures {
		out.Failed = append(out.Failed, sbomFailure{
			Scope: f.Scope, Component: f.Component, Target: f.Target, Format: f.Format, Reason: f.Reason,
		})
	}
	return out
}
