package engine

import (
	"maps"
	"slices"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// EffectConsent is which scanner effects a run accepted, beside what its descriptor declared.
//
// Both are kept because they answer different questions. The descriptor is what was reviewed;
// the run is what was in force, and --allow-effects accepts an effect for one invocation that no
// reviewed file names. A record holding only one of the two cannot show that they differ.
type EffectConsent struct {
	// Declared is config.allowEffects in the merged descriptor, sorted and deduplicated.
	Declared []plugin.EffectKind
	// Allowed is what the run accepted: Declared together with --allow-effects, sorted and
	// deduplicated.
	Allowed []plugin.EffectKind
}

// effectConsent records what a run accepted from the same inputs Plan gates on, so the record
// and the gate cannot disagree about what was in force.
func effectConsent(fromSaga, fromFlag []string) EffectConsent {
	return EffectConsent{
		Declared: slices.Sorted(maps.Keys(allowedEffects(fromSaga, nil))),
		Allowed:  slices.Sorted(maps.Keys(allowedEffects(fromSaga, fromFlag))),
	}
}

// SBOMFailure is an SBOM document config.sbom asked for that the run did not produce.
type SBOMFailure struct {
	// Scope is the document that failed: saga.SBOMScopeComponent for one target's inventory, and
	// saga.SBOMScopeProject for the document assembled from them.
	Scope saga.SBOMScope
	// Component and Target name the target whose inventory failed, as a document taken from it
	// names it (sbom.TargetName). Both are empty on a project document, and on a failure that
	// belongs to no one target: no generator configured, or the run canceled.
	Component string
	Target    string
	// Format is the format that was asked for.
	Format saga.SBOMFormat
	// Reason is what stopped it, in the generator's words, the same text ScanErrors records under
	// (sbom).
	Reason string
}
