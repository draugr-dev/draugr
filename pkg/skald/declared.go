package skald

import (
	"encoding/json"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// DeclaredProvenanceTool is the provenance entry a scan stamps on its SARIF to record what its
// descriptor declared: one entry for the project, and one more for each component.
const DeclaredProvenanceTool = "draugr/declared"

// The fields of a declared entry. Lists travel as one JSON-encoded field each, because a SARIF
// property bag is an object and a key written twice keeps only its last value.
const (
	declaredExposure    = "exposure"
	declaredCriticality = "criticality"
	declaredControls    = "controls"
	declaredExclusions  = "exclusions"
	declaredRepos       = "repositories"
)

// declaredExclusion is the part of a config.exclude rule that decides which findings it sets
// aside. The reason and the expiry travel on each finding the rule matched, and a rule read back
// here is only ever asked whether it would match one.
type declaredExclusion struct {
	Paths []string `json:"paths,omitempty"`
	Rules []string `json:"rules,omitempty"`
}

// DeclaredProvenance renders what a run's descriptor declared as SARIF provenance entries, none
// where the run recorded nothing.
//
// A report compared later as somebody's base then carries the declaration of the commit it scanned.
// A pull request is judged against what its base already declared: its own descriptor is part of
// the change under review, and a change that declares its component less exposed, turns a control
// off or excludes the finding it adds would otherwise be judged by the declaration it introduces.
func DeclaredProvenance(d engine.Declarations) []sarif.Provenance {
	if len(d.Components) == 0 && len(d.Controls) == 0 && len(d.Exclusions) == 0 {
		return nil
	}
	exclusions := make([]declaredExclusion, 0, len(d.Exclusions))
	for _, rule := range d.Exclusions {
		exclusions = append(exclusions, declaredExclusion{Paths: rule.Paths, Rules: rule.Rules})
	}
	out := []sarif.Provenance{{
		Tool: DeclaredProvenanceTool,
		Fields: []sarif.Field{
			{Key: declaredControls, Value: jsonList(d.Controls)},
			{Key: declaredExclusions, Value: jsonList(exclusions)},
		},
	}}
	for _, c := range d.Components {
		out = append(out, sarif.Provenance{
			Tool:      DeclaredProvenanceTool,
			Component: c.Name,
			Fields: []sarif.Field{
				{Key: declaredControls, Value: jsonList(c.Controls)},
				{Key: declaredCriticality, Value: string(c.Criticality)},
				{Key: declaredExposure, Value: string(c.Exposure)},
				{Key: declaredRepos, Value: jsonList(c.Repositories)},
			},
		})
	}
	return out
}

// DeclaredOfReport is what a loaded report's descriptor declared, and whether the report recorded
// it. The inverse of DeclaredProvenance. A report written before scans recorded it reads as not
// recorded, which a comparison has to say rather than read as a descriptor that declared nothing.
func DeclaredOfReport(rep sarif.Report) (engine.Declarations, bool) {
	var d engine.Declarations
	recorded := false
	for _, p := range rep.Provenance {
		if p.Tool != DeclaredProvenanceTool {
			continue
		}
		recorded = true
		if p.Component == "" {
			d.Controls = readList[string](fieldOf(p, declaredControls))
			for _, e := range readList[declaredExclusion](fieldOf(p, declaredExclusions)) {
				d.Exclusions = append(d.Exclusions, saga.ExcludeRule{Paths: e.Paths, Rules: e.Rules})
			}
			continue
		}
		d.Components = append(d.Components, engine.ComponentDeclaration{
			Name:         p.Component,
			Exposure:     saga.Exposure(fieldOf(p, declaredExposure)),
			Criticality:  saga.Criticality(fieldOf(p, declaredCriticality)),
			Controls:     readList[string](fieldOf(p, declaredControls)),
			Repositories: readList[string](fieldOf(p, declaredRepos)),
		})
	}
	return d, recorded
}

// fieldOf is the value of p's field named key, empty where it has none.
func fieldOf(p sarif.Provenance, key string) string {
	for _, f := range p.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

// jsonList encodes a list for one provenance field, `[]` for an empty one.
func jsonList[T any](items []T) string {
	if len(items) == 0 {
		return "[]"
	}
	b, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// readList decodes a list jsonList encoded, nil for a value that does not decode. The value is one
// a scan wrote with jsonList, so it decodes unless somebody edited the file by hand.
func readList[T any](value string) []T {
	var items []T
	if value == "" || json.Unmarshal([]byte(value), &items) != nil {
		return nil
	}
	return items
}
