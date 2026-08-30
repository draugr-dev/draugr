package sbom

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sbom"
)

// Assemble combines per-target documents into one covering the whole release.
//
// The unit problem this solves: an SBOM is asked for per *product*. A customer questionnaire, EO
// 14028 and the CRA all want the bill of materials of the thing you shipped. Draugr scans per
// repository and image, so a project with four repositories and three images produces seven
// documents and no answer to the question actually being asked.
//
// What makes this assembly rather than a merge is that the hierarchy is **declared, not
// inferred**. A generic merge tool has a pile of documents and must guess how they relate. This
// one is handed a release containing named components containing named targets, so the "which
// component pulled this in" question — the one a triager asks the moment a CVE lands — is
// answered from the descriptor instead of being lost in the flattening.
//
// Which is the trap in the obvious implementation. Deduplicating `requests@2.19.1` down to one
// entry answers "what do we ship" and destroys "who ships it"; keeping three answers the second
// and makes any consumer that counts packages report a number that means nothing. Neither is
// necessary: CycloneDX keeps one entry per package and a dependency graph saying which containers
// hold it, and both questions are answerable from the same document.
func (g *Generator) Assemble(
	project string, release saga.Release, format saga.SBOMFormat, docs []sbom.Document,
) (sbom.Document, error) {
	if format == "" {
		format = sbom.DefaultFormat
	}
	// SPDX expresses containment through relationships and can carry this, but assembling it
	// correctly is a different piece of work — and shipping a half-right SPDX document would be
	// worse than declining, because nothing about it would look wrong.
	if format != saga.SBOMCycloneDXJSON {
		return sbom.Document{}, fmt.Errorf(
			"config.sbom.scope: a project document can only be assembled as %s, not %s — "+
				"set config.sbom.format to %s, or use scope: component",
			saga.SBOMCycloneDXJSON, format, saga.SBOMCycloneDXJSON)
	}
	if len(docs) == 0 {
		return sbom.Document{}, fmt.Errorf("config.sbom.scope: nothing to assemble into a project document")
	}

	out := newCycloneDX(project, release)
	a := &assembly{seenComponent: map[string]bool{}, seenRef: map[string]bool{}}

	for _, d := range docs {
		var src cycloneDX
		if err := json.Unmarshal(d.Bytes, &src); err != nil {
			return sbom.Document{}, fmt.Errorf("assemble project SBOM: %s/%s is not readable CycloneDX: %w",
				d.Component, d.Target, err)
		}
		a.add(&out, d, src)
	}
	a.link(&out)

	bytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return sbom.Document{}, fmt.Errorf("assemble project SBOM: %w", err)
	}
	return sbom.Document{Project: true, Format: format, Bytes: append(bytes, '\n')}, nil
}

// assembly accumulates the hierarchy edges while documents are read, so the graph is built in one
// pass over the inputs rather than by walking the output afterwards.
type assembly struct {
	// componentRefs is each Saga component's target nodes, in the order they were seen.
	componentRefs map[string][]string
	// componentOrder keeps components in descriptor order; a project document that reorders
	// itself between runs cannot be diffed.
	componentOrder []string
	seenComponent  map[string]bool
	// seenRef deduplicates packages across documents: one entry per package, with the graph
	// carrying which containers hold it.
	seenRef map[string]bool
}

// remap translates one source document's bom-refs into the assembled document's.
//
// Necessary because packages are re-keyed on assembly — a purl where there is one, so the same
// library arriving from two targets collapses to a single entry. The source's own dependency
// edges are written in its own refs, and copying them unchanged would point them at identifiers
// that no longer exist. Dangling refs are not a validation nicety: a consumer walking the graph
// silently loses the subtree behind one.
type remap map[string]string

// apply rewrites one edge, reporting whether every ref in it survived the translation.
func (m remap) apply(dep cdxDependency) (cdxDependency, bool) {
	ref, ok := m[dep.Ref]
	if !ok {
		return cdxDependency{}, false
	}
	out := cdxDependency{Ref: ref}
	for _, t := range dep.DependsOn {
		mapped, ok := m[t]
		if !ok {
			// The edge points at something not carried into the assembly. Dropping the target
			// keeps the rest of the edge, which is more information than dropping the edge.
			continue
		}
		out.DependsOn = append(out.DependsOn, mapped)
	}
	return out, true
}

// add folds one per-target document into the assembly.
func (a *assembly) add(out *cycloneDX, d sbom.Document, src cycloneDX) {
	if a.componentRefs == nil {
		a.componentRefs = map[string][]string{}
	}
	compRef := "draugr:component/" + d.Component
	if !a.seenComponent[d.Component] {
		a.seenComponent[d.Component] = true
		a.componentOrder = append(a.componentOrder, d.Component)
		out.Components = append(out.Components, cdxComponent{
			Type: "application", Name: d.Component, BOMRef: compRef,
		})
	}

	// The target keeps its own node. Two repositories in one component are two places a package
	// can have come from, and collapsing them would answer "which component" while losing "which
	// repository" — the same loss one level down.
	targetRef := "draugr:target/" + d.Component + "/" + d.Target
	targetType := "application"
	if root := src.Metadata.Component; root != nil && root.Type != "" {
		targetType = root.Type
	}
	out.Components = append(out.Components, cdxComponent{
		Type: targetType, Name: d.Target, BOMRef: targetRef,
	})
	a.componentRefs[d.Component] = append(a.componentRefs[d.Component], targetRef)

	translate := remap{}
	if root := src.Metadata.Component; root != nil && root.BOMRef != "" {
		translate[root.BOMRef] = targetRef // the source's own root becomes our target node
	}
	var contained []string
	for _, c := range src.Components {
		ref := c.ref()
		if c.BOMRef != "" {
			translate[c.BOMRef] = ref
		}
		contained = append(contained, ref)
		if a.seenRef[ref] {
			continue
		}
		a.seenRef[ref] = true
		c.BOMRef = ref
		out.Components = append(out.Components, c)
	}
	out.Dependencies = append(out.Dependencies, cdxDependency{Ref: targetRef, DependsOn: contained})

	// Carry the source document's own dependency edges, translated. They are what the scanner
	// actually observed about the packages, and the assembled hierarchy is additional to that
	// rather than a replacement for it — a consumer asking "what pulled this in" wants the real
	// answer, not just which repository it appeared in.
	for _, dep := range src.Dependencies {
		if translated, ok := translate.apply(dep); ok {
			out.Dependencies = append(out.Dependencies, translated)
		}
	}
}

// link adds the two levels of hierarchy the descriptor declares: the release contains its
// components, and each component contains its targets.
func (a *assembly) link(out *cycloneDX) {
	rootRef := out.Metadata.Component.BOMRef
	var compRefs []string
	for _, name := range a.componentOrder {
		compRef := "draugr:component/" + name
		compRefs = append(compRefs, compRef)
		out.Dependencies = append(out.Dependencies,
			cdxDependency{Ref: compRef, DependsOn: a.componentRefs[name]})
	}
	out.Dependencies = append([]cdxDependency{{Ref: rootRef, DependsOn: compRefs}}, out.Dependencies...)

	// Sorted so the same run assembles to the same bytes. A project SBOM is a released artifact
	// people diff between versions, and map iteration order would make every regeneration look
	// like a change.
	sort.SliceStable(out.Dependencies, func(i, j int) bool { return out.Dependencies[i].Ref < out.Dependencies[j].Ref })
	for i := range out.Dependencies {
		sort.Strings(out.Dependencies[i].DependsOn)
	}
}
