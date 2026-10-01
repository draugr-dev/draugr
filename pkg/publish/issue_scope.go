package publish

import (
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Split values: one item for everything an entry covers, or one per control or per component.
const (
	splitNone      = ""
	splitControl   = "control"
	splitComponent = "component"
)

// issueSelection is the part of a run an issue entry covers, as the descriptor writes it. Within a
// field the values are alternatives; every label must match; the fields together narrow.
type issueSelection struct {
	Components []string
	Labels     map[string]string
	Controls   []string
}

// issueEntry is what shapes one entry's items: its selection, how it splits, the lowest band that
// opens an item, the branches its closing line names, and the children each item has.
type issueEntry struct {
	Select      issueSelection
	Split       string
	MinPriority string
	ClosesOn    []string
	// Children is `actions` or `controls`, and empty for an item with none.
	Children string
	// MaxChildren is the most children an item has open.
	MaxChildren int
}

// issueError is one thing that stopped a control completing.
type issueError struct {
	Control string
	Message string
}

// issuePart is what one item covers, judged: the findings and errors in it, and whether its item
// should be open.
type issuePart struct {
	// Split and Value name the part of a split entry, `control` and `sca` for example. Both are
	// empty for an entry that is not split.
	Split, Value string
	// Reports holds the covered findings by control, accepted ones included.
	Reports map[string]sarif.Report
	// Errors is empty unless the run was incomplete.
	Errors []issueError
	// Failing counts the open findings that fail the gate, by control.
	Failing map[string]int
	// Accepted counts the covered findings a config.exclude entry accepts.
	Accepted int
	// Fails reports whether the item should be open.
	Fails bool
	// BelowMinimum reports a part whose findings fail the gate with none at or above the entry's
	// minPriority, so its close comment can say which of the two let it close.
	BelowMinimum bool
	// Listed describes the findings the body lists, the open ones that fail the gate at or above
	// the entry's minPriority, for the labels labelBy keeps.
	Listed listedFacts
}

// listedFacts is what the labels of labelBy are read from: the highest priority among the listed
// findings, and the controls, exposures and criticalities they carry.
type listedFacts struct {
	Top                             string
	Controls, Exposure, Criticality map[string]bool
}

// factLabels is the labels an item keeps for the facts an entry names, sorted.
func factLabels(facts []string, part issuePart) []string {
	var out []string
	for _, f := range facts {
		switch f {
		case saga.LabelByPriority:
			if part.Listed.Top != "" {
				out = append(out, saga.FactLabel(f, part.Listed.Top))
			}
		case saga.LabelByControl:
			for _, v := range sortedKeys(part.Listed.Controls) {
				out = append(out, saga.FactLabel(f, v))
			}
		case saga.LabelByExposure:
			for _, v := range sortedKeys(part.Listed.Exposure) {
				out = append(out, saga.FactLabel(f, v))
			}
		case saga.LabelByCriticality:
			for _, v := range sortedKeys(part.Listed.Criticality) {
				out = append(out, saga.FactLabel(f, v))
			}
		case saga.LabelByIncomplete:
			if len(part.Errors) > 0 {
				out = append(out, saga.FactLabel(f, ""))
			}
		}
	}
	sort.Strings(out)
	return out
}

// failingTotal is the number of open findings in the part that fail the gate.
func (p issuePart) failingTotal() int {
	n := 0
	for _, c := range p.Failing {
		n += c
	}
	return n
}

// scopeKey is the run's scope as it was requested, in a stable form: `all` when it was not
// narrowed. Selectors appear in alphabetical order, each one's values sorted.
//
// Built from what was asked for rather than from the components it resolved to, so a component
// gaining a label does not change the key and open a second item.
func scopeKey(s engine.Scope) string {
	fields := map[string][]string{
		"components": s.Components,
		"controls":   s.Controls,
		"labels":     s.Labels,
	}
	for _, c := range s.Criticality {
		fields["criticality"] = append(fields["criticality"], string(c))
	}
	for _, e := range s.Exposure {
		fields["exposure"] = append(fields["exposure"], string(e))
	}
	if k := selectorKey(fields); k != "" {
		return k
	}
	return "all"
}

// key is the selection in the scope key's shape, empty when it selects nothing.
func (s issueSelection) key() string {
	return selectorKey(map[string][]string{
		"components": s.Components,
		"controls":   s.Controls,
		"labels":     s.labelPairs(),
	})
}

// labelPairs is the selection's labels as `key=value`, in no particular order.
func (s issueSelection) labelPairs() []string {
	labels := make([]string, 0, len(s.Labels))
	for k, v := range s.Labels {
		labels = append(labels, k+"="+v)
	}
	return labels
}

// selectorKey joins each non-empty selector as `name=v1,v2`, names in alphabetical order and each
// selector's values sorted.
func selectorKey(fields map[string][]string) string {
	names := make([]string, 0, len(fields))
	for name, values := range fields {
		if len(values) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		values := append([]string(nil), fields[name]...)
		sort.Strings(values)
		parts = append(parts, name+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, ";")
}

// coversControl reports whether the selection includes a control.
func (s issueSelection) coversControl(control string) bool {
	return len(s.Controls) == 0 || contains(s.Controls, control)
}

// coversComponent reports whether the selection includes a component. A finding or error that
// names no component belongs to every selection, since there is no component to leave it out by.
func (s issueSelection) coversComponent(component string, labels map[string]map[string]string) bool {
	if component == "" {
		return true
	}
	if len(s.Components) > 0 && !contains(s.Components, component) {
		return false
	}
	have := labels[component]
	for k, v := range s.Labels {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// issueParts divides what an entry covers into the parts its items track, in a stable order. An
// entry that is not split has one part. A split entry has one per covered control, or one per
// covered component: every declared component the selection includes, and any undeclared one a
// finding names.
//
// Every part is returned, passing or failing, because a passing part is what closes its item.
func issueParts(data report.Data, entry issueEntry) []issuePart {
	covered := coveredReports(data, entry.Select)
	errs := coveredErrors(data, entry.Select)
	policy := data.GateForReport().Policy

	switch entry.Split {
	case splitControl:
		names := map[string]bool{}
		for c := range covered {
			names[c] = true
		}
		for _, e := range errs {
			names[e.Control] = true
		}
		parts := make([]issuePart, 0, len(names))
		for _, c := range sortedKeys(names) {
			var own []issueError
			for _, e := range errs {
				if e.Control == c {
					own = append(own, e)
				}
			}
			reports := map[string]sarif.Report{}
			if r, ok := covered[c]; ok {
				reports[c] = r
			}
			parts = append(parts, judge(splitControl, c, reports, own, policy, entry.MinPriority))
		}
		return parts
	case splitComponent:
		names := map[string]bool{}
		for name := range data.Labels {
			if entry.Select.coversComponent(name, data.Labels) {
				names[name] = true
			}
		}
		for _, r := range covered {
			for _, res := range r.Results {
				if res.Component != "" {
					names[res.Component] = true
				}
			}
		}
		parts := make([]issuePart, 0, len(names))
		for _, name := range sortedKeys(names) {
			only := issueSelection{Components: []string{name}}
			reports := map[string]sarif.Report{}
			for c, r := range covered {
				if kept := keepResults(r, func(res sarif.Result) bool {
					return only.coversComponent(res.Component, nil)
				}); len(kept.Results) > 0 {
					reports[c] = kept
				}
			}
			parts = append(parts, judge(splitComponent, name, reports, errs, policy, entry.MinPriority))
		}
		return parts
	default:
		return []issuePart{judge(splitNone, "", covered, errs, policy, entry.MinPriority)}
	}
}

// coveredReports is each covered control's report holding only the covered findings. A control
// the selection includes stays even with no findings, so a split by control has a part to close.
func coveredReports(data report.Data, sel issueSelection) map[string]sarif.Report {
	out := map[string]sarif.Report{}
	for name, ctl := range data.Run.Controls {
		if !sel.coversControl(name) {
			continue
		}
		out[name] = keepResults(ctl.Report, func(res sarif.Result) bool {
			return sel.coversComponent(res.Component, data.Labels)
		})
	}
	return out
}

// coveredErrors is what stopped a covered control completing, listed only when the run is
// incomplete. A scan error records its control and no component, so it counts for every
// selection that includes the control.
func coveredErrors(data report.Data, sel issueSelection) []issueError {
	if !data.Incomplete {
		return nil
	}
	var out []issueError
	for _, control := range sortedKeys(data.Run.ScanErrors) {
		if !sel.coversControl(control) {
			continue
		}
		for _, msg := range data.Run.ScanErrors[control] {
			out = append(out, issueError{Control: control, Message: msg})
		}
	}
	return out
}

// keepResults is a copy of a report holding only the results keep accepts.
func keepResults(r sarif.Report, keep func(sarif.Result) bool) sarif.Report {
	kept := r
	kept.Results = nil
	for _, res := range r.Results {
		if keep(res) {
			kept.Results = append(kept.Results, res)
		}
	}
	return kept
}

// judge counts a part's findings and decides whether its item should be open.
func judge(split, value string, reports map[string]sarif.Report, errs []issueError, policy norn.Policy, minPriority string) issuePart {
	p := issuePart{Split: split, Value: value, Reports: reports, Errors: errs, Failing: map[string]int{},
		Listed: listedFacts{Controls: map[string]bool{}, Exposure: map[string]bool{}, Criticality: map[string]bool{}}}
	atMinimum := false
	for control, r := range reports {
		for _, res := range r.Results {
			if res.Suppressed() {
				p.Accepted++
				continue
			}
			if !policy.FindingFails(control, res) {
				continue
			}
			p.Failing[control]++
			if !atOrAbove(res.Priority, minPriority) {
				continue
			}
			atMinimum = true
			if res.Priority != "" && (p.Listed.Top == "" ||
				prioritization.Priority(res.Priority).Rank() > prioritization.Priority(p.Listed.Top).Rank()) {
				p.Listed.Top = res.Priority
			}
			p.Listed.Controls[control] = true
			if res.Exposure != "" {
				p.Listed.Exposure[res.Exposure] = true
			}
			if res.Criticality != "" {
				p.Listed.Criticality[res.Criticality] = true
			}
		}
	}
	p.Fails = atMinimum || len(errs) > 0
	p.BelowMinimum = !p.Fails && p.failingTotal() > 0
	return p
}

// atOrAbove reports whether a priority reaches a band. Every priority reaches an unset band.
func atOrAbove(priority, band string) bool {
	if band == "" {
		return true
	}
	return prioritization.Priority(priority).Rank() >= prioritization.Priority(band).Rank()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// issueMarker is the comment that identifies an item as this entry's, for this project, scope and
// part. Values are percent-encoded wherever they could end the comment or break the fields apart.
func issueMarker(project, scope string, entry issueEntry, part issuePart) string {
	fields := []string{"project=" + markerValue(project), "scope=" + markerValue(scope)}
	if k := entry.Select.key(); k != "" {
		fields = append(fields, "select="+markerValue(k))
	}
	if part.Split != "" {
		fields = append(fields, part.Split+"="+markerValue(part.Value))
	}
	return "<!-- draugr:issue v1 " + strings.Join(fields, " ") + " -->"
}

// markerValue keeps the characters a key is written in and percent-encodes the rest. A hyphen
// after a hyphen is encoded too, so no value can hold the `--` that ends a comment.
func markerValue(s string) string {
	var b strings.Builder
	afterHyphen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("._=,;/+", c) >= 0 || (c == '-' && !afterHyphen) {
			b.WriteByte(c)
			afterHyphen = c == '-'
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
		afterHyphen = false
	}
	return b.String()
}

// issueTitle is the item's title: what tells this item from the entry's others first, then what
// every item of the entry shares, and the project last, where a narrow list cuts it off.
//
// The subject is the most specific of the split part, the selection, the run's scope and the
// project. A split part is named bare, since the entry's split already says what kind it is.
func issueTitle(project string, scope engine.Scope, entry issueEntry, part issuePart) string {
	var names []string
	if part.Value != "" {
		names = append(names, part.Value)
	}
	sel := entry.Select
	if s := selectionWords(sel.labelPairs(), sel.Components, sel.Controls, nil, nil); s != "" {
		names = append(names, s)
	}
	exposure := make([]string, len(scope.Exposure))
	for i, e := range scope.Exposure {
		exposure[i] = string(e)
	}
	criticality := make([]string, len(scope.Criticality))
	for i, c := range scope.Criticality {
		criticality[i] = string(c)
	}
	if s := selectionWords(scope.Labels, scope.Components, scope.Controls, exposure, criticality); s != "" {
		names = append(names, s)
	}
	names = append(names, project)

	// Project names, keys and component names come from the descriptor, so they are broken the
	// way scanner text is; a title is plain text on every forge and takes no backslash escapes.
	for i, n := range names {
		names[i] = breakTokens(flatten(n))
	}
	title := names[0] + " fails the Draugr gate"
	for _, n := range names[1:] {
		title += " · " + n
	}
	return truncateRunes(title, maxTitle)
}

// maxTitle is the longest title written, in characters. GitHub refuses one over 256.
const maxTitle = 255

// truncateRunes shortens s to at most n characters, ending it with an ellipsis when it was cut.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// selectionWords is a selection as a title names it: every label as `key=value`, then each other
// selector as its name and its values, `control sca or sast`, the selectors joined by commas. Values
// within a selector are alternatives and selectors narrow together, which is what `or` and the
// comma say.
func selectionWords(labels, components, controls, exposure, criticality []string) string {
	var out []string
	sortedLabels := append([]string(nil), labels...)
	sort.Strings(sortedLabels)
	out = append(out, sortedLabels...)
	for _, s := range []struct {
		name   string
		values []string
	}{
		{"component", components},
		{"control", controls},
		{"exposure", exposure},
		{"criticality", criticality},
	} {
		if len(s.values) == 0 {
			continue
		}
		values := append([]string(nil), s.values...)
		sort.Strings(values)
		out = append(out, s.name+" "+strings.Join(values, " or "))
	}
	return strings.Join(out, ", ")
}
