package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Children values as an entry holds them: none is empty.
const (
	childrenNone     = ""
	childrenActions  = saga.ChildrenActions
	childrenControls = saga.ChildrenControls
)

// The marker field that makes an item a child: `action=` and a hash of the action's key, or
// `child=` and the control's name. Neither is a field a parent's marker carries.
const (
	childFieldAction  = "action"
	childFieldControl = "child"
)

// childReason is what left actions without a child.
type childReason int

const (
	childrenComplete childReason = iota // every action has a child
	childrenCapped                      // maxChildren is reached
	childrenPaced                       // the run's budget would not cover the next child
)

// childUnit is one child an item has, or should have: one action, or the actions of one control.
type childUnit struct {
	// Field is the marker field naming the unit, `action=…` or `child=sca`.
	Field    string
	Priority string
	Control  string
	Actions  []report.Action
}

// splitMarker divides an item's marker into the marker of the part it tracks and, for a child,
// the field naming its action or control. A parent's marker comes back whole, with no field.
func splitMarker(m string) (parent, field string) {
	inner := strings.TrimSuffix(m, " -->")
	i := strings.LastIndexByte(inner, ' ')
	if i < 0 {
		return m, ""
	}
	last := inner[i+1:]
	if strings.HasPrefix(last, childFieldAction+"=") || strings.HasPrefix(last, childFieldControl+"=") {
		return inner[:i] + " -->", last
	}
	return m, ""
}

// childMarker is a child's marker: its parent's, with the field naming the child last.
func childMarker(parent, field string) string {
	return strings.TrimSuffix(parent, " -->") + " " + field + " -->"
}

// actionField names an action in a marker. The key is opaque and holds a separator a comment must
// not carry, so the marker holds the start of its hash.
func actionField(a report.Action) string {
	sum := sha256.Sum256([]byte(a.Key))
	return childFieldAction + "=" + hex.EncodeToString(sum[:])[:16]
}

// fieldKind is the kind of child a marker field names: actions or controls.
func fieldKind(field string) string {
	if strings.HasPrefix(field, childFieldControl+"=") {
		return childrenControls
	}
	return childrenActions
}

// childUnits is the children a part should have, in fix order: one per action, or one per control
// holding that control's actions.
func childUnits(kind string, actions []report.Action) []childUnit {
	if kind == childrenActions {
		units := make([]childUnit, len(actions))
		for i, a := range actions {
			units[i] = childUnit{Field: actionField(a), Priority: a.Priority, Control: a.Control, Actions: []report.Action{a}}
		}
		return units
	}
	var units []childUnit
	at := map[string]int{}
	for _, a := range actions {
		i, ok := at[a.Control]
		if !ok {
			i = len(units)
			at[a.Control] = i
			units = append(units, childUnit{Field: childFieldControl + "=" + markerValue(a.Control), Control: a.Control})
		}
		u := &units[i]
		u.Actions = append(u.Actions, a)
		if a.Priority != "" && (u.Priority == "" ||
			prioritization.Priority(a.Priority).Rank() > prioritization.Priority(u.Priority).Rank()) {
			u.Priority = a.Priority
		}
	}
	return units
}

// childTitle is a child's title: its priority, then the action's title or the control's name.
func childTitle(u childUnit) string {
	name := u.Control
	if len(u.Actions) == 1 && fieldKind(u.Field) == childrenActions {
		name = u.Actions[0].Title
	}
	title := breakTokens(flatten(name))
	if u.Priority != "" {
		title = u.Priority + " · " + title
	}
	return truncateRunes(title, maxTitle)
}

// childFacts is the labels a child keeps for the facts an entry names: its own priority and
// controls, and the exposures and criticalities of the components its findings are in.
func childFacts(facts []string, part issuePart, u childUnit) []string {
	sub := issuePart{Listed: listedFacts{Top: u.Priority,
		Controls: map[string]bool{}, Exposure: map[string]bool{}, Criticality: map[string]bool{}}}
	prints := map[string]bool{}
	for _, a := range u.Actions {
		for _, af := range a.Findings {
			prints[af.Control+"\x00"+af.Fingerprint] = true
			sub.Listed.Controls[af.Control] = true
		}
	}
	for control, r := range part.Reports {
		for _, res := range r.Results {
			if !prints[control+"\x00"+res.Fingerprint()] {
				continue
			}
			if res.Exposure != "" {
				sub.Listed.Exposure[res.Exposure] = true
			}
			if res.Criticality != "" {
				sub.Listed.Criticality[res.Criticality] = true
			}
		}
	}
	return factLabels(facts, sub)
}

// childLead opens a parent's Actions section when actions have no child: how many have one, out of
// how many, and what stopped the rest.
func childLead(f issueFormat, kind string, have, total int, reason childReason, limit int) string {
	if reason == childrenComplete || have >= total {
		return ""
	}
	noun := english.Noun(total, "action")
	if kind == childrenControls {
		noun = english.Noun(total, "control")
	}
	verb := "have"
	if have == 1 || total == 1 {
		verb = "has"
	}
	s := fmt.Sprintf("%d of %d %s %s an item. ", have, total, noun, verb)
	other := total - have
	switch {
	case kind == childrenControls && other == 1:
		s += "The other control's actions are listed below and get an item "
	case kind == childrenControls:
		s += fmt.Sprintf("The other %d controls' actions are listed below and get an item ", other)
	case other == 1:
		s += "The other is listed below and gets an item "
	default:
		s += fmt.Sprintf("The other %d are listed below and get an item ", other)
	}
	if reason == childrenPaced {
		return s + "on the next run."
	}
	return s + fmt.Sprintf("as open items close, since %s is %d.", f.code("maxChildren", false), limit)
}

// childrenChangedText is the comment that closes a child of another kind than the entry's.
func childrenChangedText(f issueFormat, kind string) string {
	if kind == childrenNone {
		kind = saga.ChildrenNone
	}
	return "The publisher's " + f.code("children", false) + " is now " + f.code(kind, false) + "."
}

// goneText is the comment that closes a child whose action or control the run no longer reports.
func goneText(f issueFormat, field string) string {
	if fieldKind(field) == childrenControls {
		return "The run reports no action for " + f.code(unescapeMarker(strings.TrimPrefix(field, childFieldControl+"=")), false) + "."
	}
	return "The run no longer reports this action."
}

// family is one failing part's parent and children as the forge holds them.
type family struct {
	marker  string
	parents []trackedItem
	kids    []trackedItem
}

// keepFamily brings a failing part's parent and children in line with the run: a child for each
// action or control while under the cap and the budget, the parent listing the actions without
// one. reserve is the writes to keep back for the parents still to be written after this one.
func (s *tracking) keepFamily(ctx context.Context, part issuePart, fam family, reserve int) error {
	t, f := s.t, s.t.format()
	body := newIssueBody(s.data, s.scope, s.entry, part)
	units := childUnits(s.entry.Children, body.Actions)

	byField := map[string][]trackedItem{}
	var otherKind []trackedItem
	for _, k := range fam.kids {
		_, field := splitMarker(markerLine(k.Body))
		if fieldKind(field) != s.entry.Children {
			otherKind = append(otherKind, k)
			continue
		}
		byField[field] = append(byField[field], k)
	}
	if err := closeAll(ctx, t, otherKind, closedUntracked, childrenChangedText(f, s.entry.Children)); err != nil {
		return err
	}

	parentNew := len(fam.parents) == 0
	kept := 0
	if !parentNew {
		for _, u := range units {
			if len(byField[u.Field]) > 0 {
				kept++
			}
		}
	}
	var pending []childUnit
	for _, u := range units {
		if parentNew || len(byField[u.Field]) == 0 {
			pending = append(pending, u)
		}
	}
	room := min(len(pending), max(s.entry.MaxChildren-kept, 0))

	// parentBody is the parent as it stands once created children have a child each.
	parentBody := func(created int, reason childReason) string {
		b := body
		have := map[string]bool{}
		for _, u := range units {
			have[u.Field] = true
		}
		for _, u := range pending[created:] {
			have[u.Field] = false
		}
		b.Actions = nil
		for _, u := range units {
			if !have[u.Field] {
				b.Actions = append(b.Actions, u.Actions...)
			}
		}
		b.Lead = childLead(f, s.entry.Children, kept+created, len(units), reason, s.entry.MaxChildren)
		return b.render(f, t.budget())
	}
	planned := childrenComplete
	if room < len(pending) {
		planned = childrenCapped
	}
	written := parentBody(room, planned)

	var parent trackedItem
	facts := factLabels(s.cfg.LabelBy.Facts(), part)
	if parentNew {
		created, err := t.create(ctx, issueTitle(s.project, s.data.Requested, s.entry, part), written, facts, nil)
		if err != nil {
			return err
		}
		parent = created
		// Children whose parent was closed by hand: each is replaced by a child of the new parent.
		var orphans []trackedItem
		for _, items := range byField {
			orphans = append(orphans, items...)
		}
		if err := closeAll(ctx, t, orphans, closedUntracked,
			"Its parent is closed. A child of "+t.ref(parent.Number)+" replaces it."); err != nil {
			return err
		}
		byField = map[string][]trackedItem{}
	} else {
		parent = fam.parents[0]
		if err := closeAll(ctx, t, fam.parents[1:], closedDuplicate, "Duplicate of "+t.ref(parent.Number)+"."); err != nil {
			return err
		}
	}

	wanted := map[string]bool{}
	for _, u := range units {
		wanted[u.Field] = true
	}
	for _, field := range sortedKeys(byField) {
		if !wanted[field] {
			if err := closeAll(ctx, t, byField[field], closedPassing, goneText(f, field)); err != nil {
				return err
			}
		}
	}
	for _, u := range units {
		items := byField[u.Field]
		if len(items) == 0 {
			continue
		}
		if err := s.keepChild(ctx, part, u, items); err != nil {
			return err
		}
	}

	created := 0
	reason := planned
	for _, u := range pending[:room] {
		if !t.affords(t.childWrites() + reserve) {
			reason = childrenPaced
			break
		}
		if _, err := t.create(ctx, childTitle(u), s.childBody(part, u), childFacts(s.cfg.LabelBy.Facts(), part, u), &parent); err != nil {
			return err
		}
		created++
	}

	final := written
	if created < room {
		final = parentBody(created, reason)
	}
	current := written
	if !parentNew {
		current = parent.Body
	}
	if bodyChanged(f, current, final) {
		if err := t.rewrite(ctx, parent.Number, final); err != nil {
			return err
		}
	}
	if parentNew {
		return nil
	}
	return t.syncLabels(ctx, parent, facts)
}

// keepChild leaves one open child for a unit, rewriting its body when the findings changed and
// its title when its priority did. A title is otherwise left as somebody may have renamed it.
func (s *tracking) keepChild(ctx context.Context, part issuePart, u childUnit, items []trackedItem) error {
	t, f := s.t, s.t.format()
	keep := items[0]
	if err := closeAll(ctx, t, items[1:], closedDuplicate, "Duplicate of "+t.ref(keep.Number)+"."); err != nil {
		return err
	}
	body := s.childBody(part, u)
	if bodyChanged(f, keep.Body, body) {
		if err := t.rewrite(ctx, keep.Number, body); err != nil {
			return err
		}
	}
	if priorityLine(keep.Body) != u.Priority {
		if err := t.retitle(ctx, keep.Number, childTitle(u)); err != nil {
			return err
		}
	}
	return t.syncLabels(ctx, keep, childFacts(s.cfg.LabelBy.Facts(), part, u))
}

// childBody is a child's body: its priority, control and findings, then the action's findings
// table or the control's actions, then the run, how to accept, and when it closes.
func (s *tracking) childBody(part issuePart, u childUnit) string {
	b := newIssueBody(s.data, s.scope, s.entry, part)
	b.Marker = childMarker(b.Marker, u.Field)
	b.Controls, b.Errors, b.Lead = nil, nil, ""
	b.Actions = u.Actions
	head := &childHead{Priority: u.Priority, Control: u.Control, Gate: controlGate(b.Gate, u.Control)}
	for _, a := range u.Actions {
		head.Clears += a.Clears
	}
	if fieldKind(u.Field) == childrenActions {
		head.Action = &u.Actions[0]
	}
	b.Child = head
	return b.render(s.t.format(), s.t.budget())
}

// controlGate is the band one control is judged against: its override, or the gate's own.
func controlGate(g issueGate, control string) string {
	for _, o := range g.Overrides {
		if o.Control == control {
			return o.Band
		}
	}
	return g.Default
}

// priorityLine is the priority a child's body records, or empty when it records none.
func priorityLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if p, ok := strings.CutPrefix(line, priorityPrefix); ok {
			return strings.TrimSuffix(p, " -->")
		}
	}
	return ""
}

// priorityPrefix starts the hidden line that records a child's priority, which is what decides
// whether its title is rewritten.
const priorityPrefix = "<!-- draugr:priority "
