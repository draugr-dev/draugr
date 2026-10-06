package skald

import (
	"fmt"
	"strings"
)

// PolicyOutcome is what an organization's policy makes of one run, or of one descriptor before its
// run, as a draugr-api server answers it.
//
// The server judges and words every part of it. Draugr holds no rule logic: it renders the items
// and terms it is given and acts on Outcome, so a rule the organization changes reaches every
// client without a release, and two versions of Draugr cannot disagree about one.
type PolicyOutcome struct {
	// Schema is the shape's version. A field added beside the rest does not raise it.
	Schema int `json:"schema"`
	// Project is the project the token belongs to, whose policy this is.
	Project string `json:"project,omitempty"`
	// PolicyVersion is the version of the organization's policy judged against, 0 where nothing is
	// written down.
	PolicyVersion int `json:"policyVersion"`
	// Paused says an organization-wide pause stood, so no setting acted.
	Paused bool `json:"paused,omitempty"`
	// Outcome is the strongest act among the verdicts: refuse, then fail, then none.
	Outcome  string          `json:"outcome"`
	Passed   bool            `json:"passed"`
	Verdicts []PolicyVerdict `json:"verdicts,omitempty"`
}

// The acts a policy verdict, and so an outcome, can have.
const (
	PolicyNone   = "none"
	PolicyFail   = "fail"
	PolicyRefuse = "refuse"
)

// PolicyVerdict is one rule under one profile, judged.
type PolicyVerdict struct {
	Rule    string `json:"rule"`
	Profile string `json:"profile"`
	// State is violates, meets, not_evaluated or not_applicable. Words for the API only: a reader is
	// shown a mark and the items.
	State string `json:"state"`
	// Detail says, for a violation, how many items break, and for a verdict not evaluated, what
	// was missing.
	Detail string `json:"detail,omitempty"`
	// Items are what the verdict checked, broken ones first, a passing verdict's as well.
	Items []PolicyItem `json:"items,omitempty"`
	// Mode, EnforceFrom and Response are the setting's own terms.
	Mode        string `json:"mode,omitempty"`
	EnforceFrom string `json:"enforceFrom,omitempty"`
	Response    string `json:"response,omitempty"`
	// ProfileState is active, or observing where the setting observes whatever its mode.
	ProfileState string `json:"profileState,omitempty"`
	// Override names what made an enforce setting observe: profile-observing or paused.
	Override string `json:"override,omitempty"`
	// InForce says the setting acts: enforced, its date reached, the profile active, no pause.
	InForce bool `json:"inForce,omitempty"`
	// Acts is what the verdict does to the run: refuse, fail or none.
	Acts string `json:"acts,omitempty"`
	// Pending marks, on a publish answer, a setting in force that is decided once the run's
	// evidence is expanded, after the answer.
	Pending bool `json:"pending,omitempty"`
}

// PolicyItem is one thing a verdict checked.
type PolicyItem struct {
	Field      string `json:"field"`
	Found      string `json:"found"`
	Constraint string `json:"constraint"`
	Expected   string `json:"expected"`
	Breaks     bool   `json:"breaks,omitempty"`
}

// String is the item as every surface shows it: `failOn: P1 · required: P2 or stricter`.
func (i PolicyItem) String() string {
	return fmt.Sprintf("%s: %s · %s: %s", i.Field, i.Found, i.Constraint, i.Expected)
}

// Violates reports whether the run or descriptor breaks the setting.
func (v PolicyVerdict) Violates() bool { return v.State == "violates" }

// Evaluated reports whether the verdict could be judged: it either holds or is broken.
func (v PolicyVerdict) Evaluated() bool { return v.State == "violates" || v.State == "meets" }

// Term is what the setting does to a run that breaks it, in the phrases every surface uses:
// `observed`, `fails the gate, since 2026-10-01`, `refuses from 2026-12-01`,
// `observed, profile observing`.
func (v PolicyVerdict) Term() string {
	switch v.Override {
	case "profile-observing":
		return "observed, profile observing"
	case "paused":
		return "observed, enforcement paused"
	}
	if v.Mode != "enforce" {
		return "observed"
	}
	if v.ProfileState == "observing" {
		return "observed, profile observing"
	}
	var act string
	switch v.Response {
	case PolicyFail:
		act = "fails the gate"
	case PolicyRefuse:
		act = "refuses"
	case "strip":
		act = "removes the addresses"
	default:
		act = v.Response
	}
	if v.EnforceFrom == "" {
		return act
	}
	if v.InForce {
		return act + ", since " + v.EnforceFrom
	}
	return act + " from " + v.EnforceFrom
}

// Breaking is the verdict's broken items, or every item where none is marked.
func (v PolicyVerdict) Breaking() []PolicyItem {
	var out []PolicyItem
	for _, i := range v.Items {
		if i.Breaks {
			out = append(out, i)
		}
	}
	if len(out) == 0 {
		return v.Items
	}
	return out
}

// PolicyCheck is what a run's pre-flight learned of the organization's policy, as report.json
// records it.
type PolicyCheck struct {
	// Server is the endpoint the policy came from.
	Server string `json:"server,omitempty"`
	// Checked says the server answered. A run that could not ask says why in Reason.
	Checked bool   `json:"checked"`
	Reason  string `json:"reason,omitempty"`
	// Version is the policy version the descriptor was judged against.
	Version  int             `json:"version,omitempty"`
	Outcome  string          `json:"outcome,omitempty"`
	Verdicts []PolicyVerdict `json:"verdicts,omitempty"`
}

// Strongest is the stronger of two acts: refuse, then fail, then none.
func Strongest(a, b string) string {
	rank := map[string]int{PolicyNone: 0, "": 0, PolicyFail: 1, PolicyRefuse: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// Summary is the outcome's broken verdicts as one line each, for an error message.
func (p PolicyOutcome) Summary(act string) string {
	var lines []string
	for _, v := range p.Verdicts {
		if v.Acts != act {
			continue
		}
		for _, i := range v.Breaking() {
			lines = append(lines, fmt.Sprintf("%s %s (%s · %s)", v.Rule, i, v.Profile, v.Term()))
		}
	}
	return strings.Join(lines, "; ")
}
