package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

var brokenThreshold = skald.PolicyVerdict{
	Rule: "threshold", Profile: "PCI scope", State: "violates", Mode: "enforce", EnforceFrom: "2026-10-01",
	Response: "fail", InForce: true, Acts: "fail",
	Items: []skald.PolicyItem{
		{Field: "failOn", Found: "P1", Constraint: "required", Expected: "P2 or stricter", Breaks: true},
		{Field: "controls.licenses", Found: "P4", Constraint: "required", Expected: "P3 or stricter", Breaks: true},
	},
}

func TestThePolicyBlockSaysWhetherItRan(t *testing.T) {
	var buf bytes.Buffer
	writePolicy(&buf, tui.Plain(), nil)
	if buf.Len() != 0 {
		t.Errorf("a run asking no server prints no block: %q", buf.String())
	}
	buf.Reset()
	writePolicy(&buf, tui.Plain(), &skald.PolicyCheck{Reason: "no $DRAUGR_API_URL or $DRAUGR_API_TOKEN"})
	if !strings.Contains(buf.String(), "POLICY  not checked · no $DRAUGR_API_URL or $DRAUGR_API_TOKEN") {
		t.Errorf("not checked = %q", buf.String())
	}
	buf.Reset()
	met := skald.PolicyVerdict{Rule: "upgrade", State: "meets"}
	writePolicy(&buf, tui.Plain(), &skald.PolicyCheck{Checked: true, Version: 7, Server: "https://draugr.example",
		Verdicts: []skald.PolicyVerdict{met, met, {Rule: "licenses", State: "not_evaluated"}}})
	if !strings.Contains(buf.String(), "POLICY  version 7 · https://draugr.example · 2 rules checked, none broken") {
		t.Errorf("none broken = %q", buf.String())
	}
}

func TestEachBrokenItemIsARow(t *testing.T) {
	var buf bytes.Buffer
	writePolicy(&buf, tui.Plain(), &skald.PolicyCheck{Checked: true, Version: 7, Verdicts: []skald.PolicyVerdict{brokenThreshold}})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "  threshold  failOn: P1") || !strings.HasPrefix(lines[2], "             controls.licenses: P4") {
		t.Errorf("the rule names its first row only:\n%s", buf.String())
	}
}

func TestThePolicyTableShowsEveryRule(t *testing.T) {
	var buf bytes.Buffer
	asks := skald.PolicyVerdict{Rule: "signers", Profile: "Default", State: "not_applicable", Mode: "observe"}
	WritePolicyTable(&buf, tui.Plain(), &skald.PolicyCheck{Checked: true, Version: 7, Server: "https://draugr.example",
		Verdicts: []skald.PolicyVerdict{brokenThreshold, asks}}, "payments")
	got := buf.String()
	for _, want := range []string{
		"POLICY  payments · version 7 · https://draugr.example",
		"✗ failOn: P1 · required: P2 or stricter",
		"✗ controls.licenses: P4 · required: P3 or stricter",
		"– not applicable",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the table is missing %q:\n%s", want, got)
		}
	}
	buf.Reset()
	WritePolicyTable(&buf, tui.Plain(), &skald.PolicyCheck{Reason: "offline"}, "payments")
	if strings.TrimSpace(buf.String()) != "POLICY  not checked · offline" {
		t.Errorf("not checked = %q", buf.String())
	}
}

// Lines a caller adds sit under the heading, above the table.
func TestThePolicyTableCarriesLinesUnderItsHeading(t *testing.T) {
	var buf bytes.Buffer
	WritePolicyTableWith(&buf, tui.Plain(), &skald.PolicyCheck{Checked: true, Version: 7, Server: "https://draugr.example",
		Verdicts: []skald.PolicyVerdict{brokenThreshold}}, "payments", []string{"  login  ana@acme.com · acme"})
	lines := strings.Split(buf.String(), "\n")
	if lines[0] != "POLICY  payments · version 7 · https://draugr.example" || lines[1] != "  login  ana@acme.com · acme" ||
		!strings.HasPrefix(lines[2], "Rule") {
		t.Errorf("printed:\n%s", buf.String())
	}
}

func TestARefusedRunNamesWhatRefusedIt(t *testing.T) {
	var buf bytes.Buffer
	refused := skald.PolicyVerdict{Rule: "effects", Profile: "Default", State: "violates", Mode: "enforce", EnforceFrom: "2026-10-01",
		Response: "refuse", InForce: true, Acts: "refuse",
		Items: []skald.PolicyItem{{Field: "allowEffects", Found: "mutate", Constraint: "forbidden", Expected: "mutate", Breaks: true}}}
	WritePolicyRefused(&buf, tui.Plain(), "payments", "1.0", &skald.PolicyCheck{Checked: true, Version: 7,
		Verdicts: []skald.PolicyVerdict{refused, brokenThreshold}})
	got := buf.String()
	if !strings.HasPrefix(got, "DRAUGR   REFUSED   payments 1.0") || !strings.Contains(got, "effects  allowEffects: mutate · forbidden: mutate  Default · refuses, since 2026-10-01") ||
		strings.Contains(got, "threshold") || !strings.HasSuffix(got, "No scanner ran.\n") {
		t.Errorf("refused =\n%s", got)
	}
}

// The servers' verdict on the published run covers the descriptor's settings and the findings', so
// where it was decided it is what the block shows. Where it was not, the heading says so.
func TestThePolicyBlockShowsTheRunsVerdict(t *testing.T) {
	descriptor := skald.PolicyVerdict{Rule: "upgrade", State: "meets"}
	licenses := skald.PolicyVerdict{Rule: "licenses", Profile: "Default", State: "violates", Mode: "enforce",
		Response: "fail", InForce: true, Acts: "fail",
		Items: []skald.PolicyItem{{Field: "license", Found: "AGPL-3.0", Constraint: "forbidden", Expected: "AGPL-3.0", Breaks: true}}}
	preflight := func(run *skald.PolicyCheck) *skald.PolicyCheck {
		return &skald.PolicyCheck{Checked: true, Version: 7, Server: "https://draugr.example", Outcome: "none",
			Verdicts: []skald.PolicyVerdict{descriptor, {Rule: "licenses", State: "not_evaluated"}}, Run: run}
	}
	render := func(p *skald.PolicyCheck) string {
		var buf bytes.Buffer
		writePolicy(&buf, tui.Plain(), p)
		return strings.TrimSpace(buf.String())
	}
	cases := []struct {
		name string
		run  *skald.PolicyCheck
		want []string
	}{
		{"decided, and failing", &skald.PolicyCheck{Checked: true, Version: 8, Server: "https://draugr.example", Outcome: "fail",
			Verdicts: []skald.PolicyVerdict{descriptor, licenses}},
			[]string{"POLICY  version 8 · https://draugr.example", "  licenses  license: AGPL-3.0 · forbidden: AGPL-3.0  Default · fails the gate"}},
		{"decided, and passing", &skald.PolicyCheck{Checked: true, Version: 8, Server: "https://draugr.example", Outcome: "none",
			Verdicts: []skald.PolicyVerdict{descriptor, {Rule: "licenses", State: "meets"}}},
			[]string{"POLICY  version 8 · https://draugr.example · 2 rules checked, none broken"}},
		{"the wait ran out", &skald.PolicyCheck{Checked: true, Pending: true, Version: 8, Server: "https://draugr.example", Outcome: "none",
			Verdicts: []skald.PolicyVerdict{descriptor, {Rule: "licenses", State: "not_evaluated", Pending: true}}},
			[]string{"POLICY  version 8 · https://draugr.example · not decided within --policy-wait"}},
		{"not checked", &skald.PolicyCheck{Server: "https://draugr.example", Reason: "401 Unauthorized"},
			[]string{"POLICY  version 7 · https://draugr.example · run not checked · 401 Unauthorized"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := render(preflight(c.run))
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, "none broken") && (c.run.Pending || !c.run.Checked) {
				t.Errorf("a verdict not decided reads as a pass:\n%s", got)
			}
		})
	}
}
