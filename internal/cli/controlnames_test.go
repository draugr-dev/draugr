package cli

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestCheckControlNamesAcceptsWhatIsRegistered(t *testing.T) {
	reg := builtins.Registry()
	m := &saga.Model{
		Config: saga.Config{
			Controllers: map[string]saga.ControllerSettings{
				"sca": {"enabled": true}, "licenses": {"enabled": true},
				"infrastructure": {"enabled": true},
			},
			// A threshold for a control that is not enabled here is fine: a descriptor may be
			// shared, and the name is real either way.
			Gate: &saga.GateConfig{Controls: map[string]string{"secrets": "error"}},
		},
		Components: []saga.Component{
			{Name: "app", Controllers: map[string]saga.ControllerSettings{"iac": {"enabled": true}}},
		},
	}
	if err := checkControlNames(reg, m); err != nil {
		t.Errorf("rejected a valid descriptor: %v", err)
	}
}

func TestCheckControlNamesRejectsTypos(t *testing.T) {
	reg := builtins.Registry()
	cases := []struct {
		name  string
		model *saga.Model
		where string
	}{
		{
			"config.controllers",
			&saga.Model{Config: saga.Config{
				Controllers: map[string]saga.ControllerSettings{"scaa": {"enabled": true}}}},
			"config.controllers",
		},
		{
			"config.gate.controls",
			&saga.Model{Config: saga.Config{
				Gate: &saga.GateConfig{Controls: map[string]string{"iaac": "error"}}}},
			"config.gate.controls",
		},
		{
			"per-component controllers",
			&saga.Model{Components: []saga.Component{
				{Name: "web", Controllers: map[string]saga.ControllerSettings{"secrit": {"enabled": true}}}}},
			`components["web"].controllers`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkControlNames(reg, c.model)
			if err == nil {
				t.Fatal("accepted a control name that does not exist")
			}
			if !strings.Contains(err.Error(), c.where) {
				t.Errorf("error does not say where: %v", err)
			}
			// The suggestion is most of the value: without it the reader is scanning a list.
			if !strings.Contains(err.Error(), "did you mean") {
				t.Errorf("no suggestion offered: %v", err)
			}
			if !strings.Contains(err.Error(), "draugr controls") {
				t.Errorf("does not say how to see the real list: %v", err)
			}
		})
	}
}

func TestCheckControlNamesReportsEveryMistake(t *testing.T) {
	// One per re-run would make fixing three typos a three-round trip.
	m := &saga.Model{Config: saga.Config{
		Controllers: map[string]saga.ControllerSettings{"scaa": {}, "imagez": {}},
		Gate:        &saga.GateConfig{Controls: map[string]string{"iaac": "error"}},
	}}
	err := checkControlNames(builtins.Registry(), m)
	if err == nil {
		t.Fatal("accepted three bad names")
	}
	for _, want := range []string{"scaa", "imagez", "iaac"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q not reported: %v", want, err)
		}
	}
}

func TestNearestControlDoesNotGuessWildly(t *testing.T) {
	known := map[string]bool{}
	for _, c := range builtins.Registry().Controllers() {
		known[c.Info().Name] = true
	}
	if got := nearestControl("iaac", known); got != "iac" {
		t.Errorf("nearestControl(iaac) = %q, want iac", got)
	}
	if got := nearestControl("SCAA", known); got != "sca" {
		t.Errorf("case should not defeat the suggestion: %q", got)
	}
	// A name with nothing close gets no suggestion. Pointing somewhere wrong is worse than
	// pointing nowhere — the reader trusts it and edits the wrong line.
	for _, wild := range []string{"kubernetes-posture", "zzzzzzzz", ""} {
		if got := nearestControl(wild, known); got != "" {
			t.Errorf("nearestControl(%q) guessed %q", wild, got)
		}
	}
}

func TestCheckControlNamesEmptyModel(t *testing.T) {
	if err := checkControlNames(builtins.Registry(), &saga.Model{}); err != nil {
		t.Errorf("a descriptor naming no controls is not wrong: %v", err)
	}
}
