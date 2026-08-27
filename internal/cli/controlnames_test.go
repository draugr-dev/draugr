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
			Gate: &saga.GateConfig{Controls: map[string]saga.Reasoned[string]{"secrets": saga.Unstated("error")}},
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
				Gate: &saga.GateConfig{Controls: map[string]saga.Reasoned[string]{"iaac": saga.Unstated("error")}}}},
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
		Gate:        &saga.GateConfig{Controls: map[string]saga.Reasoned[string]{"iaac": saga.Unstated("error")}},
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
	if got := nearestName("iaac", known); got != "iac" {
		t.Errorf("nearestName(iaac) = %q, want iac", got)
	}
	if got := nearestName("SCAA", known); got != "sca" {
		t.Errorf("case should not defeat the suggestion: %q", got)
	}
	// A name with nothing close gets no suggestion. Pointing somewhere wrong is worse than
	// pointing nowhere — the reader trusts it and edits the wrong line.
	for _, wild := range []string{"kubernetes-posture", "zzzzzzzz", ""} {
		if got := nearestName(wild, known); got != "" {
			t.Errorf("nearestName(%q) guessed %q", wild, got)
		}
	}
}

func TestCheckControlNamesEmptyModel(t *testing.T) {
	if err := checkControlNames(builtins.Registry(), &saga.Model{}); err != nil {
		t.Errorf("a descriptor naming no controls is not wrong: %v", err)
	}
}

func TestCheckControlNamesRejectsUnknownScannerKeys(t *testing.T) {
	// A key naming no scanner, accepted and ignored, is how a descriptor that disables a scanner
	// runs it anyway. Rejecting any wrong key — for any reason — is also what makes per-rename
	// migration entries unnecessary: every one of them says what the control actually accepts.
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"headers": {"enabled": true, "httpHeaders": saga.ControllerSettings{"enabled": false}},
	}}}
	err := checkControlNames(builtins.Registry(), m)
	if err == nil {
		t.Fatal("a key naming no scanner was accepted")
	}
	for _, want := range []string{"httpHeaders", "not a scanner", "draugrHeaders"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestCheckControlNamesAcceptsRealScannerKeys(t *testing.T) {
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"headers":        {"enabled": true, "draugrHeaders": saga.ControllerSettings{"enabled": false}},
		"sast":           {"semgrep": saga.ControllerSettings{"config": "p/default"}, "gosec": saga.ControllerSettings{"enabled": true}},
		"infrastructure": {"draugrK8sPolicies": saga.ControllerSettings{"enabled": true}},
	}}}
	if err := checkControlNames(builtins.Registry(), m); err != nil {
		t.Errorf("rejected valid scanner keys: %v", err)
	}
}

func TestCheckControlNamesIgnoresScalarOptions(t *testing.T) {
	// A scalar under a control is a control-level option, not a scanner block, and this check
	// has no opinion about it.
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"enabled": true, "forbidden": []any{"GPL-3.0-only"}, "threshold": "warn"},
	}}}
	if err := checkControlNames(builtins.Registry(), m); err != nil {
		t.Errorf("a scalar option was treated as a scanner: %v", err)
	}
}

func TestCheckControlNamesChecksComponentScannerKeys(t *testing.T) {
	m := &saga.Model{Components: []saga.Component{{
		Name:        "web",
		Controllers: map[string]saga.ControllerSettings{"tls": {"tlsProbe": saga.ControllerSettings{"enabled": true}}},
	}}}
	err := checkControlNames(builtins.Registry(), m)
	if err == nil {
		t.Fatal("a component's own block went unchecked")
	}
	if !strings.Contains(err.Error(), "draugrTls") {
		t.Errorf("error should name the real key: %v", err)
	}
}

func TestCheckControlNamesRejectsAnOptionTheScannerDoesNotTake(t *testing.T) {
	// The engine checks this too, when it plans the run — but by then the descriptor has passed
	// `draugr validate`, been merged, and is failing in a pipeline. Validate is the cheap place.
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"secrets": {"enabled": true, "gitleaks": saga.ControllerSettings{"severity": "high"}},
	}}}
	err := checkControlNames(builtins.Registry(), m)
	if err == nil {
		t.Fatal("an option gitleaks does not read was accepted")
	}
	for _, want := range []string{"gitleaks", `"severity"`, "controls --options"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
}

func TestCheckControlNamesRejectsAWrongTypedOption(t *testing.T) {
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"tls": {"draugrTls": saga.ControllerSettings{"expiryWarnDays": "thirty"}},
	}}}
	err := checkControlNames(builtins.Registry(), m)
	if err == nil {
		t.Fatal("a string where an integer belongs was accepted")
	}
	if !strings.Contains(err.Error(), "expiryWarnDays") {
		t.Errorf("error should name the option: %v", err)
	}
}

func TestCheckControlNamesAcceptsDeclaredOptionsAndTheEnabledFlag(t *testing.T) {
	// `enabled` is the reserved flag, not one of the scanner's own options: a schema with
	// additionalProperties:false would reject it if it reached the validator.
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"tls":      {"draugrTls": saga.ControllerSettings{"enabled": true, "expiryWarnDays": 21}},
		"licenses": {"trivyLicense": saga.ControllerSettings{"deny": []any{map[string]any{"id": "AGPL-3.0-only"}}}},
	}}}
	if err := checkControlNames(builtins.Registry(), m); err != nil {
		t.Errorf("rejected a valid block: %v", err)
	}
}

func TestReachabilityAnalyzerInAScannerBlockSaysWhereItGoes(t *testing.T) {
	// Names something real, in the wrong place. "not a scanner" would send the reader hunting a
	// typo they did not make.
	model := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"sca": {"govulncheck": saga.ControllerSettings{"enabled": true}},
	}}}
	err := checkControlNames(builtins.Registry(), model)
	if err == nil {
		t.Fatal("want an error for an analyzer named as a scanner")
	}
	for _, want := range []string{"decides reachability", "config.reachability", "analyzers: [govulncheck]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestUnknownReachabilityAnalyzerIsRejected(t *testing.T) {
	// A descriptor saying findings will be ranked by reachability, that silently are not, is the
	// same failure as naming a control this build cannot run.
	model := &saga.Model{Config: saga.Config{
		Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulnchek"}},
	}}
	err := checkControlNames(builtins.Registry(), model)
	if err == nil {
		t.Fatal("want an error for an analyzer this build does not have")
	}
	if !strings.Contains(err.Error(), "did you mean \"govulncheck\"?") {
		t.Errorf("error %q does not suggest the near miss", err)
	}
}

func TestKnownReachabilityAnalyzerIsAccepted(t *testing.T) {
	model := &saga.Model{Config: saga.Config{
		Reachability: &saga.ReachabilityConfig{Analyzers: []string{"govulncheck"}},
	}}
	if err := checkControlNames(builtins.Registry(), model); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
}

// A control's own options are where a policy is written, and they reach a scanner only after the
// controller has resolved them. An entry the controller could not read is simply not in the list
// by then: a policy quietly one license shorter, with a passing validate behind it.
func TestCheckControlNamesChecksTheControlsOwnPolicy(t *testing.T) {
	entry := func(kv map[string]any) *saga.Model {
		return &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
			"licenses": {"enabled": true, "deny": []any{kv}},
		}}}
	}

	err := checkControlNames(builtins.Registry(), entry(map[string]any{
		"id": "AGPL-3.0-only", "reasn": "we ship binaries",
	}))
	if err == nil {
		t.Fatal("a misspelled key inside a license entry was accepted")
	}
	if !strings.Contains(err.Error(), `unknown option "reasn"`) {
		t.Errorf("error should name the key: %v", err)
	}

	// The reason is optional: an entry with nothing to add is complete.
	if err := checkControlNames(builtins.Registry(), entry(map[string]any{"id": "AGPL-3.0-only"})); err != nil {
		t.Errorf("rejected an entry with no reason: %v", err)
	}

	// The shape a rule had before it could carry one is refused here rather than dropped later.
	bare := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"enabled": true, "deny": []any{"SSPL-1.0"}},
	}}}
	if err := checkControlNames(builtins.Registry(), bare); err == nil {
		t.Error("a bare identifier reaches the controller as an entry it cannot read, and the policy is one license shorter")
	}

	ok := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"enabled": true, "deny": []any{
			map[string]any{"id": "SSPL-1.0"},
			map[string]any{"id": "AGPL-3.0-only", "reason": "we ship binaries to customers"},
		}},
	}}}
	if err := checkControlNames(builtins.Registry(), ok); err != nil {
		t.Errorf("rejected a valid policy: %v", err)
	}
}

// Each scanner of a control is asked, and a reader with one thing to fix is told once.
func TestCheckControlNamesReportsOnePolicyProblemOnce(t *testing.T) {
	m := &saga.Model{Config: saga.Config{Controllers: map[string]saga.ControllerSettings{
		"licenses": {"enabled": true, "deny": []any{map[string]any{"id": "AGPL-3.0-only", "reasn": "typo"}}},
	}}}
	err := checkControlNames(builtins.Registry(), m)
	if err == nil {
		t.Fatal("expected the entry to be reported")
	}
	if got := strings.Count(err.Error(), `unknown option "reasn"`); got != 1 {
		t.Errorf("reported %d times, want once — trivy-license and mend-licenses both declare deny", got)
	}
}
