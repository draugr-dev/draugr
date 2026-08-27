package saga

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The reason is optional. A rule with nothing to say is written without one and is complete.
func TestReasonedWithoutAReason(t *testing.T) {
	t.Parallel()

	var got struct {
		Exposure Reasoned[Exposure] `yaml:"exposure"`
	}
	if err := yaml.Unmarshal([]byte("exposure:\n  value: public\n"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Exposure.Value != ExposurePublic {
		t.Errorf("value = %q, want %q", got.Exposure.Value, ExposurePublic)
	}
	if got.Exposure.Reason != "" || got.Exposure.WrittenShort() {
		t.Errorf("got %+v, want a rule with no reason and not the older shape", got.Exposure)
	}
}

// The shape a rule had before it could carry a reason still loads until the removal date, and
// says so — an upgrade that stopped every existing pipeline on the same afternoon would be a
// worse answer than a date somebody can plan around.
func TestReasonedAcceptsTheOlderShapeAndSaysSo(t *testing.T) {
	t.Parallel()

	var got struct {
		Exposure Reasoned[Exposure] `yaml:"exposure"`
	}
	if err := yaml.Unmarshal([]byte("exposure: public\n"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Exposure.Value != ExposurePublic || !got.Exposure.WrittenShort() {
		t.Errorf("got %+v, want the value read and the older shape recorded", got.Exposure)
	}
}

func TestReasonedWithAReason(t *testing.T) {
	t.Parallel()

	const src = `
exposure:
  value: public
  reason: >-
    The binary is downloadable and runnable by anyone, no sign-in.
`
	var got struct {
		Exposure Reasoned[Exposure] `yaml:"exposure"`
	}
	if err := yaml.Unmarshal([]byte(src), &got); err != nil {
		t.Fatal(err)
	}
	if got.Exposure.Value != ExposurePublic {
		t.Errorf("value = %q, want %q", got.Exposure.Value, ExposurePublic)
	}
	if !strings.HasPrefix(got.Exposure.Reason, "The binary is downloadable") {
		t.Errorf("reason = %q, want the argument that was written", got.Exposure.Reason)
	}
}

// A rule somebody believes is in force and is not is the failure this refuses. Each of these is
// a way of writing one, and each has to be named rather than ignored.
func TestReasonedRejectsWhatCannotBeActedOn(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, src, want string
	}{
		{"an unknown key", "exposure:\n  value: public\n  why: because\n", `unknown key "why"`},
		{"no value", "exposure:\n  reason: because\n", "no `value`"},
		{"neither shape", "exposure: [public]\n", "expected a mapping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got struct {
				Exposure Reasoned[Exposure] `yaml:"exposure"`
			}
			err := yaml.Unmarshal([]byte(tc.src), &got)
			if err == nil {
				t.Fatalf("accepted %q, which says nothing a reader can act on", tc.src)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A wrong type inside the long form is the scanner's own decoding error, still attributed to the
// key it came from rather than surfacing as a bare type mismatch.
func TestReasonedReportsABadValueByItsKey(t *testing.T) {
	t.Parallel()

	var got struct {
		Exposure Reasoned[Exposure] `yaml:"exposure"`
	}
	err := yaml.Unmarshal([]byte("exposure:\n  value: [public]\n  reason: because\n"), &got)
	if err == nil || !strings.Contains(err.Error(), "value:") {
		t.Fatalf("error = %v, want it to name the value", err)
	}
	err = yaml.Unmarshal([]byte("exposure:\n  value: public\n  reason: [because]\n"), &got)
	if err == nil || !strings.Contains(err.Error(), "reason:") {
		t.Fatalf("error = %v, want it to name the reason", err)
	}
}

// The digest a run publishes is taken over these bytes, so what a rule marshals to has to be
// what was read — with the reason when there is one, and without it when there is not.
func TestReasonedRoundTripsToWhatWasWritten(t *testing.T) {
	t.Parallel()

	for _, src := range []string{
		"exposure:\n    value: public\n",
		"exposure:\n    value: public\n    reason: Downloadable by anyone.\n",
	} {
		var got struct {
			Exposure Reasoned[Exposure] `yaml:"exposure"`
		}
		if err := yaml.Unmarshal([]byte(src), &got); err != nil {
			t.Fatal(err)
		}
		out, err := yaml.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != src {
			t.Errorf("round trip of %q gave %q", src, out)
		}
	}
}

// A rule nobody wrote must not appear in the descriptor as one somebody deliberately cleared.
func TestReasonedOmitsWhatWasNeverSet(t *testing.T) {
	t.Parallel()

	out, err := yaml.Marshal(struct {
		Exposure Reasoned[Exposure] `yaml:"exposure,omitempty"`
		Name     string             `yaml:"name"`
	}{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "exposure") {
		t.Errorf("marshaled an unset rule: %q", out)
	}
}

func TestReasonedHelpers(t *testing.T) {
	t.Parallel()

	if r := Unstated(ExposurePublic); r.Value != ExposurePublic || r.Reason != "" || r.String() != "public" {
		t.Errorf("Unstated = %+v", r)
	}
	if r := Stated(ExposurePublic, "anyone can reach it"); r.Reason != "anyone can reach it" {
		t.Errorf("Stated = %+v", r)
	}
	if !(Reasoned[Exposure]{}).IsZero() || (Unstated(ExposurePublic)).IsZero() {
		t.Error("IsZero disagrees with what omitempty needs")
	}
}

// The notice has to name every rule written the older way, found by walking the model — a rule
// added later would otherwise be missing from it, and the first anybody would hear is the
// release that stops loading their descriptor.
func TestRuleDeprecationsNamesEveryOlderRule(t *testing.T) {
	t.Parallel()

	const src = `
project: p
release:
  version: "1"
config:
  gate:
    failOnPriority: P1
    controls:
      licenses: critical
components:
  - name: api
    exposure: public
    criticality:
      value: critical
      reason: it holds the payment path
  - name: web
    exposure:
      value: internal
`
	m, err := Load([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := RuleDeprecations(m)
	// Only the three written as bare values. components[0].criticality and components[1].exposure
	// are written as rules and must not appear.
	want := []string{"components[0].exposure", "config.gate.controls.licenses", "config.gate.failOnPriority"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("RuleDeprecations = %v, want %v", got, want)
	}

	// And the descriptor still loads, with the values read.
	if m.Components[0].Exposure.Value != ExposurePublic || m.Config.Gate.FailOnPriority.Value != "P1" {
		t.Errorf("the older shape should still load: %+v", m.Components[0].Exposure)
	}

	// The notice carries the removal date and the shape to write instead.
	notices := strings.Join(m.Deprecations(), "\n")
	for _, want := range []string{"components[0].exposure", RuleShapeRemoval, "`value:`", "`reason:`"} {
		if !strings.Contains(notices, want) {
			t.Errorf("the notice should mention %q:\n%s", want, notices)
		}
	}
}

// What Draugr writes back is the shape a rule has now, whichever shape it read — so a descriptor
// that round-trips through the plane stops carrying the older one.
func TestRuleDeprecationsDoNotSurviveAMarshal(t *testing.T) {
	t.Parallel()

	m, err := Load([]byte("project: p\nrelease:\n  version: \"1\"\ncomponents:\n  - name: api\n    exposure: public\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "exposure:\n            value: public") &&
		!strings.Contains(string(out), "value: public") {
		t.Errorf("marshaled to something other than a rule:\n%s", out)
	}
	again, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := RuleDeprecations(again); len(got) != 0 {
		t.Errorf("still reports the older shape after a round trip: %v", got)
	}
}
