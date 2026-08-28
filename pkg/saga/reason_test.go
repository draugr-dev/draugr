package saga

import (
	"os"
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
	if got.Exposure.Reason != "" {
		t.Errorf("got %+v, want a rule with no reason", got.Exposure)
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
		// The shape a rule had before it could carry a reason, shown the two lines that replace
		// it — "expected a mapping" sends somebody to the schema to work out which one.
		{"the value on its own", "exposure: public\n", "value: public"},
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

// The older shape is refused wherever a rule appears, not only on a component — a descriptor
// half-converted is the case somebody actually hits, and finding out one key at a time is worse
// than being told on the first.
func TestOlderShapeIsRefusedAtEveryRule(t *testing.T) {
	t.Parallel()

	for _, src := range []string{
		"project: p\nrelease:\n  version: \"1\"\nconfig:\n  gate:\n    failOnPriority: P1\n",
		"project: p\nrelease:\n  version: \"1\"\nconfig:\n  gate:\n    controls:\n      licenses: critical\n",
		"project: p\nrelease:\n  version: \"1\"\ncomponents:\n  - name: api\n    exposure: public\n",
		"project: p\nrelease:\n  version: \"1\"\ncomponents:\n  - name: api\n    criticality: critical\n",
	} {
		if _, err := Load([]byte(src)); err == nil {
			t.Errorf("loaded a rule written as a bare value:\n%s", src)
		} else if !strings.Contains(err.Error(), "value:") {
			t.Errorf("error should show what to write instead: %v", err)
		}
	}
}

// The descriptor this repository scans itself with is the one that should demonstrate the point:
// the arguments for its classification were comments, and a comment does not survive being
// merged and re-serialized.
func TestSelfDescriptorStatesItsReasons(t *testing.T) {
	t.Parallel()

	b, err := os.ReadFile("../../.draugr/self.saga.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Load(b)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Components[0]
	if c.Exposure.Reason == "" || c.Criticality.Reason == "" {
		t.Errorf("%s: classification with no argument attached — exposure %q, criticality %q",
			c.Name, c.Exposure.Reason, c.Criticality.Reason)
	}
}
