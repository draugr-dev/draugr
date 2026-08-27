package saga

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The short form is the common case and has to stay exactly as cheap to write as it was.
func TestReasonedShortForm(t *testing.T) {
	t.Parallel()

	var got struct {
		Exposure Reasoned[Exposure] `yaml:"exposure"`
	}
	if err := yaml.Unmarshal([]byte("exposure: public\n"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Exposure.Value != ExposurePublic {
		t.Errorf("value = %q, want %q", got.Exposure.Value, ExposurePublic)
	}
	if got.Exposure.Reason != "" {
		t.Errorf("reason = %q, want none", got.Exposure.Reason)
	}
}

func TestReasonedLongForm(t *testing.T) {
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
		{"no reason", "exposure:\n  value: public\n", "no `reason`"},
		{"a blank reason", "exposure:\n  value: public\n  reason: \"   \"\n", "no `reason`"},
		{"neither form", "exposure: [public]\n", "expected a value or a mapping"},
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

// The digest a run publishes is taken over these bytes. A field changing shape in Go must not
// move it for every descriptor that never used the long form.
func TestReasonedRoundTripsToWhatWasWritten(t *testing.T) {
	t.Parallel()

	for _, src := range []string{
		"exposure: public\n",
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
