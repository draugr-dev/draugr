package saga

import (
	"strings"
	"testing"
)

// fragmentWithSigners builds a fragment carrying one signer under a name, the shape yaml.v3
// decodes a control block into.
func fragmentWithSigners(source string, names ...string) Fragment {
	signers := make([]any, 0, len(names))
	for _, n := range names {
		signers = append(signers, map[string]any{"name": n})
	}
	return Fragment{
		Source: source,
		Config: FragmentConfig{Controls: map[string]ControllerSettings{
			"provenance": {"signers": signers},
		}},
	}
}

// signerNames reads back what a merged model holds, so a test asserts on the descriptor rather
// than on the merge's internals.
func signerNames(t *testing.T, m *Model) []string {
	t.Helper()
	raw, ok := m.Config.Controls["provenance"]["signers"].([]any)
	if !ok {
		t.Fatalf("provenance.signers is %T, want a list", m.Config.Controls["provenance"]["signers"])
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		out = append(out, s.(map[string]any)["name"].(string))
	}
	return out
}

// Two fragments, not one. One proves the fold runs; two prove it does not collapse, which is the
// bug this merge would have: a second fragment's signers replacing the first's leaves a descriptor
// checking less than it says, and nothing about the run looks wrong.
func TestTwoFragmentsBothContributeSigners(t *testing.T) {
	t.Parallel()
	model := &Model{Config: Config{Controls: map[string]ControllerSettings{
		"provenance": {"signers": []any{map[string]any{"name": "our-ci"}}},
	}}}

	Merge(model, fragmentWithSigners("org.saga-fragment.yaml", "chainguard"))
	Merge(model, fragmentWithSigners("team.saga-fragment.yaml", "base-images", "cache-ci"))

	got := signerNames(t, model)
	want := []string{"our-ci", "chainguard", "base-images", "cache-ci"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("signers = %v, want %v, the descriptor's first and each fragment's after it", got, want)
	}
}

// A descriptor declaring none is still a descriptor with the fragment's, rather than one where the
// absent key swallowed them.
func TestAFragmentSuppliesSignersToADescriptorWithNone(t *testing.T) {
	t.Parallel()
	model := &Model{}
	Merge(model, fragmentWithSigners("org.saga-fragment.yaml", "chainguard"))
	if got := signerNames(t, model); len(got) != 1 || got[0] != "chainguard" {
		t.Errorf("signers = %v, want the fragment's", got)
	}
}

// What makes carrying the setting in a fragment safe: a reviewer can find out which file expects
// an identity nobody reading the descriptor declared.
func TestEachContributingFragmentIsNamed(t *testing.T) {
	t.Parallel()
	model := &Model{}
	Merge(model, fragmentWithSigners("org.saga-fragment.yaml", "chainguard"))
	Merge(model, fragmentWithSigners("team.saga-fragment.yaml", "cache-ci"))

	got := model.Config.ControlSources["provenance.signers"]
	if len(got) != 2 || got[0] != "org.saga-fragment.yaml" || got[1] != "team.saga-fragment.yaml" {
		t.Errorf("sources = %v, want both fragments named in the order they merged", got)
	}
}

// A surveyor builds a fragment in memory with no file behind it, and an empty source would read as
// a contribution from a file called "".
func TestAFragmentWithNoFileContributesNoSource(t *testing.T) {
	t.Parallel()
	model := &Model{}
	Merge(model, fragmentWithSigners("", "chainguard"))
	if len(model.Config.ControlSources) != 0 {
		t.Errorf("sources = %v, want none for a fragment with no file", model.Config.ControlSources)
	}
	if got := signerNames(t, model); len(got) != 1 {
		t.Errorf("signers = %v, want the fragment's to merge anyway", got)
	}
}

// The refusals, each naming what it refused and what is allowed instead. A reader hitting one has
// usually just copied a working block out of their own descriptor, so "unknown field" would be
// both wrong and unhelpful.
func TestAFragmentIsRefusedWhatItMayNotCarry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		controls map[string]ControllerSettings
		want     string
	}{
		{
			"a control not on the list",
			map[string]ControllerSettings{"sca": {"enabled": true}},
			"may not configure `sca`",
		},
		{
			"switching the control off",
			map[string]ControllerSettings{"provenance": {"enabled": false}},
			"may not set `provenance.enabled`",
		},
		{
			"changing what is trusted",
			map[string]ControllerSettings{"provenance": {"trustRoot": "/tmp/roots.json"}},
			"may not set `provenance.trustRoot`",
		},
		{
			"deciding what an uncovered image is worth",
			map[string]ControllerSettings{"provenance": {"unmatched": "fail"}},
			"may not set `provenance.unmatched`",
		},
		{
			"a value that would answer over the descriptor rather than add to it",
			map[string]ControllerSettings{"provenance": {"signers": "our-ci"}},
			"must be a list",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := Fragment{Config: FragmentConfig{Controls: c.controls}}.Validate()
			if err == nil {
				t.Fatalf("accepted %v", c.controls)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to contain %q", err, c.want)
			}
		})
	}
}

// The refusal names what is allowed instead, and today that is one key. Exercised at the lengths
// the list will reach rather than the length it currently has, because the sentence a reader gets
// is the thing under test and it changes shape with the count.
func TestTheRefusalListsWhatIsAllowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		keys []string
		want string
	}{
		{nil, "nothing"},
		{[]string{"a"}, "`a`"},
		{[]string{"a", "b"}, "`a` and `b`"},
		{[]string{"a", "b", "c"}, "`a`, `b` and `c`"},
	}
	for _, c := range cases {
		if got := joinKeyed(c.keys); got != c.want {
			t.Errorf("joinKeyed(%v) = %q, want %q", c.keys, got, c.want)
		}
	}
}

// The allowlist is what the schema is generated from, so an empty answer for a control nobody
// listed is the property the generator relies on.
func TestOnlyListedControlsAreOffered(t *testing.T) {
	t.Parallel()
	if got := FragmentControls(); len(got) != 1 || got[0] != "provenance" {
		t.Errorf("controls = %v, want provenance alone until another passes the test", got)
	}
	if got := FragmentControlOptionsFor("provenance"); len(got) != 1 || got[0] != "signers" {
		t.Errorf("provenance options = %v, want signers alone", got)
	}
	if got := FragmentControlOptionsFor("sca"); len(got) != 0 {
		t.Errorf("sca options = %v, want none: a control says nothing in a fragment by default", got)
	}
}
