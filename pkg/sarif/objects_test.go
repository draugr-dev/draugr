package sarif

import (
	"slices"
	"testing"
)

// TestObjectsSurviveTheFile is the round trip for the objects a finding standing for a set of them
// lists. `draugr diff` reads them from the file to tell a check that gained an object from one that
// was fixed, so a report read back has to carry them as the run did, each on its own finding.
func TestObjectsSurviveTheFile(t *testing.T) {
	t.Parallel()
	in := Report{Results: []Result{{
		// Nothing but the objects, so the property bag is written for them alone.
		RuleID: "draugr/cis/5.2.2", Level: LevelError,
		Message:  "2 running privileged: apps/a/app, apps/b/app",
		Location: Location{URI: "kubernetes/prod"},
		Objects:  []string{"apps/a/app", "apps/b/app"},
	}, {
		RuleID: "draugr/cis/5.2.2", Level: LevelError,
		Message:  "1 running privileged: apps/c/app",
		Location: Location{URI: "kubernetes/staging"},
		Objects:  []string{"apps/c/app"},
	}, {
		RuleID: "G101", Level: LevelWarning, Message: "hardcoded credential",
		Location: Location{URI: "main.go", StartLine: 3},
	}}}
	data, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 3 {
		t.Fatalf("read back %d results, wrote 3", len(out.Results))
	}
	for i, want := range [][]string{{"apps/a/app", "apps/b/app"}, {"apps/c/app"}, nil} {
		if got := out.Results[i].Objects; !slices.Equal(got, want) {
			t.Errorf("result %d objects = %v, want %v", i, got, want)
		}
	}
}
