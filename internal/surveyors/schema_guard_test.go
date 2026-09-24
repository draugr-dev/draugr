package surveyors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEverySurveyorsOutputIsHeldToTheSchema requires each surveyor's tests to pass the fragment it
// writes through sagatest.FragmentAccepted.
//
// A surveyor writes the descriptor somebody pastes in, so what it emits is held to the schema an
// editor uses and to the loader, as the examples are. A new surveyor with no such check could
// write a field the schema refuses, and nothing would notice until an editor underlined it.
func TestEverySurveyorsOutputIsHeldToTheSchema(t *testing.T) {
	survey := regexp.MustCompile(`(?m)^func \([a-z]+ \*?[A-Z]\w*\) Survey\(`)
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, src := range sources {
		if strings.HasSuffix(src, "_test.go") {
			continue
		}
		body, err := os.ReadFile(src) // #nosec G304 -- a file in this package
		if err != nil {
			t.Fatal(err)
		}
		if !survey.Match(body) {
			continue
		}
		checked++
		test := strings.TrimSuffix(src, ".go") + "_test.go"
		tb, err := os.ReadFile(test) // #nosec G304 -- this surveyor's own test file
		if err != nil || !strings.Contains(string(tb), "sagatest.FragmentAccepted(t, frag)") {
			t.Errorf("%s writes a descriptor fragment, and %s does not hold it to the schema: "+
				"call sagatest.FragmentAccepted(t, frag) on the fragment a successful Survey returns", src, test)
		}
	}
	if checked < 6 {
		t.Fatalf("found %d surveyors; the pattern has stopped matching their Survey methods", checked)
	}
}
