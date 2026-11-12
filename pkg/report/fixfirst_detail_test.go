package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/tui"
)

const privilegedSentence = "Container 'api' of Pod 'demo-api' should set 'securityContext.privileged' to false"

// The rule's title takes the line under the id and the sentence goes beneath it, whole where it fits.
// Where it does not, its end survives, because the setting is at the end and the object is on the
// row's location.
func TestAFindingShowsTheScannersSentenceBeneathItsTitle(t *testing.T) {
	f := finding{priority: "P1", ruleID: "KSV-0017", message: "Privileged", detail: privilegedSentence}
	var wide, narrow bytes.Buffer
	writeBlockHead(&wide, tui.Plain(), f, 160)
	if got, want := wide.String(), "  P1            KSV-0017\n      Privileged\n      "+privilegedSentence+"\n"; got != want {
		t.Errorf("wide = %q\nwant %q", got, want)
	}
	writeBlockHead(&narrow, tui.Plain(), f, 60)
	got := narrow.String()
	if !strings.Contains(got, "'securityContext.privileged' to false") || !strings.Contains(got, "…") {
		t.Errorf("narrow lost the setting: %q", got)
	}
	var plain bytes.Buffer
	writeBlockHead(&plain, tui.Plain(), finding{priority: "P1", ruleID: "DS-1", message: "A title"}, 160)
	if got, want := plain.String(), "  P1            DS-1\n      A title\n"; got != want {
		t.Errorf("a finding with no sentence: %q, want %q", got, want)
	}
}

// A message holding one long token keeps as much of the token as fits, because the token is usually
// what the message is there to say.
func TestElideKeepsALongTokenRatherThanTheWordsBeforeIt(t *testing.T) {
	msg := "Signed by chainguard-images/images/.github/workflows/release.yaml@refs/heads/main, not our-ci."
	if got, want := elide(msg, 40), "Signed by chainguard-images/images/.git…"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := elide("a short sentence with several ordinary words in it", 30), "a short sentence with…"; got != want {
		t.Errorf("a boundary late in the line is still where it cuts: got %q, want %q", got, want)
	}
	if got := elide("Signé par ééééééééééééééééééééééééééééééééééééééééééé", 20); !utf8.ValidString(got) {
		t.Errorf("cut inside a character: %q", got)
	}
}

func TestElideFront(t *testing.T) {
	for _, c := range []struct {
		msg   string
		width int
		want  string
	}{
		{"short enough", 40, "short enough"},
		{"one two three four", 12, "…three four"},
		{"unbroken", 4, "…ken"},
		{"anything", 1, "anything"},
	} {
		if got := elideFront(c.msg, c.width); got != c.want {
			t.Errorf("elideFront(%q, %d) = %q, want %q", c.msg, c.width, got, c.want)
		}
	}
}

// An action covers every finding of a rule, so it says one sentence and how many others differ. The same
// sentence on two components is one change, and a finding with no sentence adds nothing to count.
func TestAnActionSaysOneSentenceAndHowManyDiffer(t *testing.T) {
	for _, c := range []struct {
		name string
		fs   []finding
		want string
	}{
		{"one", []finding{{detail: "A"}}, "A"},
		{"the same twice", []finding{{detail: "A"}, {detail: "A"}}, "A"},
		{"two others", []finding{{detail: "A"}, {detail: "B"}, {detail: "C"}, {detail: "B"}}, "A · +2 more"},
		{"one with none", []finding{{detail: "A"}, {}}, "A"},
		{"none", []finding{{}}, ""},
		{"nothing", nil, ""},
	} {
		if got := occurrenceSummary(action{findings: c.fs}); got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
	if got := summaryFor(action{title: "Fix KSV-0017 “Privileged”", findings: []finding{{detail: "A"}}}); got != "A" {
		t.Errorf("a quoted title with a sentence = %q", got)
	}
}
