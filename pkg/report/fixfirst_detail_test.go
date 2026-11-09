package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/tui"
)

const privilegedSentence = "Container 'api' of Pod 'demo-api' should set 'securityContext.privileged' to false"

// The rule's title stays on the row and the sentence goes beneath it, whole where it fits. Where it does
// not, its end survives, because the setting is at the end and the object is on the row's location.
func TestAFindingShowsTheScannersSentenceBeneathItsTitle(t *testing.T) {
	f := finding{priority: "P1", ruleID: "KSV-0017", message: "Privileged", detail: privilegedSentence}
	var wide, narrow bytes.Buffer
	writeBlockHead(&wide, tui.Plain(), f, 160)
	if got := wide.String(); !strings.Contains(got, "KSV-0017 · Privileged\n") || !strings.Contains(got, "      "+privilegedSentence+"\n") {
		t.Errorf("wide = %q", got)
	}
	writeBlockHead(&narrow, tui.Plain(), f, 60)
	got := narrow.String()
	if !strings.Contains(got, "'securityContext.privileged' to false") || !strings.Contains(got, "…") {
		t.Errorf("narrow lost the setting: %q", got)
	}
	var plain bytes.Buffer
	writeBlockHead(&plain, tui.Plain(), finding{priority: "P1", ruleID: "DS-1", message: "A title"}, 160)
	if strings.Count(plain.String(), "\n") != 1 {
		t.Errorf("a finding with no sentence took a second line: %q", plain.String())
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
