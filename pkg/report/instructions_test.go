package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A title has one line, so a sentence too long for it loses its end, which is where it says what to do.
// A row can stand for many lines, so a sentence pointing at "this" one is wrong about the rest.
func TestAnInstructionFitsATitleAndReadsOverManyLines(t *testing.T) {
	for rule, sentence := range ruleInstruction {
		if n := utf8.RuneCountInString(sentence); n > actionTitleWidth {
			t.Errorf("%s: %d characters, over %d: %q", rule, n, actionTitleWidth, sentence)
		}
		if strings.Contains(strings.ToLower(sentence), "this ") {
			t.Errorf("%s: says this: %q", rule, sentence)
		}
		if strings.HasSuffix(sentence, ".") {
			t.Errorf("%s: a title takes no full stop: %q", rule, sentence)
		}
	}
}

func TestALineTakesAnInstructionFromTheRuleThatTitlesIt(t *testing.T) {
	f := finding{control: "sast", ruleID: "G104", location: "a.go:1", message: "Errors unhandled"}
	title, summary := lineTitle([]finding{f})
	if title != "Handle the returned error" || summary != "" {
		t.Errorf("title %q, summary %q", title, summary)
	}
}

// Two rules about one flaw read alike, whichever of them ranks first on the line.
func TestALineTakesAnInstructionFromAnyRuleOnIt(t *testing.T) {
	semgrep := finding{control: "sast", ruleID: "go.lang.security.unlisted.unlisted", location: "a.go:1",
		priority: "P1", message: "Checks for disabling of TLS/SSL certificate verification"}
	gosec := finding{control: "sast", ruleID: "G402", location: "a.go:1", priority: "P2", message: "TLS InsecureSkipVerify set to true."}
	if got, also := instructionFor([]finding{semgrep, gosec}); got != ruleInstruction["G402"] || also != "" {
		t.Errorf("got %q, also %q", got, also)
	}
	if got, _ := instructionFor(nil); got != "" {
		t.Errorf("no findings: got %q", got)
	}
	if got, _ := instructionFor([]finding{semgrep}); got != "" {
		t.Errorf("no rule with an instruction: got %q", got)
	}
}

// Handling the error leaves the response unescaped, so a row saying only that would claim to clear a
// finding it does not.
func TestALineAskingForTwoChangesNamesBoth(t *testing.T) {
	gosec := finding{control: "sast", ruleID: "G104", location: "a.go:1", priority: "P1"}
	semgrep := finding{control: "sast", ruleID: "go.lang.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter",
		location: "a.go:1", priority: "P3"}
	title, summary := lineTitle([]finding{gosec, semgrep})
	if title != ruleInstruction["G104"] || summary != "Also: "+ruleInstruction["no-direct-write-to-responsewriter"] {
		t.Errorf("title %q, summary %q", title, summary)
	}

	// Two rules asking for one change say it once.
	md5 := finding{control: "sast", ruleID: "G501", location: "a.go:1", priority: "P1"}
	same := finding{control: "sast", ruleID: "G401", location: "a.go:1", priority: "P2"}
	if _, also := instructionFor([]finding{md5, same}); also != "" {
		t.Errorf("also %q", also)
	}
}

// Semgrep names its rules by a dotted path, and the table by the last part of it.
func TestAnInstructionIsFoundByTheRulesShortName(t *testing.T) {
	f := finding{control: "sast", location: ".github/ci.yaml:3",
		ruleID: "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"}
	if got := findingInstruction(f); got != "Pin actions to a full commit SHA" {
		t.Errorf("got %q", got)
	}
}

// The table is about a flagged line. A rule of the same name elsewhere groups on the rule and is titled
// as it always was.
func TestAFindingOffALineHasNoInstruction(t *testing.T) {
	if got := findingInstruction(finding{control: "iac", ruleID: "privileged-container", location: "a.yaml:1"}); got != "" {
		t.Errorf("another control: got %q", got)
	}
	if got := findingInstruction(finding{control: "sast", ruleID: "G104", location: "a.go"}); got != "" {
		t.Errorf("no line: got %q", got)
	}
}
