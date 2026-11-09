package report

import (
	"maps"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// A title has one line, so a sentence too long for it loses its end, which is where it says what to do.
// A row can stand for many lines, so a sentence pointing at "this" one is wrong about the rest.
func TestAnInstructionFitsATitleAndReadsOverManyLines(t *testing.T) {
	every := maps.Clone(ruleInstruction)
	maps.Copy(every, reasonedInstruction)
	maps.Copy(every, cloudInstruction)
	for rule, sentence := range every {
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

// A rule's own row takes the instruction as its title and keeps the scanner's sentence as the reason,
// and the rule's name moves to a line of its own, because the title no longer carries it.
func TestARuleRowTakesItsInstructionAndKeepsItsReason(t *testing.T) {
	const message = "Missing Content-Security-Policy: add a CSP to mitigate XSS and content-injection."
	f := finding{control: "headers", ruleID: "headers/csp-missing", location: "https://example.test/", message: message, tool: "draugr-headers"}
	a := action{byRule: true, title: titleFor(f), findings: []finding{f}}
	if a.title != "Add a Content-Security-Policy header" {
		t.Fatalf("title %q", a.title)
	}
	if got := summaryFor(a); got != "Missing Content-Security-Policy: add a CSP to mitigate XSS and content-injection" {
		t.Errorf("summary %q", got)
	}
	if !a.titleHidesRule() {
		t.Error("the row should give the rule a line of its own")
	}
	if ref := actionRef(tui.Plain(), a); ref != "" {
		t.Errorf("the rule is named twice: %q", ref)
	}
}

// A sentence that only restates the instruction is left out.
func TestARuleRowDropsASentenceThatRepeatsItsInstruction(t *testing.T) {
	f := finding{control: "tls", ruleID: "tls-no-tls13", location: "https://example.test/", message: "TLS 1.3 is not accepted. It is faster."}
	a := action{byRule: true, title: titleFor(f), findings: []finding{f}}
	if a.title != "Turn on TLS 1.3" {
		t.Fatalf("title %q", a.title)
	}
	if got := summaryFor(a); got != "" {
		t.Errorf("summary %q, want none", got)
	}
}

// A sentence can hold the fact the instruction leaves out, so it stays where each host says its own.
func TestARuleRowKeepsASentenceHoldingAValue(t *testing.T) {
	f := finding{control: "tls", ruleID: "tls-cert-expiring", location: "https://example.test/", message: "Certificate expires in 8 days, on 2026-11-16. Renew it before it lapses."}
	a := action{byRule: true, title: titleFor(f), findings: []finding{f}}
	if a.title != "Renew the certificate" {
		t.Fatalf("title %q", a.title)
	}
	if got := summaryFor(a); !strings.Contains(got, "2026-11-16") {
		t.Errorf("summary %q lost the date", got)
	}
}

// A rule with no entry keeps its name as its title, its sentence, and its name where it was.
func TestARuleWithNoInstructionKeepsItsRow(t *testing.T) {
	f := finding{control: "dast", ruleID: "tech-detect", location: "https://example.test/", message: "Wappalyzer Technology Detection"}
	a := action{byRule: true, title: titleFor(f), findings: []finding{f}}
	if a.title != "Fix tech-detect" || a.titleHidesRule() {
		t.Errorf("title %q, hides rule %v", a.title, a.titleHidesRule())
	}
}

// A line of code takes the same reason, unless another rule on it asks for something else: then the
// line beneath says what else to do.
func TestALineKeepsItsReasonUnlessAnotherRuleAsksForMore(t *testing.T) {
	user := finding{control: "sast", ruleID: "dockerfile.security.missing-user.missing-user", location: "Dockerfile:9", message: "By not specifying a USER, a program may run as 'root'."}
	title, summary := lineTitle([]finding{user})
	if title != "Set a non-root USER in the Dockerfile" || !strings.Contains(summary, "USER") {
		t.Errorf("title %q, summary %q", title, summary)
	}
	debug := finding{control: "sast", ruleID: "debug-enabled", location: "app.py:9", message: "Detected Flask app with debug=True."}
	host := finding{control: "sast", ruleID: "avoid_app_run_with_bad_host", location: "app.py:9", message: "Running flask app with host 0.0.0.0."}
	title, summary = lineTitle([]finding{debug, host})
	if title != "Bind a specific host unless the server must be reachable from outside" || summary != "Also: Turn off debug mode outside development" {
		t.Errorf("title %q, summary %q", title, summary)
	}
}

// withoutReasonedInstructions empties reasonedInstruction for one test, for a test about what a row reads
// when its rule has no entry. A rule's name is easier to read in a fixture than a made-up one, and this
// keeps such a test from changing when the rule gains an instruction.
func withoutReasonedInstructions(t *testing.T) {
	t.Helper()
	saved := reasonedInstruction
	reasonedInstruction = map[string]string{}
	t.Cleanup(func() { reasonedInstruction = saved })
}
