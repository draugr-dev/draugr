package scanners

import (
	"sort"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// findCSP runs the analyzer and returns the rule ids it produced, sorted.
func findCSP(policy string) []string {
	var ids []string
	evaluateCSP(policy, func(ruleID, _ string, _ sarif.Level) {
		ids = append(ids, ruleID)
	})
	sort.Strings(ids)
	return ids
}

// hasCSPRule reports whether ids contains want.
func hasCSPRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestCSPParse(t *testing.T) {
	p := parseCSP("default-src 'self';script-src 'self' 'unsafe-inline' ;  ; OBJECT-SRC 'none'")
	if got := p["default-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Errorf("default-src = %v", got)
	}
	if got := p["script-src"]; len(got) != 2 {
		t.Errorf("script-src = %v", got)
	}
	// Directive names are case-insensitive; source values are not, because a nonce is a value.
	if _, ok := p["object-src"]; !ok {
		t.Error("uppercase directive name was not normalized")
	}
	// An empty segment is not a directive.
	if len(p) != 3 {
		t.Errorf("parsed %d directives, want 3: %v", len(p), p)
	}
}

func TestCSPRepeatedDirectiveTakesTheFirst(t *testing.T) {
	// Browsers ignore a repeated directive after the first. Reporting on the later one would
	// describe a policy nobody is running.
	p := parseCSP("script-src 'self'; script-src 'unsafe-inline'")
	if got := p["script-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Errorf("script-src = %v, want the first occurrence", got)
	}
}

func TestCSPDefaultSrcFallback(t *testing.T) {
	p := parseCSP("default-src 'self'")

	// A fetch directive inherits.
	if got, ok := p.effective("script-src"); !ok || got[0] != "'self'" {
		t.Errorf("script-src did not inherit from default-src: %v %v", got, ok)
	}
	// base-uri and frame-ancestors do not. This is the subtlety that leaves policies weaker
	// than their authors believe, so it is the one most worth pinning.
	if _, ok := p.effective("base-uri"); ok {
		t.Error("base-uri inherited from default-src; it does not")
	}
	if _, ok := p.effective("frame-ancestors"); ok {
		t.Error("frame-ancestors inherited from default-src; it does not")
	}
}

func TestCSPFlagsRealWeaknesses(t *testing.T) {
	// The issue's example: passes a presence check, stops almost nothing.
	ids := findCSP("default-src *; script-src 'unsafe-inline' 'unsafe-eval'")
	for _, want := range []string{
		"headers/csp-unsafe-inline",
		"headers/csp-unsafe-eval",
		"headers/csp-object-src-broad",
		"headers/csp-base-uri-missing",
	} {
		if !hasCSPRule(ids, want) {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
}

func TestCSPBroadScriptSources(t *testing.T) {
	for _, policy := range []string{
		"script-src *",
		"script-src https:",
		"script-src 'self' data:",
	} {
		if !hasCSPRule(findCSP(policy), "headers/csp-script-src-broad") {
			t.Errorf("%q was not reported as broad", policy)
		}
	}
	// A wildcard host is a deliberate decision about one domain, not an open door.
	if hasCSPRule(findCSP("script-src 'self' *.example.com"), "headers/csp-script-src-broad") {
		t.Error("a wildcard subdomain was reported as an open door")
	}
}

func TestCSPNonceMakesUnsafeInlineInert(t *testing.T) {
	// CSP3: a nonce or hash makes 'unsafe-inline' ignored. It is how a good policy stays
	// compatible with old browsers, so reporting it as a flaw would penalize the people who
	// did the work.
	for _, policy := range []string{
		"script-src 'nonce-abc123' 'unsafe-inline'",
		"script-src 'sha256-abc' 'unsafe-inline'",
		"script-src 'strict-dynamic' 'nonce-abc' 'unsafe-inline'",
	} {
		ids := findCSP(policy)
		if hasCSPRule(ids, "headers/csp-unsafe-inline") {
			t.Errorf("%q: reported an inert 'unsafe-inline' as a real one", policy)
		}
		if !hasCSPRule(ids, "headers/csp-unsafe-inline-legacy-fallback") {
			t.Errorf("%q: said nothing at all; the reader should know it is doing nothing", policy)
		}
	}
}

func TestCSPStrictDynamicMakesHostSourcesInert(t *testing.T) {
	// 'strict-dynamic' causes host and scheme sources to be ignored, so a policy carrying them
	// alongside it is not permissive — it is being compatible.
	ids := findCSP("script-src 'strict-dynamic' 'nonce-abc' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'")
	if hasCSPRule(ids, "headers/csp-script-src-broad") {
		t.Errorf("reported host sources that strict-dynamic makes inert: %v", ids)
	}
}

func TestCSPUngovernedScript(t *testing.T) {
	// Neither script-src nor default-src: scripts load from anywhere, and nothing else in the
	// policy compensates.
	ids := findCSP("style-src 'self'")
	if !hasCSPRule(ids, "headers/csp-script-src-missing") {
		t.Errorf("a policy that does not govern script was not reported: %v", ids)
	}
}

func TestCSPObjectSrcGrading(t *testing.T) {
	// Inheriting 'self' is a real restriction, and a different risk from none at all. Reporting
	// both the same way would tell the reader they are equivalent.
	ids := findCSP("default-src 'self'")
	if !hasCSPRule(ids, "headers/csp-object-src-not-none") {
		t.Errorf("inherited object-src should still be noted: %v", ids)
	}
	if hasCSPRule(ids, "headers/csp-object-src-broad") {
		t.Errorf("inherited 'self' reported as broad: %v", ids)
	}

	ids = findCSP("default-src *")
	if !hasCSPRule(ids, "headers/csp-object-src-broad") {
		t.Errorf("ungoverned objects not reported as broad: %v", ids)
	}
}

func TestCSPCompletePolicyIsQuiet(t *testing.T) {
	// The shape we tell people to write. If this produces findings, the checks are advice
	// nobody can satisfy.
	ids := findCSP("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; " +
		"frame-ancestors 'none'; report-uri /csp-report")
	if len(ids) != 0 {
		t.Errorf("a complete policy produced findings: %v", ids)
	}
}

func TestCSPMessagesSayWhatToChange(t *testing.T) {
	// A finding that names a problem without naming a fix is a finding someone has to research
	// before they can act on it.
	var msgs []string
	evaluateCSP("default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
		func(_, message string, _ sarif.Level) { msgs = append(msgs, message) })
	if len(msgs) == 0 {
		t.Fatal("no findings")
	}
	for _, m := range msgs {
		if !strings.ContainsAny(m, "'\"") {
			t.Errorf("message names no concrete value to set: %q", m)
		}
	}
}

func TestCSPSeverityReflectsRisk(t *testing.T) {
	levels := map[string]sarif.Level{}
	evaluateCSP("default-src *; script-src 'unsafe-inline'",
		func(ruleID, _ string, level sarif.Level) { levels[ruleID] = level })

	// An injected <script> running is materially different from no reporting endpoint.
	if levels["headers/csp-unsafe-inline"] != sarif.LevelError {
		t.Errorf("unsafe-inline = %v, want error", levels["headers/csp-unsafe-inline"])
	}
	if levels["headers/csp-no-reporting"] != sarif.LevelNote {
		t.Errorf("no-reporting = %v, want note", levels["headers/csp-no-reporting"])
	}
}

func TestCSPMalformedInputIsStillJudged(t *testing.T) {
	// A browser applies what it can parse. Refusing to look would report nothing about a header
	// that is doing something.
	if ids := findCSP(";;; script-src   'unsafe-eval' ;;"); !hasCSPRule(ids, "headers/csp-unsafe-eval") {
		t.Errorf("malformed policy was not judged: %v", ids)
	}
	if ids := findCSP(""); len(ids) == 0 {
		t.Error("an empty policy should still report that nothing governs script")
	}
}
