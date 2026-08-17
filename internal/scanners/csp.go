package scanners

import (
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// cspPolicy is a parsed Content-Security-Policy: directive name (lower-cased) to its source
// list, with each source kept as written because case matters inside a nonce or a hash.
type cspPolicy map[string][]string

// parseCSP splits a policy into directives. Malformed input yields whatever could be read
// rather than an error: a policy the browser will partially apply is a policy worth judging,
// and refusing to look at it would report nothing about a header that is doing something.
func parseCSP(policy string) cspPolicy {
	out := cspPolicy{}
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		// A repeated directive is ignored by browsers after the first, so the first wins here
		// too — reporting on a list the browser discarded would describe a policy nobody has.
		if _, seen := out[name]; seen {
			continue
		}
		out[name] = fields[1:]
	}
	return out
}

// fetchDirectiveFallback lists the directives that inherit from default-src when absent.
//
// base-uri and frame-ancestors are deliberately not here: they are not fetch directives and do
// **not** fall back, which is the CSP subtlety that most often leaves a policy weaker than its
// author believes.
var fetchDirectiveFallback = map[string]bool{
	"script-src": true, "style-src": true, "img-src": true, "object-src": true,
	"connect-src": true, "font-src": true, "media-src": true, "frame-src": true,
	"worker-src": true, "manifest-src": true, "child-src": true,
}

// effective returns the sources a directive resolves to, following the default-src fallback
// where the directive takes one. The second value reports whether anything governs it at all.
func (p cspPolicy) effective(name string) ([]string, bool) {
	if v, ok := p[name]; ok {
		return v, true
	}
	if fetchDirectiveFallback[name] {
		if v, ok := p["default-src"]; ok {
			return v, true
		}
	}
	return nil, false
}

// has reports whether a source list contains a keyword, case-insensitively.
func hasSource(sources []string, want string) bool {
	for _, s := range sources {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// hasNonceOrHash reports whether the list carries a nonce or an integrity hash — the two things
// that make 'unsafe-inline' inert in a CSP3 browser.
func hasNonceOrHash(sources []string) bool {
	for _, s := range sources {
		v := strings.ToLower(strings.Trim(s, "'"))
		if strings.HasPrefix(v, "nonce-") || strings.HasPrefix(v, "sha256-") ||
			strings.HasPrefix(v, "sha384-") || strings.HasPrefix(v, "sha512-") {
			return true
		}
	}
	return false
}

// broadSources returns the entries that let a policy load script from anywhere in practice: the
// wildcard, and bare schemes. Sorted, so the message is stable across runs.
//
// A wildcard host (*.example.com) is deliberately not one of them: it is a decision about one
// domain someone already controls, not the open door this check is for.
func broadSources(sources []string) []string {
	var out []string
	for _, s := range sources {
		switch strings.ToLower(s) {
		case "*", "http:", "https:", "data:", "blob:":
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// evaluateCSP judges a Content-Security-Policy's content, not merely its presence.
//
// A CSP of `default-src *; script-src 'unsafe-inline' 'unsafe-eval'` satisfies a presence check
// and stops almost nothing, so "has a CSP" is not a security statement on its own.
//
// Two CSP3 rules decide whether a weakness is real, and getting them wrong is how a checker
// becomes noise: a nonce or a hash makes 'unsafe-inline' inert, and 'strict-dynamic' makes host
// and scheme sources inert. Both are how a *good* policy is written, so reporting them as flaws
// would penalize exactly the people who did the work.
func evaluateCSP(policy string, add func(ruleID, message string, level sarif.Level)) {
	p := parseCSP(policy)

	script, governed := p.effective("script-src")
	strictDynamic := hasSource(script, "'strict-dynamic'")

	switch {
	case !governed:
		// No script-src and no default-src: scripts load from anywhere. Nothing else in the
		// policy compensates for that.
		add("headers/csp-script-src-missing",
			"Content-Security-Policy has neither 'script-src' nor a 'default-src' fallback, so scripts "+
				"may load from anywhere. Add \"script-src 'self'\" at minimum.",
			sarif.LevelError)
	default:
		if hasSource(script, "'unsafe-eval'") {
			add("headers/csp-unsafe-eval",
				"Content-Security-Policy allows 'unsafe-eval' in script-src, which permits eval() and "+
					"string-to-code conversion — a common path from an injection to running code. Remove it "+
					"and replace the code that needs it.",
				sarif.LevelError)
		}
		if hasSource(script, "'unsafe-inline'") {
			// Inert when a nonce, a hash, or 'strict-dynamic' is present: browsers ignore it,
			// and it is there as a fallback for ones that do not understand the rest.
			if hasNonceOrHash(script) || strictDynamic {
				add("headers/csp-unsafe-inline-legacy-fallback",
					"Content-Security-Policy lists 'unsafe-inline' in script-src, but a nonce, hash or "+
						"'strict-dynamic' is also present, so browsers ignore it. It is doing nothing except "+
						"weakening the policy for browsers too old to understand the rest.",
					sarif.LevelNote)
			} else {
				add("headers/csp-unsafe-inline",
					"Content-Security-Policy allows 'unsafe-inline' in script-src, so an injected <script> tag "+
						"or event handler runs — which is most of what a CSP is for. Use a nonce or a hash "+
						"per script instead.",
					sarif.LevelError)
			}
		}
		if broad := broadSources(script); len(broad) > 0 && !strictDynamic {
			add("headers/csp-script-src-broad",
				fmt.Sprintf("Content-Security-Policy allows script from %s in script-src, which lets an "+
					"attacker host the payload anywhere that matches. Name the origins you actually load "+
					"script from, or use a nonce with 'strict-dynamic'.", strings.Join(broad, ", ")),
				sarif.LevelError)
		}
	}

	// object-src governs <object>, <embed> and <applet>, a plugin-shaped route to script
	// execution that script-src does not cover.
	//
	// Graded rather than flat: a policy inheriting "object-src 'self'" from default-src is
	// already same-origin, which is a different risk from one that governs objects not at all.
	// Reporting both at the same severity would tell a reader the two are equivalent.
	obj, objGoverned := p.effective("object-src")
	switch {
	case !objGoverned || len(broadSources(obj)) > 0:
		add("headers/csp-object-src-broad",
			"Content-Security-Policy leaves <object> and <embed> able to load from anywhere — a route to "+
				"script execution that script-src does not cover. Add \"object-src 'none'\"; almost no site "+
				"needs plugins.",
			sarif.LevelWarning)
	case !hasSource(obj, "'none'"):
		add("headers/csp-object-src-not-none",
			"Content-Security-Policy restricts <object> and <embed> but does not disable them. "+
				"\"object-src 'none'\" is the recommended value and almost no site needs plugins.",
			sarif.LevelNote)
	}

	// base-uri does not fall back to default-src. Without it, injected markup can repoint
	// relative script URLs at an attacker's host, which defeats an origin allowlist entirely.
	if _, ok := p["base-uri"]; !ok {
		add("headers/csp-base-uri-missing",
			"Content-Security-Policy does not set 'base-uri', and it does not inherit from default-src. "+
				"An injected <base> tag can then repoint every relative script URL. Add \"base-uri 'none'\" "+
				"or \"base-uri 'self'\".",
			sarif.LevelWarning)
	}

	// default-src is what governs every fetch directive nobody listed. Without it the policy
	// only covers what it names, and the next resource type added to the page is unprotected.
	if _, ok := p["default-src"]; !ok {
		add("headers/csp-default-src-missing",
			"Content-Security-Policy has no 'default-src', so any resource type it does not name is "+
				"unrestricted. Add \"default-src 'self'\" as the floor and narrow from there.",
			sarif.LevelNote)
	}

	if _, uri := p["report-uri"]; !uri {
		if _, to := p["report-to"]; !to {
			add("headers/csp-no-reporting",
				"Content-Security-Policy has no 'report-uri' or 'report-to', so violations are invisible. "+
					"Reporting is how you find out the policy is blocking something legitimate — or that "+
					"someone is trying something.",
				sarif.LevelNote)
		}
	}
}
