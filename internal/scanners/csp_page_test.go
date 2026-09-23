package scanners

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// pageFindings runs the page check and returns rule id -> message.
func pageFindings(t *testing.T, policy string, reportOnly bool, page string) map[string]string {
	t.Helper()
	got := map[string]string{}
	evaluatePage(policy, reportOnly, readPage(mustURL(t, "https://app.example.com/"), []byte(page)),
		func(ruleID, message string, level sarif.Level) {
			if level != sarif.LevelNote {
				t.Errorf("%s is %s; a page the policy breaks must not fail a security gate", ruleID, level)
			}
			got[ruleID] = message
		})
	return got
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
}

func TestReadPageRecordsWhatThePageRunsAndLoads(t *testing.T) {
	page := `<html><head>
<base href="https://cdn.example.net/assets/">
<script type="application/ld+json">{"@type":"Thing"}</script>
<script nonce="abc">boot()</script>
<script src="app.js" integrity="sha384-xyz"></script>
<link rel="stylesheet" href="site.css">
<link rel="preload" as="font" href="/f.woff2">
<link rel="modulepreload" as="script" href="m.js">
<link rel="preload" as="image" href="hero.png">
<link rel="preload" as="style" href="p.css">
<link rel="icon" href="favicon.ico">
<style>body{color:red}</style>
</head><body>
<button onclick="go()" style="color:blue">Go</button>
<a href="javascript:void(0)">x</a>
<img src="a.png" srcset="b.png 1x, c.png 2x">
</body></html>`
	pc := readPage(mustURL(t, "https://app.example.com/"), []byte(page))

	if len(pc.inlineScripts) != 1 || pc.inlineScripts[0].nonce != "abc" {
		t.Errorf("inline scripts = %+v; a JSON data block is not a script", pc.inlineScripts)
	}
	if len(pc.inlineStyles) != 1 || len(pc.styleAttrs) != 1 {
		t.Errorf("styles = %d blocks, %d attributes", len(pc.inlineStyles), len(pc.styleAttrs))
	}
	var where []string
	for _, h := range pc.handlers {
		where = append(where, h.where)
	}
	if strings.Join(where, "|") != "onclick on <button>|javascript: link on <a>" {
		t.Errorf("handlers = %v", where)
	}
	kinds := map[string][]string{}
	for _, l := range pc.loads {
		kinds[l.kind] = append(kinds[l.kind], l.url.String())
	}
	if got := kinds["script"]; len(got) != 2 || got[0] != "https://cdn.example.net/assets/app.js" {
		t.Errorf("scripts = %v; relative references resolve against <base>", got)
	}
	if got := kinds["image"]; len(got) != 4 {
		t.Errorf("images = %v; src, both srcset candidates and the preload", got)
	}
	if len(kinds["stylesheet"]) != 2 || len(kinds["font"]) != 1 {
		t.Errorf("loads = %v; an icon is not governed by anything read here", kinds)
	}
}

// The scripts a strict policy is written to allow must not be reported. Getting this wrong
// reports the pages of the people who did the work.
func TestAPageThePolicyAllowsReportsNothing(t *testing.T) {
	inline := "boot()"
	page := `<script nonce="n1">x()</script><script>` + inline + `</script>
<script src="/app.js"></script><script src="https://cdn.example.net/lib.js" nonce="n1"></script>
<img src="data:image/png;base64,AAAA"><img src="//img.example.org/a.png">
<link rel="stylesheet" href="https://fonts.example.com/css"><button style="x" onclick="go()">`
	policy := "default-src 'self'; script-src 'self' 'nonce-n1' " + sha(inline) +
		"; img-src 'self' data: *.example.org; style-src 'self' https://fonts.example.com 'unsafe-inline'; " +
		"script-src-attr 'unsafe-inline'"
	if got := pageFindings(t, policy, false, page); len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
}

func TestAPageThePolicyBreaksIsReported(t *testing.T) {
	page := `<script>a()</script><script>b()</script><button onclick="go()">
<script src="https://static.example-analytics.com/beacon.js"></script>
<script src="https://cdn.other.net/x.js"></script>
<img src="https://img.example.org/a.png"><style>p{}</style>
<link rel="stylesheet" href="https://fonts.example.com/css">
<link rel="preload" as="font" href="https://fonts.example.com/f.woff2">`
	got := pageFindings(t, "default-src 'self'; script-src 'self' 'nonce-zzz' 'unsafe-inline'", false, page)

	if m := got["headers/csp-blocks-inline-script"]; !strings.Contains(m, "blocks 2 inline scripts") {
		t.Errorf("inline script = %q; a nonce makes 'unsafe-inline' inert", m)
	}
	if m := got["headers/csp-blocks-inline-handler"]; !strings.Contains(m, "onclick on <button>") {
		t.Errorf("handler = %q", m)
	}
	m := got["headers/csp-blocks-script-origin"]
	for _, want := range []string{"https://cdn.other.net, https://static.example-analytics.com", "Add the origin to script-src"} {
		if !strings.Contains(m, want) {
			t.Errorf("script origin = %q; want %q", m, want)
		}
	}
	// No img-src: default-src governs, and the advice names it rather than a directive whose
	// addition would stop the fallback.
	if m := got["headers/csp-blocks-image-origin"]; !strings.Contains(m, "Add the origin to default-src") {
		t.Errorf("image origin = %q", m)
	}
	for _, rule := range []string{"headers/csp-blocks-inline-style", "headers/csp-blocks-stylesheet-origin", "headers/csp-blocks-font-origin"} {
		if got[rule] == "" {
			t.Errorf("%s missing from %v", rule, got)
		}
	}
}

func TestAReportOnlyPolicySaysWhatEnforcingItWouldBreak(t *testing.T) {
	m := pageFindings(t, "script-src 'self'", true, `<script>a()</script>`)["headers/csp-blocks-inline-script"]
	if !strings.Contains(m, "would block") || !strings.Contains(m, "Report-Only") {
		t.Errorf("message = %q", m)
	}
}

func TestAPolicyThatDoesNotGovernAResourceAllowsIt(t *testing.T) {
	// No script-src and no default-src: the header check reports that; the page check has nothing
	// to say, because nothing on the page is stopped.
	if got := pageFindings(t, "frame-ancestors 'none'", false, `<script>a()</script><img src="https://x.test/a">`); len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
}

func TestStrictDynamicWantsANonceOrAHashOnMarkupScripts(t *testing.T) {
	sources := []string{"'strict-dynamic'", "'nonce-n'", "'sha384-abc'", "https:"}
	page := mustURL(t, "https://app.example.com/")
	load := func(nonce, integrity string) pageLoad {
		return pageLoad{kind: "script", url: mustURL(t, "https://cdn.example.net/a.js"), nonce: nonce, integrity: integrity}
	}
	if !loadAllowed(sources, load("n", ""), page) || !loadAllowed(sources, load("", "sha384-abc"), page) {
		t.Error("a nonce or a listed integrity hash is allowed")
	}
	if loadAllowed(sources, load("", ""), page) {
		t.Error("under 'strict-dynamic' a host source does not allow a markup script")
	}
}

func TestAttributeCodeNeedsUnsafeHashesForAHash(t *testing.T) {
	if attrAllowed([]string{sha("go()")}, "go()") {
		t.Error("a hash alone does not allow an attribute")
	}
	if !attrAllowed([]string{"'unsafe-hashes'", sha("go()")}, "go()") {
		t.Error("'unsafe-hashes' with a matching hash allows it")
	}
	for _, sum := range []func(string) []byte{sum384, sum512} {
		alg := map[int]string{48: "sha384", 64: "sha512"}[len(sum("go()"))]
		if !hashMatches([]string{"'" + alg + "-" + base64.StdEncoding.EncodeToString(sum("go()")) + "'"}, "go()") {
			t.Errorf("%s hash does not match", alg)
		}
	}
	if inlineAllowed([]string{"'none'"}, "x", "") {
		t.Error("'none' allows nothing")
	}
}

func TestSourceMatchesFollowsCSP3(t *testing.T) {
	page := mustURL(t, "http://app.example.com/")
	cases := []struct {
		source, u string
		want      bool
	}{
		{"*", "https://any.test/a", true},
		{"*", "data:image/png,AA", false},
		{"'self'", "https://app.example.com/a", true}, // the secure upgrade
		{"'self'", "http://app.example.com:8080/a", false},
		{"'self'", "https://other.example.com/a", false},
		{"'nonce-x'", "https://app.example.com/a", false},
		{"https:", "https://any.test/a", true},
		{"http:", "https://any.test/a", true},
		{"ws:", "wss://any.test/a", true},
		{"data:", "https://any.test/a", false},
		{"*.example.com", "https://cdn.example.com/a", true},
		{"*.example.com", "https://example.com/a", false},
		{"cdn.example.com", "https://cdn.example.com/a", true},
		{"cdn.example.com", "ftp://cdn.example.com/a", false},
		{"https://cdn.example.com", "http://cdn.example.com/a", false},
		{"http://cdn.example.com", "https://cdn.example.com/a", true},
		{"ws://cdn.example.com", "wss://cdn.example.com/a", true},
		{"cdn.example.com", "https://cdn.example.com:8443/a", false},
		{"cdn.example.com:8443", "https://cdn.example.com:8443/a", true},
		{"cdn.example.com:*", "https://cdn.example.com:9/a", true},
		{"cdn.example.com/js/", "https://cdn.example.com/js/a.js", true},
		{"cdn.example.com/js/a.js", "https://cdn.example.com/js/b.js", false},
		{"cdn.example.com/js/a.js", "https://cdn.example.com/js/a.js", true},
	}
	for _, c := range cases {
		if got := sourceMatches(c.source, mustURL(t, c.u), page); got != c.want {
			t.Errorf("sourceMatches(%q, %q) = %v, want %v", c.source, c.u, got, c.want)
		}
	}
	if portOf(mustURL(t, "wss://a.test")) != "443" || portOf(mustURL(t, "ws://a.test")) != "80" || portOf(mustURL(t, "data:x")) != "" {
		t.Error("default ports")
	}
}

func TestInlineEvidenceSaysWhatDependsOnUnsafeInline(t *testing.T) {
	none := inlineEvidence(readPage(mustURL(t, "https://a.test/"), []byte(`<script src="/a.js"></script>`)))
	if !strings.Contains(none, "removing it changes nothing") {
		t.Errorf("evidence = %q", none)
	}
	some := inlineEvidence(readPage(mustURL(t, "https://a.test/"), []byte(
		`<script>a()</script><a onclick="1" onmouseover="2" onfocus="3" onblur="4" href="#">`)))
	for _, want := range []string{"1 inline script", "4 inline event handlers", "and 1 more"} {
		if !strings.Contains(some, want) {
			t.Errorf("evidence = %q; want %q", some, want)
		}
	}
}

// Through the scanner: the page is read for a browser host, the evidence lands on the finding that
// reports the directive, and a Report-Only policy is judged when nothing is enforced.
func TestTheScannerComparesThePolicyWithThePage(t *testing.T) {
	scan := func(hostType string, h http.Header, body string) map[string]string {
		s := draugrHeadersScanner{info: NewHTTPHeaders().Info(),
			fetch: func(_ context.Context, target string, _ bool) (response, error) {
				return response{header: h, body: []byte(body), url: mustURL(t, target)}, nil
			}}
		rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://app.example.com/", Type: hostType}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, r := range rep.Results {
			got[r.RuleID] = r.Message
		}
		return got
	}
	page := `<script>a()</script><script src="https://cdn.other.net/x.js"></script>`

	got := scan("browser", http.Header{"Content-Security-Policy": {"script-src 'self' 'unsafe-inline'"}}, page)
	if !strings.Contains(got["headers/csp-unsafe-inline"], "1 inline script runs because of it") {
		t.Errorf("unsafe-inline = %q", got["headers/csp-unsafe-inline"])
	}
	if got["headers/csp-blocks-script-origin"] == "" {
		t.Errorf("findings = %v", got)
	}

	got = scan("browser", http.Header{"Content-Security-Policy-Report-Only": {"script-src 'self'"}}, page)
	if !strings.Contains(got["headers/csp-blocks-inline-script"], "would block") {
		t.Errorf("report-only = %v", got)
	}

	if got = scan("browser", http.Header{}, page); got["headers/csp-blocks-inline-script"] != "" {
		t.Error("no policy blocks nothing")
	}
	if got = scan("api", http.Header{"Content-Security-Policy": {"script-src 'self'"}}, page); got["headers/csp-blocks-inline-script"] != "" {
		t.Error("an API host has no page")
	}
}
