package scanners

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A policy graded on its own can score well and break the page it protects: a strict script-src
// beside an inline handler blocks the handler, silently, and every tool that reads only the header
// says the policy is excellent. This file compares the two.
//
// It reads the markup the server sends and nothing a browser builds afterwards. A script added by
// another script, a tag manager's payload, a fetch to an origin connect-src forgot: none of that is
// in the HTML. What is in it is the class that strands a policy in report-only: inline handlers,
// inline scripts, and a CDN nobody added to the list.

// pageContent is what a page asks the browser to run and load, as the markup states it.
type pageContent struct {
	base          *url.URL // what relative references resolve against: the page, or its <base href>
	inlineScripts []inlineBlock
	handlers      []inlineAttr // on*= attributes and javascript: links
	inlineStyles  []inlineBlock
	styleAttrs    []inlineAttr
	loads         []pageLoad
}

// inlineBlock is a <script> or <style> element's own text, kept exactly as sent because a CSP
// hash is taken over the bytes as they appear.
type inlineBlock struct {
	text  string
	nonce string
}

// inlineAttr is code or style carried in an attribute, named by where it sits so a finding can
// point at it: "onclick on <button>".
type inlineAttr struct {
	where string
	value string
}

// pageLoad is one resource the page fetches, and the directive that governs it.
type pageLoad struct {
	directive []string // the fallback chain, most specific first
	kind      string   // script, stylesheet, image, font: what a message calls it
	url       *url.URL
	nonce     string
	integrity string
}

// Data blocks a browser does not execute, so script-src does not govern them.
var dataScriptTypes = map[string]bool{
	"application/ld+json": true, "application/json": true, "text/template": true,
	"text/x-template": true, "text/html": true, "text/plain": true,
}

// readPage tokenizes a page and records what it runs and loads.
func readPage(page *url.URL, body []byte) pageContent {
	pc := pageContent{base: page}
	z := html.NewTokenizer(bytes.NewReader(body))
	var open *inlineBlock // the <script> or <style> whose text comes next
	var openKind atom.Atom
	for {
		switch z.Next() {
		case html.ErrorToken:
			return pc
		case html.TextToken:
			if open != nil {
				open.text += string(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if a := atom.Lookup(name); open != nil && a == openKind {
				if strings.TrimSpace(open.text) != "" {
					if openKind == atom.Script {
						pc.inlineScripts = append(pc.inlineScripts, *open)
					} else {
						pc.inlineStyles = append(pc.inlineStyles, *open)
					}
				}
				open = nil
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			attrs := map[string]string{}
			for _, a := range t.Attr {
				attrs[strings.ToLower(a.Key)] = a.Val
			}
			for _, a := range t.Attr {
				key := strings.ToLower(a.Key)
				if strings.HasPrefix(key, "on") && len(key) > 2 {
					pc.handlers = append(pc.handlers, inlineAttr{where: key + " on <" + t.Data + ">", value: a.Val})
				}
				if key == "style" && strings.TrimSpace(a.Val) != "" {
					pc.styleAttrs = append(pc.styleAttrs, inlineAttr{where: "style on <" + t.Data + ">", value: a.Val})
				}
			}
			pc.readElement(t.DataAtom, t.Data, attrs, &open, &openKind)
		}
	}
}

// readElement records what one element runs or loads.
func (pc *pageContent) readElement(tag atom.Atom, name string, attrs map[string]string,
	open **inlineBlock, openKind *atom.Atom) {
	switch tag {
	case atom.Base:
		// Only the first <base> counts, and only one with an href.
		if href, ok := attrs["href"]; ok && pc.base != nil && href != "" {
			if u, err := pc.base.Parse(href); err == nil {
				pc.base = u
			}
		}
	case atom.Script:
		if dataScriptTypes[strings.ToLower(strings.TrimSpace(attrs["type"]))] {
			return
		}
		if src, ok := attrs["src"]; ok && src != "" {
			pc.load([]string{"script-src-elem", "script-src"}, "script", src, attrs)
			return
		}
		*open, *openKind = &inlineBlock{nonce: attrs["nonce"]}, atom.Script
	case atom.Style:
		*open, *openKind = &inlineBlock{nonce: attrs["nonce"]}, atom.Style
	case atom.Link:
		rel := " " + strings.ToLower(attrs["rel"]) + " "
		href := attrs["href"]
		switch {
		case href == "":
		case strings.Contains(rel, " stylesheet "):
			pc.load([]string{"style-src-elem", "style-src"}, "stylesheet", href, attrs)
		case strings.Contains(rel, " preload ") || strings.Contains(rel, " modulepreload "):
			// A preload is fetched under the directive of what it will become.
			switch strings.ToLower(attrs["as"]) {
			case "script":
				pc.load([]string{"script-src-elem", "script-src"}, "script", href, attrs)
			case "style":
				pc.load([]string{"style-src-elem", "style-src"}, "stylesheet", href, attrs)
			case "font":
				pc.load([]string{"font-src"}, "font", href, attrs)
			case "image":
				pc.load([]string{"img-src"}, "image", href, attrs)
			}
		}
	case atom.Img:
		if src := attrs["src"]; src != "" {
			pc.load([]string{"img-src"}, "image", src, attrs)
		}
		for _, candidate := range strings.Split(attrs["srcset"], ",") {
			if f := strings.Fields(candidate); len(f) > 0 {
				pc.load([]string{"img-src"}, "image", f[0], attrs)
			}
		}
	case atom.A, atom.Area:
		if href := strings.TrimSpace(attrs["href"]); strings.HasPrefix(strings.ToLower(href), "javascript:") {
			pc.handlers = append(pc.handlers, inlineAttr{where: "javascript: link on <" + name + ">", value: href})
		}
	}
}

// load records a fetch, resolving the reference the way the browser will.
func (pc *pageContent) load(directive []string, kind, ref string, attrs map[string]string) {
	if pc.base == nil {
		return
	}
	u, err := pc.base.Parse(strings.TrimSpace(ref))
	if err != nil {
		return
	}
	pc.loads = append(pc.loads, pageLoad{
		directive: directive, kind: kind, url: u, nonce: attrs["nonce"], integrity: attrs["integrity"],
	})
}

// resolve follows a CSP3 fallback chain to the source list that governs it: the most specific
// directive present, then default-src where the last one takes it. The second value is false where
// nothing governs the resource at all, which is a policy allowing it.
func (p cspPolicy) resolve(chain []string) ([]string, bool) {
	for _, name := range chain[:len(chain)-1] {
		if v, ok := p[name]; ok {
			return v, true
		}
	}
	return p.effective(chain[len(chain)-1])
}

// governing names the directive a chain resolves to, which is the one a fix edits. Adding a
// script-src to a policy that only has default-src would stop script falling back to it, so the
// advice names default-src where that is what governs.
func (p cspPolicy) governing(chain []string) string {
	for _, name := range chain {
		if _, ok := p[name]; ok {
			return name
		}
	}
	return "default-src"
}

// inlineAllowed reports whether a source list lets an inline block run, and why not.
//
// 'unsafe-inline' allows it unless a nonce, a hash or 'strict-dynamic' is also listed, in which
// case browsers ignore 'unsafe-inline' and only a matching nonce or hash will do. That rule is how
// a good policy is written, and missing it would report the pages of the people who did the work.
func inlineAllowed(sources []string, text, nonce string) bool {
	if hasSource(sources, "'none'") && len(sources) == 1 {
		return false
	}
	if nonce != "" && hasSource(sources, "'nonce-"+nonce+"'") {
		return true
	}
	if hashMatches(sources, text) {
		return true
	}
	return hasSource(sources, "'unsafe-inline'") && !hasNonceOrHash(sources) &&
		!hasSource(sources, "'strict-dynamic'")
}

// attrAllowed is inlineAllowed for code or style in an attribute. A nonce cannot apply to an
// attribute; a hash can, but only where 'unsafe-hashes' says so.
func attrAllowed(sources []string, value string) bool {
	if hasSource(sources, "'unsafe-hashes'") && hashMatches(sources, value) {
		return true
	}
	return hasSource(sources, "'unsafe-inline'") && !hasNonceOrHash(sources) &&
		!hasSource(sources, "'strict-dynamic'")
}

// hashMatches reports whether any hash in the list is the hash of text, in the algorithm it names.
func hashMatches(sources []string, text string) bool {
	sums := map[string]func(string) []byte{"sha256": sum256, "sha384": sum384, "sha512": sum512}
	for _, src := range sources {
		alg, digest, ok := strings.Cut(strings.Trim(src, "'"), "-")
		sum, known := sums[strings.ToLower(alg)]
		if ok && known && digest == base64.StdEncoding.EncodeToString(sum(text)) {
			return true
		}
	}
	return false
}

func sum256(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func sum384(s string) []byte { h := sha512.Sum384([]byte(s)); return h[:] }
func sum512(s string) []byte { h := sha512.Sum512([]byte(s)); return h[:] }

// loadAllowed reports whether a source list lets a page fetch a URL.
//
// Under 'strict-dynamic' a script's host and scheme sources are ignored and a script the parser
// meets needs a nonce, or an integrity hash the policy lists. That is CSP3's rule for exactly the
// scripts that appear in markup, which are the only ones this reads.
func loadAllowed(sources []string, l pageLoad, page *url.URL) bool {
	if l.kind == "script" && hasSource(sources, "'strict-dynamic'") {
		if l.nonce != "" && hasSource(sources, "'nonce-"+l.nonce+"'") {
			return true
		}
		for _, h := range strings.Fields(l.integrity) {
			if hasSource(sources, "'"+h+"'") {
				return true
			}
		}
		return false
	}
	if l.nonce != "" && hasSource(sources, "'nonce-"+l.nonce+"'") {
		return true
	}
	for _, s := range sources {
		if sourceMatches(s, l.url, page) {
			return true
		}
	}
	return false
}

// networkSchemes are what '*' matches. It deliberately does not cover data:, blob: or
// filesystem:, which have to be named.
var networkSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true}

// sourceMatches applies one source expression to a URL, per CSP3's matching rules.
func sourceMatches(source string, u, page *url.URL) bool {
	lower := strings.ToLower(source)
	switch {
	case lower == "*":
		return networkSchemes[u.Scheme] || (page != nil && u.Scheme == page.Scheme)
	case lower == "'self'":
		return page != nil && sameOrigin(u, page)
	case strings.HasPrefix(lower, "'"):
		return false // a keyword, a nonce or a hash, none of which names a place
	case strings.HasSuffix(lower, ":") && !strings.Contains(lower, "/"):
		// A scheme source. http: also allows its secure upgrade.
		want := strings.TrimSuffix(lower, ":")
		return schemeAllows(want, u.Scheme)
	}
	return hostSourceMatches(lower, u, page)
}

// schemeAllows reports whether a source naming one scheme admits a URL with another: the same
// scheme, or its secure upgrade.
func schemeAllows(want, got string) bool {
	return got == want || (want == "http" && got == "https") || (want == "ws" && got == "wss")
}

// sameOrigin is 'self': scheme, host and port, allowing the upgrade from http to https that a
// browser allows on the same host.
func sameOrigin(u, page *url.URL) bool {
	if !strings.EqualFold(u.Hostname(), page.Hostname()) {
		return false
	}
	if u.Scheme == page.Scheme {
		return portOf(u) == portOf(page)
	}
	return page.Scheme == "http" && u.Scheme == "https"
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	}
	return ""
}

// hostSourceMatches handles [scheme://]host[:port][/path], with a leading *. on the host.
func hostSourceMatches(source string, u, page *url.URL) bool {
	scheme := ""
	if i := strings.Index(source, "://"); i >= 0 {
		scheme, source = source[:i], source[i+3:]
	}
	path := ""
	if i := strings.Index(source, "/"); i >= 0 {
		source, path = source[:i], source[i:]
	}
	host, port := source, ""
	if i := strings.LastIndex(source, ":"); i >= 0 {
		host, port = source[:i], source[i+1:]
	}

	switch {
	case scheme != "":
		if !schemeAllows(scheme, u.Scheme) {
			return false
		}
	case page != nil:
		// No scheme means the page's own, again allowing the secure upgrade.
		if !schemeAllows(page.Scheme, u.Scheme) {
			return false
		}
	}

	h := strings.ToLower(u.Hostname())
	switch {
	case strings.HasPrefix(host, "*."):
		if !strings.HasSuffix(h, host[1:]) {
			return false
		}
	case h != host:
		return false
	}

	switch port {
	case "", "*":
		if port == "" && u.Port() != "" && u.Port() != portOf(&url.URL{Scheme: u.Scheme}) {
			return false
		}
	default:
		if portOf(u) != port {
			return false
		}
	}

	if path != "" {
		if strings.HasSuffix(path, "/") {
			return strings.HasPrefix(u.Path, path)
		}
		return u.Path == path
	}
	return true
}

// evaluatePage reports what the policy stops this page doing.
//
// Each message opens "CSP blocks" rather than naming the header in full, because a terminal shows
// the first sixty or so characters of a message and the origin is the part somebody acts on.
//
// Blocked content is a correctness finding, and a note: a strict policy breaking its own page is
// worth knowing and is not a vulnerability, so it must not fail a security gate. The security half
// is the reverse, content that forces 'unsafe-inline', and it is carried as evidence on the
// csp-unsafe-inline finding rather than as a second finding about the same weakness.
//
// reportOnly says the policy is being reported rather than enforced, in which case nothing is
// blocked yet and the message says what enforcing it would stop.
func evaluatePage(policy string, reportOnly bool, pc pageContent, add func(ruleID, message string, level sarif.Level)) {
	p := parseCSP(policy)
	verb := "blocks"
	if reportOnly {
		verb = "would block"
	}
	// What the browser does about it, which a Report-Only policy changes.
	after := func(n int) string {
		if reportOnly {
			return english.Choose(n, "The policy is Report-Only, so the browser reports it and still allows it.",
				"The policy is Report-Only, so the browser reports them and still allows them.")
		}
		return english.Choose(n, "The browser refuses it.", "The browser refuses them.")
	}

	if sources, ok := p.resolve([]string{"script-src-elem", "script-src"}); ok {
		var blocked int
		for _, s := range pc.inlineScripts {
			if !inlineAllowed(sources, s.text, s.nonce) {
				blocked++
			}
		}
		if blocked > 0 {
			add("headers/csp-blocks-inline-script", fmt.Sprintf(
				"CSP %s %s on this page, which %s no nonce or hash the policy lists. %s",
				verb, english.Count(blocked, "inline script"), english.Choose(blocked, "carries", "carry"),
				after(blocked)), sarif.LevelNote)
		}
	}
	if sources, ok := p.resolve([]string{"script-src-attr", "script-src"}); ok {
		if where := blockedAttrs(sources, pc.handlers); len(where) > 0 {
			add("headers/csp-blocks-inline-handler", fmt.Sprintf(
				"CSP %s %s on this page (%s). %s",
				verb, english.Count(len(where), "inline event handler"), listed(where), after(len(where))), sarif.LevelNote)
		}
	}
	var styleBlocked int
	if sources, ok := p.resolve([]string{"style-src-elem", "style-src"}); ok {
		for _, s := range pc.inlineStyles {
			if !inlineAllowed(sources, s.text, s.nonce) {
				styleBlocked++
			}
		}
	}
	if sources, ok := p.resolve([]string{"style-src-attr", "style-src"}); ok {
		styleBlocked += len(blockedAttrs(sources, pc.styleAttrs))
	}
	if styleBlocked > 0 {
		add("headers/csp-blocks-inline-style", fmt.Sprintf(
			"CSP %s %s on this page. %s",
			verb, english.Count(styleBlocked, "inline style"), after(styleBlocked)), sarif.LevelNote)
	}

	// One finding per kind of resource, each naming the origins it stops. An origin repeated across
	// ten images is one decision, and ten findings for it would be ten things to read.
	blocked := map[string]map[string][]string{} // kind -> origin -> urls
	chains := map[string][]string{}             // kind -> the fallback chain its loads follow
	for _, l := range pc.loads {
		sources, ok := p.resolve(l.directive)
		if !ok || loadAllowed(sources, l, pc.base) {
			continue
		}
		origin := l.url.Scheme + "://" + l.url.Host
		if l.url.Scheme == "data" || l.url.Scheme == "blob" {
			origin = l.url.Scheme + ":"
		}
		chains[l.kind] = l.directive
		if blocked[l.kind] == nil {
			blocked[l.kind] = map[string][]string{}
		}
		blocked[l.kind][origin] = append(blocked[l.kind][origin], l.url.String())
	}
	for _, kind := range []string{"script", "stylesheet", "image", "font"} {
		byOrigin := blocked[kind]
		if len(byOrigin) == 0 {
			continue
		}
		origins := make([]string, 0, len(byOrigin))
		for o := range byOrigin {
			origins = append(origins, o)
		}
		sort.Strings(origins)
		directive := p.governing(chains[kind])
		add("headers/csp-blocks-"+kind+"-origin", fmt.Sprintf(
			"CSP %s %s from %s, which this page loads (%s). %s",
			verb, english.Noun(total(byOrigin), kind), strings.Join(origins, ", "), listed(firstOf(byOrigin, origins)), after(total(byOrigin)))+
			" "+fmt.Sprintf("Add the origin to %s, or stop loading from it.", directive), sarif.LevelNote)
	}
}

// inlineEvidence says what on a page depends on 'unsafe-inline' in script-src, for the finding
// that reports the directive. Evidence turns "remove 'unsafe-inline'" from advice into a list of
// what to move, or into proof that nothing needs moving.
func inlineEvidence(pc pageContent) string {
	scripts, handlers := len(pc.inlineScripts), len(pc.handlers)
	if scripts == 0 && handlers == 0 {
		return " This page has no inline script and no inline event handler, so removing it changes " +
			"nothing the page runs."
	}
	var parts []string
	if scripts > 0 {
		parts = append(parts, english.Count(scripts, "inline script"))
	}
	if handlers > 0 {
		where := make([]string, 0, handlers)
		for _, h := range pc.handlers {
			where = append(where, h.where)
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", english.Count(handlers, "inline event handler"), listed(where)))
	}
	n := scripts + handlers
	return fmt.Sprintf(" On this page %s %s because of it. Move %s into files and it can be removed.",
		strings.Join(parts, " and "), english.Choose(n, "runs", "run"), english.Choose(n, "it", "them"))
}

func blockedAttrs(sources []string, attrs []inlineAttr) []string {
	var where []string
	for _, a := range attrs {
		if !attrAllowed(sources, a.value) {
			where = append(where, a.where)
		}
	}
	return where
}

// total is how many resources a kind's blocked origins account for.
func total(byOrigin map[string][]string) int {
	n := 0
	for _, urls := range byOrigin {
		n += len(urls)
	}
	return n
}

// firstOf takes one example URL per origin, in origin order, for the message.
func firstOf(byOrigin map[string][]string, origins []string) []string {
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		out = append(out, byOrigin[o][0])
	}
	return out
}

// listed names up to three items and says how many more, so a page with forty handlers produces a
// readable sentence rather than all forty.
func listed(items []string) string {
	seen := map[string]bool{}
	var uniq []string
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			uniq = append(uniq, it)
		}
	}
	if len(uniq) <= 3 {
		return strings.Join(uniq, ", ")
	}
	return strings.Join(uniq[:3], ", ") + fmt.Sprintf(" and %d more", len(uniq)-3)
}
