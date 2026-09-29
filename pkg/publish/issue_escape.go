package publish

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

// zeroWidth is U+200B. Placed after a sigil it leaves the text reading the same and stops a forge
// from reading the sigil as a mention, a reference, an emoji or a quick action.
const zeroWidth = "\u200b"

// sigils are the characters a forge acts on when they begin a token: `@` mentions, `#` and `!`
// reference issues and merge requests, `:` opens an emoji code, and GitLab reads `%`, `&`, `$` and
// `~` as a milestone, an epic, a snippet and a label.
const sigils = "@#!:%&$~"

// markdownPunct is the Markdown punctuation that changes how text renders. `~` is here as well as
// in sigils because GitHub reads a single tilde as strikethrough.
const markdownPunct = "\\`*_{}[]()<>|~"

// ghReference and bareHost are what GitHub links without a sigil: `GH-123` and a `www.` host.
var (
	ghReference = regexp.MustCompile(`(?i)\b(gh-)(\d)`)
	bareHost    = regexp.MustCompile(`(?i)\b(w)(ww\.)`)
)

// flatten collapses every run of whitespace, newlines included, to one space. Scanner text is
// written for a terminal, and a newline inside a table cell ends the table.
func flatten(s string) string { return strings.Join(strings.Fields(s), " ") }

// breakTokens puts a zero-width space after every sigil and inside every autolink prefix.
func breakTokens(s string) string {
	s = ghReference.ReplaceAllString(s, "${1}"+zeroWidth+"${2}")
	s = bareHost.ReplaceAllString(s, "${1}"+zeroWidth+"${2}")
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(r)
		if strings.ContainsRune(sigils, r) {
			b.WriteString(zeroWidth)
		}
	}
	return b.String()
}

// mdText renders scanner or author text as plain Markdown prose: flattened to one line, sigils
// broken and punctuation escaped, so it reads as written and acts on nothing.
//
// A leading `/` is escaped too. GitLab runs a line that starts with one as a quick action, and
// the body is built so no line starts with text Draugr did not write; the escape holds that for
// any caller that places text at the start of a line.
func mdText(s string) string {
	var b strings.Builder
	for i, r := range breakTokens(flatten(s)) {
		if strings.ContainsRune(markdownPunct, r) || (i == 0 && r == '/') {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mdCode renders an identifier as a code span, with a fence longer than any backtick run inside
// it. In a table cell a `|` still ends the cell inside a code span, so it is escaped there.
func mdCode(s string, inTable bool) string {
	s = flatten(s)
	if inTable {
		s = strings.ReplaceAll(s, "|", `\|`)
	}
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return fence + pad + s + pad + fence
}

// htmlText renders scanner or author text for an HTML context: flattened, sigils broken, then
// escaped. Markdown is not parsed inside a `<summary>`, and Azure's description is HTML.
func htmlText(s string) string { return html.EscapeString(breakTokens(flatten(s))) }

// safeURL returns a link target from a scanner, or empty when it is not one to link. Only http and
// https are linked, and the characters that would end a Markdown link or an HTML attribute are
// percent-encoded.
func safeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", "<", "%3C", ">", "%3E", `"`, "%22", "'", "%27").
		Replace(u.String())
}
