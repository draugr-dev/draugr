package saga

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// LineHistory is what a repository's git history says about the line an exclusion is written at:
// the last commit to change it, as `git blame` names it, that commit's author and date, or why none
// is reported.
//
// Git's record rather than the descriptor's. The name an exclusion carries is whatever its author
// typed, and the commit that wrote the line is what a reviewer reads to learn who set a finding
// aside. It is reported only where the history is reliable, so an unavailable history says why and
// never names a guess: a shallow clone attributes every line it cannot see past to the commit at
// its boundary, which would put that commit's author on lines somebody else wrote.
type LineHistory struct {
	// Path is the file's path in the repository holding it, slash-separated. Empty when no git
	// work tree holds the file.
	Path string `json:"path,omitempty"`
	// Commit is the last commit to change the line, as git blame names it, Author is that commit's
	// author name and Date its author date in RFC 3339, with the author's offset. Set only when the
	// history is reliable. No email address is kept.
	Commit string `json:"commit,omitempty"`
	Author string `json:"author,omitempty"`
	Date   string `json:"date,omitempty"`
	// Unavailable is why no commit is reported, set exactly when Commit is not.
	Unavailable string `json:"unavailable,omitempty"`
}

// String renders the history as a line of the console prints it: `last changed in <commit> by
// <author>, <date>`, or `git history unavailable: <reason>`.
//
// "Last changed", because blame names the last commit to touch the line, which is the commit that
// wrote the exclusion only when nobody has edited the line since.
func (h LineHistory) String() string {
	if h.Commit == "" {
		return "git history " + h.Summary()
	}
	return "last changed in " + h.Summary()
}

// Summary renders the history for a place already labeled as git history, such as a table column:
// `<commit> by <author>, <date>`, or `unavailable: <reason>`.
func (h LineHistory) Summary() string {
	if h.Commit == "" {
		return "unavailable: " + h.Unavailable
	}
	day := h.Date
	if len(day) > len(expiresLayout) {
		day = day[:len(expiresLayout)]
	}
	return fmt.Sprintf("%s by %s, %s", short(h.Commit), h.Author, day)
}

// stampExcludeLines records the line each config.exclude entry starts at, read from the parsed
// document the rules were decoded from.
//
// Read from the tree before it is re-marshaled for strict decoding, because the marshaled copy has
// its own line numbers and the ones a reader looks up are the file's.
func stampExcludeLines(root *yaml.Node, rules []ExcludeRule) {
	doc := root
	if doc != nil && doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	config := resolveAlias(mappingValue(resolveAlias(doc), "config"))
	exclude := resolveAlias(mappingValue(config, "exclude"))
	if exclude == nil || exclude.Kind != yaml.SequenceNode || len(exclude.Content) != len(rules) {
		return
	}
	for i, item := range exclude.Content {
		item = resolveAlias(item)
		rules[i].Line = item.Line
		if key := mappingKey(item, "acceptedBy"); key != nil {
			rules[i].acceptedByLine = key.Line
		}
	}
}

// mappingKey returns the key node named key in a mapping, or nil.
func mappingKey(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i]
		}
	}
	return nil
}

// resolveAlias follows an alias to the node it names, whose line is where the text is written.
func resolveAlias(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}
