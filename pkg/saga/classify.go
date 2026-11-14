package saga

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Classification is a component's risk tags.
type Classification struct {
	Exposure    Exposure
	Criticality Criticality
}

// WriteClassifications sets each named component's exposure and criticality in the raw Saga
// bytes and returns the updated document. Components not present in class are left untouched. New
// keys are inserted right after the component's name; existing values are updated in place.
//
// The file is a person's, so it is edited as text: the two values change or two lines are added,
// and every other byte stays where it was, comment alignment, blank lines, a commented-out block
// and ${{ VAR }} tokens included. Re-encoding the parsed document instead keeps the comments but
// not their place, and a commented-out key moved to a deeper indent is nested somewhere else the
// moment somebody uncomments it. Only a component written in flow style, `{name: web}`, which has
// no line of its own to add a key to, is re-encoded.
func WriteClassifications(data []byte, class map[string]Classification) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse saga: %w", err)
	}
	if len(root.Content) == 0 {
		return data, nil
	}
	comps := mappingValue(root.Content[0], "components")
	if comps == nil || comps.Kind != yaml.SequenceNode {
		return data, nil
	}
	var edits []lineEdit
	for _, comp := range comps.Content {
		if comp.Kind != yaml.MappingNode {
			continue
		}
		name := mappingValue(comp, "name")
		if name == nil {
			continue
		}
		c, ok := class[name.Value]
		if !ok {
			continue
		}
		if comps.Style&yaml.FlowStyle != 0 || comp.Style&yaml.FlowStyle != 0 {
			return reencodeClassifications(&root, comps, class)
		}
		edits = append(edits, componentEdits(comp, string(c.Exposure), string(c.Criticality))...)
	}
	return applyLineEdits(data, edits), nil
}

// lineEdit is one change to the document's lines: the value on line (1-based) starting at column
// replaced by value, or, when insert is set, the line added after line.
type lineEdit struct {
	line, column int
	value        string
	insert       string
}

// componentEdits are the edits that give one component its exposure and criticality. A key that is
// there has its value replaced; one that is not is added under the key before it, at that key's
// indent.
func componentEdits(comp *yaml.Node, exposure, criticality string) []lineEdit {
	nameKey := mappingKey(comp, "name")
	indent := strings.Repeat(" ", nameKey.Column-1)
	var out []lineEdit
	after := nameKey.Line
	for _, kv := range [][2]string{{"exposure", exposure}, {"criticality", criticality}} {
		if v := mappingValue(comp, kv[0]); v != nil {
			edit := lineEdit{line: v.Line, column: v.Column, value: kv[1]}
			if v.Kind == yaml.ScalarNode && v.Value == "" && v.Style == 0 {
				// `exposure:` with nothing after it has no value to replace, so the key is
				// rewritten with one.
				k := mappingKey(comp, kv[0])
				edit = lineEdit{line: k.Line, column: k.Column, value: kv[0] + ": " + kv[1]}
			}
			out = append(out, edit)
			after = edit.line
			continue
		}
		out = append(out, lineEdit{line: after, insert: indent + kv[0] + ": " + kv[1]})
	}
	return out
}

// applyLineEdits applies edits to data, keeping the file's line endings. Insertions after the same
// line keep the order they were made in.
func applyLineEdits(data []byte, edits []lineEdit) []byte {
	lines := strings.SplitAfter(string(data), "\n")
	inserts := map[int][]string{}
	for _, e := range edits {
		if e.insert != "" {
			inserts[e.line] = append(inserts[e.line], e.insert)
			continue
		}
		lines[e.line-1] = replaceValue(lines[e.line-1], e.column, e.value)
	}
	at := make([]int, 0, len(inserts))
	for l := range inserts {
		at = append(at, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(at)))
	eol := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		eol = "\r\n"
	}
	for _, l := range at {
		if !strings.HasSuffix(lines[l-1], "\n") {
			lines[l-1] += eol // the last line had no newline of its own
		}
		added := make([]string, len(inserts[l]))
		for i, s := range inserts[l] {
			added[i] = s + eol
		}
		lines = append(lines[:l:l], append(added, lines[l:]...)...)
	}
	return []byte(strings.Join(lines, ""))
}

// replaceValue replaces the scalar starting at column (1-based, in characters) of line with value,
// keeping what follows it: the spacing before a comment, the comment, the line ending.
func replaceValue(line string, column int, value string) string {
	r := []rune(line)
	start := column - 1
	if start < 0 || start > len(r) {
		return line
	}
	end := scalarEnd(r, start)
	return string(r[:start]) + value + string(r[end:])
}

// scalarEnd is where the single-line scalar starting at start ends: after its closing quote, or,
// for a plain scalar, before the spaces that precede a comment or the end of the line.
func scalarEnd(r []rune, start int) int {
	if start < len(r) && (r[start] == '"' || r[start] == '\'') {
		q := r[start]
		for i := start + 1; i < len(r); i++ {
			switch {
			case q == '"' && r[i] == '\\':
				i++
			case q == '\'' && r[i] == '\'' && i+1 < len(r) && r[i+1] == '\'':
				i++
			case r[i] == q:
				return i + 1
			}
		}
		return len(r)
	}
	end := len(r)
	for i := start; i < len(r); i++ {
		if r[i] == '\r' || r[i] == '\n' || r[i] == '#' && i > start && (r[i-1] == ' ' || r[i-1] == '\t') {
			end = i
			break
		}
	}
	for end > start && (r[end-1] == ' ' || r[end-1] == '\t') {
		end--
	}
	return end
}

// reencodeClassifications is the path for a component written in flow style: set the values on the
// parsed document and encode it again.
func reencodeClassifications(root, comps *yaml.Node, class map[string]Classification) ([]byte, error) {
	for _, comp := range comps.Content {
		name := mappingValue(comp, "name")
		if comp.Kind != yaml.MappingNode || name == nil {
			continue
		}
		if c, ok := class[name.Value]; ok {
			setScalarAfter(comp, "name", "exposure", string(c.Exposure))
			setScalarAfter(comp, "exposure", "criticality", string(c.Criticality))
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(Indent)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("encode saga: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

// mappingKey returns the key node for key in a mapping node, or nil.
func mappingKey(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}

// mappingValue returns the value node for key in a mapping node, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setScalarAfter sets key=val in the mapping node: it updates the value in place if key
// already exists, otherwise inserts the key/value pair immediately after the pair whose key
// is afterKey (appending if afterKey is absent).
func setScalarAfter(m *yaml.Node, afterKey, key, val string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Value = val
			m.Content[i+1].Tag = "!!str"
			m.Content[i+1].Style = 0
			return
		}
	}
	pair := []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
	}
	idx := len(m.Content)
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == afterKey {
			idx = i + 2
			break
		}
	}
	m.Content = append(m.Content[:idx:idx], append(pair, m.Content[idx:]...)...)
}
