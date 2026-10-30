package config

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/suggest"
)

// KeysURL is where every key of the file is documented.
const KeysURL = "https://draugr.dev/docs/latest/reference/cli/#draugr-config"

// KeysHint closes a report of a key the file cannot hold, naming the command that lists every key
// this build has.
const KeysHint = "`draugr config keys` lists every key"

// Problems is every reason one configuration file cannot be used, each naming the key it is about.
type Problems struct {
	// Path is the file.
	Path string
	// List holds one problem per line, each led by the dotted key it is about.
	List []string
	// Hint is where to look next, printed after the list.
	Hint string
}

// Error renders the file, its problems one per line, and the hint.
func (p *Problems) Error() string {
	var b strings.Builder
	b.WriteString(p.Path)
	b.WriteString(":")
	for _, line := range p.List {
		b.WriteString("\n  ")
		b.WriteString(line)
	}
	if p.Hint != "" {
		b.WriteString("\n\n")
		b.WriteString(p.Hint)
	}
	return b.String()
}

var (
	unknownField = regexp.MustCompile(`^line (\d+): field (.+) not found in type .+$`)
	wrongType    = regexp.MustCompile("^line (\\d+): cannot unmarshal !!\\w+ `(.*)` into (.+)$")
)

// describe rewrites the decoder's messages in the file's terms.
//
// The decoder names Go types: `field veiw not found in type config.OutputSettings`, `cannot
// unmarshal !!int 5 into time.Duration`. Somebody editing the file knows keys, not types, so each
// message is matched back to the key on the line it names. A message no pattern matches is kept as
// the decoder wrote it, with its line number.
func describe(data []byte, errs []string) []string {
	var root yaml.Node
	_ = yaml.Unmarshal(data, &root) // the decoder already parsed it; a syntax error never reaches here
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, describeOne(&root, e))
	}
	return out
}

// keysHintFor is KeysHint when a decoder error names a key the file cannot hold, and "" when every
// one is a value of the wrong type, which its own line already explains.
func keysHintFor(errs []string) string {
	for _, e := range errs {
		if !wrongType.MatchString(e) {
			return KeysHint
		}
	}
	return ""
}

func describeOne(root *yaml.Node, msg string) string {
	if m := unknownField.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		parent, ok := findKey(root, nil, func(k, _ *yaml.Node) bool { return k.Line == line && k.Value == m[2] })
		if ok {
			return unknownSetting(parent, m[2])
		}
	}
	if m := wrongType.FindStringSubmatch(msg); m != nil {
		line, _ := strconv.Atoi(m[1])
		key := ""
		parent, ok := findKey(root, nil, func(k, v *yaml.Node) bool {
			if v.Line == line && v.Kind == yaml.ScalarNode && v.Value == m[2] {
				key = k.Value
				return true
			}
			return false
		})
		if ok {
			return fmt.Sprintf("%s: expected %s, got %s",
				strings.Join(append(parent, key), "."), expected(m[3]), m[2])
		}
	}
	return msg
}

// unknownSetting reports a key the file cannot hold, with the nearest key it can.
func unknownSetting(parent []string, field string) string {
	where := ""
	if len(parent) > 0 {
		where = strings.Join(parent, ".") + ": "
	}
	msg := fmt.Sprintf("%s%q is not a setting Draugr has", where, field)
	known := fieldsAt(parent)
	if near := suggest.Nearest(field, known); near != "" {
		return msg + fmt.Sprintf(", did you mean %q?", near)
	}
	if len(known) > 0 {
		names := make([]string, 0, len(known))
		for k := range known {
			names = append(names, k)
		}
		sort.Strings(names)
		msg += " (it has " + strings.Join(names, ", ") + ")"
	}
	return msg
}

// findKey returns the path of the mapping holding the first entry match accepts, the parent's keys
// from the top of the file down.
func findKey(n *yaml.Node, path []string, match func(k, v *yaml.Node) bool) ([]string, bool) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if p, ok := findKey(c, path, match); ok {
				return p, true
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if match(k, v) {
				return path, true
			}
			if p, ok := findKey(v, append(append([]string{}, path...), k.Value), match); ok {
				return p, true
			}
		}
	}
	return nil, false
}

// fieldsAt lists the keys the file may hold under a dotted path, read from File's yaml tags so it
// cannot fall behind the struct.
func fieldsAt(path []string) map[string]bool {
	t := reflect.TypeOf(File{})
	for _, seg := range path {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch t.Kind() {
		case reflect.Struct:
			f, ok := fieldByTag(t, seg)
			if !ok {
				return nil
			}
			t = f.Type
		case reflect.Map:
			t = t.Elem() // the segment is a key of the map, such as a tool's name
		default:
			return nil
		}
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	out := map[string]bool{}
	for i := range t.NumField() {
		if name := tagName(t.Field(i)); name != "" {
			out[name] = true
		}
	}
	return out
}

func fieldByTag(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		if tagName(t.Field(i)) == name {
			return t.Field(i), true
		}
	}
	return reflect.StructField{}, false
}

func tagName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if name == "-" {
		return ""
	}
	return name
}

// expected names what a Go type accepts, in the file's terms.
func expected(goType string) string {
	switch {
	case goType == "time.Duration":
		return "a duration such as 12h"
	case goType == "bool":
		return "true or false"
	case strings.HasPrefix(goType, "int"), strings.HasPrefix(goType, "uint"):
		return "a whole number"
	case goType == "string":
		return "a string"
	case strings.HasPrefix(goType, "[]"):
		return "a list"
	default:
		return "a mapping"
	}
}
