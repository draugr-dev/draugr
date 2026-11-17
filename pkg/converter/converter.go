// Package converter reads the file a converter writes for Draugr to import: the findings of a tool
// Draugr has no reader for, with those of Draugr's own result properties a declared converter may
// set.
//
// A converter is a program a CI step runs on another tool's output. Draugr never runs it. It reads
// the file the step wrote, as it reads any import, held to a commit, because running a program at
// scan time would put arbitrary code execution inside the scan.
//
// The file follows a versioned contract, draugr-converter.v1.schema.json, embedded here as the one
// description of the file's shape. Read holds a file to it key by key, so a converter's author is
// told which key of which result is wrong, and to a fixed list of the properties a converter may set
// (Properties). Each of those adds evidence about a finding or raises it. A property that sets a
// finding aside or lowers it (Never) is refused by name, whatever the descriptor says: a finding
// moves down only on evidence Draugr can check, and a converter's word is not that evidence.
package converter

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
)

// SchemaJSON is the contract's JSON Schema, embedded so the binary reads files against exactly the
// contract it documents.
//
//go:embed draugr-converter.v1.schema.json
var SchemaJSON []byte

// SchemaFile is the name the schema is kept and published under.
const SchemaFile = "draugr-converter.v1.schema.json"

// ID is the contract's id, which every converter file states as its `contract`.
const ID = "draugr-converter"

// Version is the contract version this build reads. A file stating any other is refused, naming
// this one, because a reader that guessed at an older or newer shape would read some of its keys and
// drop the rest without a word.
const Version = 1

// Property is one of Draugr's result properties a converter may set.
type Property string

// The properties a converter may set. Each adds evidence about a finding or raises it.
const (
	// PropertyPackage is the dependency a finding is about, with its version, fixed version and
	// package URL.
	PropertyPackage Property = "package"
	// PropertyCWE is the CWE ids of the flaw.
	PropertyCWE Property = "cwe"
	// PropertyLabels is labels on the finding, beside the component's own.
	PropertyLabels Property = "labels"
	// PropertyReachable is a verdict that the project's code reaches the vulnerable code.
	PropertyReachable Property = "reachable"
	// PropertyRaise is a band the finding is ranked at least at.
	PropertyRaise Property = "raise"
)

// Properties is the allow-list, fixed here. A descriptor's converter.sets may name fewer of them and
// never another.
var Properties = []Property{PropertyPackage, PropertyCWE, PropertyLabels, PropertyReachable, PropertyRaise}

// Never are the result properties no converter may set, whatever a descriptor declares: each sets a
// finding aside, says who accepted it, or ranks it lower. A file naming one is refused by name rather
// than read without it, so the converter's author learns the property was never going to apply.
var Never = []string{
	"suppression", "suppressions", "aside", "nonShipping", "acceptedBy", "origin",
	"priority", "priorityCap", "rankedAs", "unreachable",
}

// Allowed reports whether name is a property a converter may set.
func Allowed(name string) bool { return slices.Contains(Properties, Property(name)) }

// Forbidden reports whether name is a property no converter may set.
func Forbidden(name string) bool { return slices.Contains(Never, name) }

// Document is a converter file.
type Document struct {
	Contract   string    `json:"contract"`
	Version    int       `json:"version"`
	Converter  Converter `json:"converter"`
	Source     Source    `json:"source"`
	Commit     string    `json:"commit"`
	Repository string    `json:"repository,omitempty"`
	Written    string    `json:"written,omitempty"`
	Results    []Result  `json:"results"`
}

// Converter is the converter that wrote a file.
type Converter struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Source is the tool whose output a converter read, and the file it read.
type Source struct {
	Tool    string `json:"tool"`
	Version string `json:"version,omitempty"`
	File    string `json:"file,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

// Result is one finding.
type Result struct {
	RuleID    string            `json:"ruleId"`
	Message   string            `json:"message"`
	Severity  string            `json:"severity"`
	Score     *float64          `json:"score,omitempty"`
	Location  *Location         `json:"location,omitempty"`
	Package   *Package          `json:"package,omitempty"`
	CWE       []string          `json:"cwe,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Reachable *bool             `json:"reachable,omitempty"`
	Raise     *Raise            `json:"raise,omitempty"`
}

// Location is where a finding is, relative to the repository's root.
type Location struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
}

// Package is the dependency a finding is about.
type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	PURL         string `json:"purl,omitempty"`
	Ecosystem    string `json:"ecosystem,omitempty"`
}

// Raise is a band a finding is ranked at least at, and why.
type Raise struct {
	Priority string `json:"priority"`
	Reason   string `json:"reason"`
}

// Sets are the properties the result sets, in the order Properties lists them. A key written with an
// empty value still sets its property, so a file cannot slip one past converter.sets by leaving it
// empty.
func (r Result) Sets() []Property {
	var out []Property
	for _, p := range []struct {
		property Property
		set      bool
	}{
		{PropertyPackage, r.Package != nil},
		{PropertyCWE, r.CWE != nil},
		{PropertyLabels, r.Labels != nil},
		{PropertyReachable, r.Reachable != nil},
		{PropertyRaise, r.Raise != nil},
	} {
		if p.set {
			out = append(out, p.property)
		}
	}
	return out
}

// errNotConverter is the error of a file that is not a converter's, worded for the errors block,
// which keeps the clause after the last colon.
var errNotConverter = errors.New("not a converter file. A converter writes contract " + ID)

// Read reads a converter file, held to the contract and to allowed, the properties the descriptor
// declares the converter sets. Anything else the file sets is an error naming it.
//
// The checks run in the order a converter's author fixes them: whether it is a converter file at
// all, its version, a property no converter may set, then the contract key by key, and last a
// property the descriptor did not declare.
func Read(data []byte, allowed []Property) (Document, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, errNotConverter
	}
	top, ok := raw.(map[string]any)
	if !ok || top["contract"] != ID {
		return Document{}, errNotConverter
	}
	if err := checkVersion(top["version"]); err != nil {
		return Document{}, err
	}
	if err := refuseNever(top); err != nil {
		return Document{}, err
	}
	c := contract()
	if err := c.walk(c.root, raw, ""); err != nil {
		return Document{}, err
	}
	// The walk covers every keyword the schema uses; this is the backstop for one added later.
	if err := c.resolved.Validate(raw); err != nil {
		return Document{}, fmt.Errorf("does not follow contract version %d, %s", Version, lastClause(err.Error()))
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Document{}, fmt.Errorf("does not follow contract version %d, %s", Version, lastClause(err.Error()))
	}
	for i, r := range doc.Results {
		at := fmt.Sprintf("results[%d]", i)
		if r.Reachable != nil && r.Package == nil {
			return Document{}, fmt.Errorf("%s sets reachable with no package. A verdict is about a dependency", at)
		}
		for _, p := range r.Sets() {
			if !slices.Contains(allowed, p) {
				return Document{}, fmt.Errorf("%s sets %s, which converter.sets does not list", at, p)
			}
		}
	}
	return doc, nil
}

// checkVersion refuses any contract version but Version, naming the one Draugr reads.
func checkVersion(v any) error {
	n, ok := v.(float64)
	switch {
	case v == nil:
		return fmt.Errorf("states no contract version. Draugr reads version %d", Version)
	case !ok || n != math.Trunc(n):
		return fmt.Errorf("contract version %s is not one Draugr reads. It reads %d", show(v), Version)
	case int(n) < Version:
		return fmt.Errorf("contract version %d is older than Draugr reads, version %d. Update the converter", int(n), Version)
	case int(n) > Version:
		return fmt.Errorf("contract version %d is unknown here. Draugr reads version %d", int(n), Version)
	}
	return nil
}

// refuseNever refuses a file that sets a property no converter may set, at the top of the file or
// on a result, and a result that says the code does not reach a flaw.
func refuseNever(top map[string]any) error {
	for _, k := range sortedKeys(top) {
		if Forbidden(k) {
			return fmt.Errorf("the file sets %s, which no converter may set", k)
		}
	}
	results, _ := top["results"].([]any)
	for i, r := range results {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range sortedKeys(m) {
			if Forbidden(k) {
				return fmt.Errorf("results[%d] sets %s, which no converter may set", i, k)
			}
		}
		if m["reachable"] == false {
			return fmt.Errorf("results[%d] sets reachable false, a lowering no converter may make", i)
		}
	}
	return nil
}

// schema is the contract's schema, read once: the decoded document the walk reads, and the resolved
// schema the backstop validates against.
type schema struct {
	root     map[string]any
	defs     map[string]any
	resolved *jsonschema.Resolved
	// leaves are each leaf's resolved schema, by the leaf's JSON, built as the walk meets them.
	mu     sync.Mutex
	leaves map[string]*jsonschema.Resolved
}

// contract is the embedded schema, parsed and resolved once.
var contract = sync.OnceValue(func() *schema {
	var root map[string]any
	_ = json.Unmarshal(SchemaJSON, &root)
	defs, _ := root["$defs"].(map[string]any)
	return &schema{root: root, defs: defs, resolved: mustResolve(SchemaJSON), leaves: map[string]*jsonschema.Resolved{}}
})

// mustResolve resolves a schema from the embedded contract. The contract is compiled into the
// binary and every test reads files against it, so one that does not resolve is a defect in this
// build rather than in anybody's file, and a panic is the honest report of it.
func mustResolve(raw []byte) *jsonschema.Resolved {
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		panic("converter: the embedded contract is not a schema: " + err.Error())
	}
	resolved, err := s.Resolve(nil)
	if err != nil {
		panic("converter: the embedded contract does not resolve: " + err.Error())
	}
	return resolved
}

// walk holds v to node, the part of the schema it is at, and names the key at fault in what it
// returns: at is v's path in the file, "" for the file itself.
//
// An object with properties is checked for keys the contract does not define and keys it requires,
// then each key against its own schema; an array is checked itself and then each item; anything
// else is a leaf, validated against its schema alone.
func (c *schema) walk(node map[string]any, v any, at string) error {
	if ref, ok := node["$ref"].(string); ok {
		def, _ := c.defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		return c.walk(def, v, at)
	}
	if props, ok := node["properties"].(map[string]any); ok {
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is %s, and the contract takes an object", where(at), kindOf(v))
		}
		if node["additionalProperties"] == false {
			for _, k := range sortedKeys(obj) {
				if _, ok := props[k]; !ok {
					return fmt.Errorf("%s has %s, a key contract version %d does not define", where(at), k, Version)
				}
			}
		}
		required, _ := node["required"].([]any)
		for _, r := range required {
			if _, ok := obj[r.(string)]; !ok {
				return fmt.Errorf("%s has no %s, which the contract requires", where(at), r)
			}
		}
		for _, k := range sortedKeys(obj) {
			sub, ok := props[k].(map[string]any)
			if !ok {
				continue
			}
			if err := c.walk(sub, obj[k], path(at, k)); err != nil {
				return err
			}
		}
		return nil
	}
	// A map of free keys, such as labels: each value against the schema every value is held to.
	if values, ok := node["additionalProperties"].(map[string]any); ok {
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is %s, and the contract takes an object", where(at), kindOf(v))
		}
		for _, k := range sortedKeys(obj) {
			if err := c.walk(values, obj[k], path(at, k)); err != nil {
				return err
			}
		}
		return nil
	}
	if items, ok := node["items"].(map[string]any); ok {
		list := map[string]any{}
		for k, s := range node {
			if k != "items" {
				list[k] = s
			}
		}
		if err := c.leaf(list, v, at); err != nil {
			return err
		}
		arr, _ := v.([]any)
		for i, item := range arr {
			if err := c.walk(items, item, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
		return nil
	}
	return c.leaf(node, v, at)
}

// leaf validates v against node, a schema with no properties or items of its own to walk, and says
// what is wrong in the contract's terms.
func (c *schema) leaf(node map[string]any, v any, at string) error {
	// A node of the decoded schema always marshals.
	key, _ := json.Marshal(node)
	c.mu.Lock()
	resolved, ok := c.leaves[string(key)]
	if !ok {
		resolved = mustResolve(key)
		c.leaves[string(key)] = resolved
	}
	c.mu.Unlock()
	verr := resolved.Validate(v)
	if verr == nil {
		return nil
	}
	msg := verr.Error()
	at = where(at)
	switch {
	case node["enum"] != nil:
		return fmt.Errorf("%s is %s, not one of %s", at, show(v), listOf(node["enum"]))
	case node["const"] != nil:
		return fmt.Errorf("%s is %s, and the contract takes only %s", at, show(v), show(node["const"]))
	case strings.Contains(msg, "type: "):
		return fmt.Errorf("%s is %s, and the contract takes %s", at, kindOf(v), node["type"])
	case strings.Contains(msg, "pattern: "):
		// The pattern itself is left out: a package URL's holds a colon, which the errors block would
		// cut the reason at.
		return fmt.Errorf("%s is %s, not in the form the contract takes", at, show(v))
	case strings.Contains(msg, "minLength: "):
		return fmt.Errorf("%s is empty, and the contract takes a value", at)
	case node["maximum"] != nil && (strings.Contains(msg, "minimum: ") || strings.Contains(msg, "maximum: ")):
		return fmt.Errorf("%s is %s, outside %s to %s", at, show(v), show(node["minimum"]), show(node["maximum"]))
	case strings.Contains(msg, "minimum: "):
		return fmt.Errorf("%s is %s, below %s", at, show(v), show(node["minimum"]))
	case strings.Contains(msg, "uniqueItems: "):
		return fmt.Errorf("%s lists one value twice", at)
	}
	return fmt.Errorf("%s does not follow contract version %d, %s", at, Version, lastClause(msg))
}

// where is a path as an error names it: "the file" for the top.
func where(at string) string {
	if at == "" {
		return "the file"
	}
	return at
}

// path is the key k below at.
func path(at, k string) string {
	if at == "" {
		return k
	}
	return at + "." + k
}

// kindOf names a JSON value's type as an error says it.
func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "a list"
	case map[string]any:
		return "an object"
	}
	return fmt.Sprintf("%T", v)
}

// show is a value as an error quotes it, cut short where it is long.
func show(v any) string {
	var s string
	switch t := v.(type) {
	case string:
		s = strconv.Quote(t)
	case float64:
		s = strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, _ := json.Marshal(t)
		s = string(b)
	}
	if len(s) > 40 {
		s = s[:37] + "..."
	}
	return s
}

// listOf joins an enum's values.
func listOf(v any) string {
	values, _ := v.([]any)
	parts := make([]string, 0, len(values))
	for _, e := range values {
		parts = append(parts, fmt.Sprint(e))
	}
	return strings.Join(parts, ", ")
}

// lastClause is the end of a validator's message, after the last colon, which is the clause that
// says what was wrong.
func lastClause(msg string) string {
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

// sortedKeys are an object's keys in order, so a file with two faults always reports the same one.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
