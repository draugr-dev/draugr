package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func lineFor(fields []SchemaField, path string) (SchemaField, bool) {
	for _, f := range fields {
		if f.Path == path {
			return f, true
		}
	}
	return SchemaField{}, false
}

func TestTheSchemaOutlineNamesEveryTopLevelField(t *testing.T) {
	out, err := GetSchema("")
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	if out.Version == "" {
		t.Error("the schema must say which build it came from, that's the point of asking Draugr rather than the web")
	}
	if out.Schema != nil {
		t.Error("the outline carries lines, not the schema document")
	}
	var root map[string]any
	if err := json.Unmarshal(saga.SchemaJSON, &root); err != nil {
		t.Fatal(err)
	}
	for name := range root["properties"].(map[string]any) {
		if _, ok := lineFor(out.Fields, name); !ok {
			t.Errorf("the outline has no line for the top-level field %q", name)
		}
	}
	exposure, ok := lineFor(out.Fields, "components.exposure")
	if !ok {
		t.Fatal("the outline has no line for components.exposure, the field a model most needs the values of")
	}
	want := []string{"public", "authenticated", "internal", "restricted"}
	if !slices.Equal(exposure.Values, want) {
		t.Errorf("components.exposure values = %v, want %v", exposure.Values, want)
	}
	if exposure.Type != "string" || exposure.Description == "" {
		t.Errorf("components.exposure line = %+v, want its type and description", exposure)
	}
	if labels, _ := lineFor(out.Fields, "components.labels"); labels.Type != "map of string or number or boolean" {
		t.Errorf("components.labels type = %q, want a map of its value types", labels.Type)
	}
	if components, _ := lineFor(out.Fields, "components"); components.Type != "list of object" {
		t.Errorf("components type = %q, want a list of object", components.Type)
	}
}

func TestOneFieldComesBackWithItsDefinitionAndValues(t *testing.T) {
	for _, field := range []string{"components.exposure", "components[0].exposure", "$.components.0.exposure", " components[].exposure "} {
		out, err := GetSchema(field)
		if err != nil {
			t.Fatalf("GetSchema(%q): %v", field, err)
		}
		if out.Field != "components.exposure" {
			t.Errorf("GetSchema(%q).Field = %q, want the plain path", field, out.Field)
		}
		if strings.Contains(out.Hint, "ask for field") {
			t.Errorf("an answer with no pointer in it should not explain pointers: %q", out.Hint)
		}
		raw, _ := json.Marshal(out.Schema)
		for _, want := range []string{`"const":"authenticated"`, "behind authentication", "How reachable"} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("GetSchema(%q) schema lacks %q: %s", field, want, raw)
			}
		}
	}
}

func TestAComponentsAnswerWritesValuesOutAndPointsAtObjects(t *testing.T) {
	out, err := GetSchema("components")
	if err != nil {
		t.Fatal(err)
	}
	props := out.Schema["items"].(map[string]any)["properties"].(map[string]any)
	exposure := props["exposure"].(map[string]any)
	if exposure["anyOf"] == nil {
		t.Errorf("components.exposure is a value and should be written out: %v", exposure)
	}
	imports := props["imports"].(map[string]any)["items"].(map[string]any)
	if imports["$comment"] != "ask for field components.imports" {
		t.Errorf("components.imports is an object and should point at its own path: %v", imports)
	}
	if !strings.Contains(out.Hint, "ask for field <path>") {
		t.Errorf("an answer with a pointer in it says how to follow one: %q", out.Hint)
	}
	if _, ok := lineFor(out.Fields, "components.imports"); !ok {
		t.Error("a field's answer lists the fields under it, so each can be asked for")
	}
	if raw, _ := json.Marshal(out.Schema); strings.Contains(string(raw), "$ref") {
		t.Errorf("a $ref is a pointer into a document the model never sees: %s", raw)
	}
}

func TestAFieldThatDoesNotExistNamesTheOnesThatDo(t *testing.T) {
	_, err := GetSchema("components.exposed")
	if err == nil || !strings.Contains(err.Error(), `components has no field "exposed"`) ||
		!strings.Contains(err.Error(), "exposure") {
		t.Errorf("err = %v, want it to name the component's fields", err)
	}
	_, err = GetSchema("project.name")
	if err == nil || !strings.Contains(err.Error(), "project is a single value with no fields under it") {
		t.Errorf("err = %v, want it to say project holds no fields", err)
	}
	_, err = GetSchema("nonsense")
	if err == nil || !strings.HasPrefix(err.Error(), "The descriptor has no field") {
		t.Errorf("err = %v, want it to say the descriptor has no such field", err)
	}
	if _, err = GetSchema("accounts.provider"); err != nil {
		t.Errorf("a map of objects is looked through to the object, as a list is: %v", err)
	}
}

// Every answer the tool can give, the outline and each field it names, has to fit in one tool
// result a client passes to the model, or the model is left with a file path and a guess. The
// walk follows every path an answer offers, so a field the schema grows is held to the bound
// without anyone adding it here.
func TestEverySchemaAnswerFitsInOneToolResult(t *testing.T) {
	ctx := context.Background()
	sess := connect(t, Options{Registry: builtins.Registry(), Root: t.TempDir()})

	call := func(field string) (string, SchemaOutput) {
		t.Helper()
		params := &mcp.CallToolParams{Name: "get_saga_schema"}
		if field != "" {
			params.Arguments = map[string]any{"field": field}
		}
		res, err := sess.CallTool(ctx, params)
		if err != nil {
			t.Fatalf("get_saga_schema %q: %v", field, err)
		}
		if res.IsError {
			t.Fatalf("get_saga_schema %q errored: %+v", field, res.Content)
		}
		var text strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text.WriteString(tc.Text)
			}
		}
		var out SchemaOutput
		decode(t, res, &out)
		return text.String(), out
	}

	queue := []string{""}
	seen := map[string]bool{"": true}
	largest, largestField := 0, ""
	for len(queue) > 0 {
		field := queue[0]
		queue = queue[1:]
		text, out := call(field)
		if text == "" {
			t.Fatalf("get_saga_schema %q returned no text for a client that reads only content", field)
		}
		if len(text) > largest {
			largest, largestField = len(text), field
		}
		if len(text) > maxSchemaResult {
			t.Errorf("get_saga_schema %q returned %d characters, over the %d a client passes to a model",
				field, len(text), maxSchemaResult)
		}
		next := []string{}
		for _, f := range out.Fields {
			next = append(next, f.Path)
		}
		raw, _ := json.Marshal(out.Schema)
		for _, part := range strings.Split(string(raw), `"ask for field `)[1:] {
			p := part[:strings.IndexByte(part, '"')]
			if p == field {
				t.Errorf("get_saga_schema %q points back at itself, so its definition is never shown", field)
			}
			next = append(next, p)
		}
		for _, p := range next {
			if !seen[p] {
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	// A walk that stopped at the outline would pass for the wrong reason.
	if len(seen) < 200 {
		t.Errorf("the walk reached %d fields; the schema has more than that, so it stopped early", len(seen))
	}
	t.Logf("%d answers; the largest, %q, is %d characters", len(seen), largestField, largest)
}

func TestReferencesThatLoopOrDangleStillAnswer(t *testing.T) {
	s := schemaDoc{
		root: map[string]any{"properties": map[string]any{
			"node":    map[string]any{"$ref": "#/$defs/node"},
			"missing": map[string]any{"$ref": "#/$defs/gone", "description": "points nowhere"},
			"value":   map[string]any{"$ref": "#/$defs/value"},
		}},
		defs: map[string]any{
			"node": map[string]any{
				"type":       "object",
				"properties": map[string]any{"child": map[string]any{"$ref": "#/$defs/node"}},
			},
			"value": map[string]any{"anyOf": []any{
				map[string]any{"const": "a"},
				map[string]any{"$ref": "#/$defs/value"},
			}},
		},
	}
	value, err := s.lookup("value")
	if err != nil {
		t.Fatal(err)
	}
	alts := s.expand(value, "value")["anyOf"].([]any)
	if again := alts[1].(map[string]any); again["$comment"] != "ask for field value" {
		t.Errorf("a value definition that refers to itself is written out once: %v", alts)
	}
	node, err := s.lookup("node.child.child")
	if err != nil {
		t.Fatalf("a definition that refers to itself is still walked: %v", err)
	}
	out := s.expand(node, "node.child.child")
	child := out["properties"].(map[string]any)["child"].(map[string]any)
	if child["$comment"] != "ask for field node.child.child.child" {
		t.Errorf("a definition already being written out is pointed at, not repeated: %v", child)
	}
	missing, err := s.lookup("missing")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.line(missing, "missing"); got.Description != "points nowhere" {
		t.Errorf("a reference to no definition keeps what it says itself: %+v", got)
	}
}

func TestAnOutlineLineIsOneSentence(t *testing.T) {
	for in, want := range map[string]string{
		"Free-form metadata, e.g. team or tier.":    "Free-form metadata, e.g. team or tier.",
		"How reachable.\n  Used to rank findings.":  "How reachable.",
		"Deprecated: write `controls`. Still read.": "Deprecated: write `controls`.",
		"": "",
	} {
		if got := firstSentence(in); got != want {
			t.Errorf("firstSentence(%q) = %q, want %q", in, got, want)
		}
	}
}
