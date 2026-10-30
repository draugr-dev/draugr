package schemagen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/observability"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// durationPattern is what Go's time.ParseDuration reads, without a sign: `draugr config validate`
// refuses a negative ttl, and the decoder refuses a bare number other than as the string "0".
const durationPattern = `^\+?(0|(([0-9]+(\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h))+)$`

// freeText is the shape of a free-form scalar. YAML reads `1.20` as a number and `true` as a
// boolean, and the decoder keeps the text of either in a string field, so a version written
// unquoted loads.
func freeText() map[string]any { return map[string]any{"type": []any{"string", "number", "boolean"}} }

// stringsAny is values as the []any a schema's enum holds.
func stringsAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// configFields describes every key of draugr.config.yaml by its dotted path, `*` standing for a
// tool name. Each entry is laid over the shape read from the Go type, so it carries the
// description and any constraint the type cannot state.
//
// A field of config.File with no entry fails generation. The struct is where a key is added, and
// this is the one place its reader is told what it does.
func configFields() map[string]map[string]any {
	views := make([]any, 0, len(report.Views()))
	for _, v := range report.Views() {
		views = append(views, map[string]any{"const": string(v), "description": v.Summary()})
	}
	return map[string]map[string]any{
		"tools": {
			"description": "The version of each external tool `draugr tools install` provisions, keyed by tool name.",
		},
		"tools.*": {
			"description": "Settings for one tool.",
		},
		"tools.*.version": {
			"description": "The version to install, e.g. `0.69.3`.",
		},
		"controls": {
			"description": "Default settings for each control, merged underneath a descriptor's `config.controls`, " +
				"so a project overrides only the keys it names. The same shape as `config.controls` in a Saga.",
		},
		"controllers": {
			"description": "Deprecated: write `controls`. Read as `controls`; `controls` wins where both set a key.",
		},
		"cache": {
			"description": "Where scan results are reused between runs, and for how long.",
		},
		"cache.dir": {
			"description": "The directory results are cached in. Unset leaves caching off. Overridden by `--cache-dir`.",
		},
		"cache.ttl": {
			"description": "How long a cached result stays usable, as a duration such as `24h`. `0s` means no " +
				"expiry; unset keeps the built-in default. Overridden by `--cache-ttl`.",
			"pattern": durationPattern,
		},
		"cache.readOnly": {
			"description": "Serve cached results without writing new ones. A project file's `false` does not " +
				"override a `true` set in `~/.draugr/config.yaml`. Overridden by `--cache-read-only`.",
		},
		"cache.requireDigest": {
			"description": "Refuse to cache an image named only by a tag, which can be rebuilt under the same name. " +
				"A project file's `false` does not override a `true` set in `~/.draugr/config.yaml`. " +
				"Overridden by `--cache-require-digest`.",
		},
		"publish": {
			"description": "Defaults for where a run is delivered.",
		},
		"publish.apiUrl": {
			"description": "Where the `draugr-api` publisher posts when `$DRAUGR_API_URL` is unset. In a project's " +
				"draugr.config.yaml it is used only on the origin of `publish.apiUrl` in `~/.draugr/config.yaml`, " +
				"or one `$DRAUGR_API_ORIGINS` lists. Never holds a token.",
		},
		"output": {
			"description": "How a console report is rendered. A flag on the command line overrides each setting.",
		},
		"output.view": {
			"description": "What a console report shows. Overridden by `--view`.",
			"type":        "string",
			"anyOf":       views,
		},
		"output.evidence": {
			"description": "Also print what stands behind the verdict: tool provenance, what each control measured " +
				"against, the scanned revision, and what the run cost. Overridden by `--evidence`.",
		},
		"output.top": {
			"description": "How many rows a console report lists. `0` keeps the command's own default, a cap for " +
				"`scan` and every row for `diff`. Overridden by `--top`.",
			"minimum": 0,
		},
		"output.offerInstall": {
			"description": "Whether `draugr scan` on a terminal offers to install the scanners it is missing. " +
				"Unset means it offers.",
		},
		"output.tips": {
			"description": "Whether a console scan prints its contextual tips and its progress line. Unset means " +
				"it prints them. Overridden by `--no-tips` and `$DRAUGR_NO_TIPS`.",
		},
		"scan": {
			"description": "How a scan runs on this machine.",
		},
		"scan.jobs": {
			"description": "How many scan jobs run at once. `0` means one per CPU. Overridden by `--jobs`.",
			"minimum":     0,
		},
		"log": {
			"description": "What Draugr logs, and in which format.",
		},
		"log.level": {
			"description": "The least severe level logged. Overridden by `--log-level`.",
			"type":        "string",
			"enum":        stringsAny(observability.Levels),
		},
		"log.format": {
			"description": "How log records are written. Overridden by `--log-format`.",
			"type":        "string",
			"enum":        stringsAny(observability.Formats),
		},
		"offline": {
			"description": "Make no network calls: optional fetches are skipped, and commands that exist to " +
				"download refuse. A more specific file's `false` does not turn it off. Overridden by " +
				"`--offline` and `$DRAUGR_OFFLINE`.",
		},
	}
}

// configShaper reads config.File into a schema, one field at a time.
type configShaper struct {
	docs map[string]map[string]any
	defs map[string]any
	used map[string]bool
}

var (
	durationType = reflect.TypeOf(time.Duration(0))
	controlsType = reflect.TypeOf(map[string]saga.ControllerSettings{})
	toolsType    = reflect.TypeOf(map[string]config.ToolSettings{})
)

// shape is the schema for a value of type t found at path, with its entry in configFields laid
// over it.
func (s *configShaper) shape(t reflect.Type, path string) (map[string]any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var node map[string]any
	switch {
	case t == durationType:
		node = map[string]any{"type": "string"}
	case t == controlsType:
		node = map[string]any{"$ref": "#/$defs/controllers"}
	case t == toolsType:
		def, err := s.shape(t.Elem(), path+".*")
		if err != nil {
			return nil, err
		}
		s.defs["toolSettings"] = def
		props := map[string]any{}
		for _, name := range tools.Installable() {
			props[name] = map[string]any{"$ref": "#/$defs/toolSettings"}
		}
		node = map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	case t.Kind() == reflect.Struct:
		props := map[string]any{}
		for i := range t.NumField() {
			key, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
			if key == "" || key == "-" {
				continue
			}
			child, err := s.shape(t.Field(i).Type, strings.TrimPrefix(path+"."+key, "."))
			if err != nil {
				return nil, err
			}
			props[key] = child
		}
		node = map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	case t.Kind() == reflect.String:
		node = freeText()
	case t.Kind() == reflect.Bool:
		node = map[string]any{"type": "boolean"}
	case t.Kind() == reflect.Int:
		node = map[string]any{"type": "integer"}
	default:
		return nil, fmt.Errorf("%s: no JSON Schema shape for a %s; teach configShaper.shape the type", path, t)
	}
	if path == "" {
		return node, nil
	}
	doc, ok := s.docs[path]
	if !ok {
		return nil, fmt.Errorf("%s has no entry in configFields, so the schema cannot say what it does", path)
	}
	s.used[path] = true
	for k, v := range doc {
		node[k] = v
	}
	return node, nil
}

// reachable copies into out the definition name and every definition it refers to, from defs.
func reachable(defs map[string]any, name string, out map[string]any) error {
	if _, done := out[name]; done {
		return nil
	}
	def, ok := defs[name]
	if !ok {
		return fmt.Errorf("schema has no %s definition", name)
	}
	out[name] = def
	var refs []string
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok {
				if target, found := strings.CutPrefix(ref, "#/$defs/"); found {
					refs = append(refs, target)
				}
			}
			for _, c := range v {
				walk(c)
			}
		case []any:
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(def)
	sort.Strings(refs)
	for _, r := range refs {
		if err := reachable(defs, r, out); err != nil {
			return err
		}
	}
	return nil
}

// ConfigSchema derives the JSON Schema for draugr.config.yaml from the Saga's.
//
// Its `controls` block is the Saga's own `controllers` definition and the per-control definitions
// it refers to, copied rather than rebuilt, so a control name, a scanner key and a scanner option
// are held to the same rule in both files, and `draugr config validate` checks the same ones. The
// rest is read from config.File by reflection: a field added there reaches the schema on the next
// `go generate`, and generation fails until configFields says what it does.
func ConfigSchema(sagaJSON []byte) ([]byte, error) { return configSchema(sagaJSON, configFields()) }

// configSchema is ConfigSchema with the field descriptions passed in.
func configSchema(sagaJSON []byte, docs map[string]map[string]any) ([]byte, error) {
	var sagaDoc map[string]any
	if err := json.Unmarshal(sagaJSON, &sagaDoc); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	sagaDefs, ok := sagaDoc["$defs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema has no $defs object")
	}
	s := &configShaper{docs: docs, defs: map[string]any{}, used: map[string]bool{}}
	if err := reachable(sagaDefs, "controllers", s.defs); err != nil {
		return nil, err
	}
	root, err := s.shape(reflect.TypeOf(config.File{}), "")
	if err != nil {
		return nil, err
	}
	var stale []string
	for path := range s.docs {
		if !s.used[path] {
			stale = append(stale, path)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		return nil, fmt.Errorf("configFields describes %s, which config.File does not have", strings.Join(stale, ", "))
	}

	root["$schema"] = sagaDoc["$schema"]
	root["$id"] = saga.ConfigSchemaURL
	root["$comment"] = "Generated in full from the Saga schema and pkg/config; before editing it by hand, " +
		"read docs/contributing/schema.md in the draugr repository."
	root["title"] = "Draugr configuration"
	root["description"] = "The draugr.config.yaml file: settings for the machine or organization running a " +
		"scan, layered underneath every descriptor it scans. See " + config.KeysURL
	root["$defs"] = s.defs

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
