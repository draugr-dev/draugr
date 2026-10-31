package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/observability"
	"github.com/draugr-dev/draugr/internal/suggest"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// What a key accepts, in the words a refusal of it uses: pkg/config's decoder for a value of the
// wrong type, and valueProblems for one out of range. TestEveryConfigKeyAcceptsWhatValidateSays
// holds each row to the refusal `draugr config validate` prints.
const (
	acceptsBool     = "true or false"
	acceptsDuration = "a duration such as 12h"
	acceptsCount    = "a whole number of 0 or more"
)

// toolPlaceholder stands for every tool in the key that pins one.
const toolPlaceholder = "<tool>"

// configKey is one row of `draugr config keys`.
type configKey struct {
	key string
	// accepts is what the key takes, in the words a refusal of it uses.
	accepts string
	// def is the value in effect when no file sets the key, or "-" where the schema declares none.
	def string
}

// machineKeys says what each key outside `controls` accepts and defaults to, by the dotted key
// config.File's yaml tags give it.
//
// Every field of config.File needs a row: TestEveryConfigFieldHasAKeysRow walks the struct, and
// internal/schemagen refuses one that configFields does not describe. TestEveryConfigKeyDefaultIs
// TheOneTheCodeApplies holds each default to the flag or the code that applies it.
var machineKeys = map[string]struct{ accepts, def string }{
	"cache.dir":            {"a directory", "none, caching off"},
	"cache.readOnly":       {acceptsBool, "false"},
	"cache.requireDigest":  {acceptsBool, "false"},
	"cache.ttl":            {acceptsDuration + "; 0s, no expiry", "24h"},
	"log.format":           {list(observability.Formats), "console"},
	"log.level":            {list(observability.Levels), "info"},
	"offline":              {acceptsBool, "false"},
	"output.evidence":      {acceptsBool, "false"},
	"output.offerInstall":  {acceptsBool, "true"},
	"output.tips":          {acceptsBool, "true"},
	"output.top":           {acceptsCount, "10 for scan, every row for diff"},
	"output.view":          {list(viewNames()), "findings"},
	"publish.apiUrl":       {"a URL", "none"},
	"scan.jobs":            {acceptsCount + "; 0, one per CPU", "0"},
	"tools.<tool>.version": {"a release, such as 0.69.3", "Draugr's pin"},
}

// viewNames is every value output.view takes.
func viewNames() []string {
	out := make([]string, 0, len(report.Views()))
	for _, v := range report.Views() {
		out = append(out, string(v))
	}
	return out
}

// machineKeyNames lists the keys of config.File outside `controls`, read from its yaml tags as
// fieldsAt reads them, so a field added there is listed with no second list to keep in step.
func machineKeyNames() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		switch {
		case t.Kind() == reflect.Struct:
			for i := range t.NumField() {
				name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
				if name == "" || name == "-" {
					continue
				}
				if prefix != "" {
					name = prefix + "." + name
				}
				walk(t.Field(i).Type, name)
			}
		case t.Kind() == reflect.Map && t.Elem().Kind() == reflect.Struct:
			// A map of settings by name, such as a pin per tool: one row stands for every name.
			walk(t.Elem(), prefix+"."+toolPlaceholder)
		case t.Kind() == reflect.Map:
			// controls and its older spelling: free-form here, and listed from the registry.
		default:
			out = append(out, prefix)
		}
	}
	walk(reflect.TypeOf(config.File{}), "")
	sort.Strings(out)
	return out
}

// machineRows is a row for each key outside `controls`, `tools.<tool>.version` standing for every
// tool.
func machineRows() []configKey {
	names := machineKeyNames()
	out := make([]configKey, 0, len(names))
	for _, name := range names {
		facts, ok := machineKeys[name]
		if !ok {
			// Listed rather than hidden, so a key nobody described is still a key somebody can find.
			facts.accepts, facts.def = "-", "-"
		}
		out = append(out, configKey{key: name, accepts: facts.accepts, def: facts.def})
	}
	return out
}

// toolRows is a row per tool `draugr tools install` provisions, each defaulting to its pin.
func toolRows(placeholder configKey) []configKey {
	names := tools.Installable()
	sort.Strings(names)
	out := make([]configKey, 0, len(names))
	for _, name := range names {
		out = append(out, configKey{
			key:     strings.Replace(placeholder.key, toolPlaceholder, name, 1),
			accepts: placeholder.accepts,
			def:     tools.PinnedVersion(name),
		})
	}
	return out
}

// keyCatalog is every key the file can hold under this build, read from config.File, the tool
// catalog and the registry.
type keyCatalog struct {
	reg *engine.Registry
	// serving lists the scanners of each control, by name, in registry order.
	serving map[string][]string
	// schemas holds each scanner's ConfigSchema, by name.
	schemas map[string]json.RawMessage
}

func newKeyCatalog(reg *engine.Registry) keyCatalog {
	c := keyCatalog{reg: reg, serving: servingScanners(reg), schemas: map[string]json.RawMessage{}}
	for _, s := range reg.Scanners() {
		c.schemas[s.Info().Name] = s.Info().ConfigSchema
	}
	return c
}

// controlRows is every key of one control: whether it runs, its own settings, then each scanner's
// block in the order `draugr controls` names them.
func (c keyCatalog) controlRows(info plugin.ControllerInfo) []configKey {
	base := "controls." + info.Name
	// A block with no `enabled` key supplies settings to a control the descriptor turns on, and
	// `enabled: true` turns the control on where the descriptor leaves it out.
	out := []configKey{{key: base + ".enabled", accepts: acceptsBool, def: "off unless the descriptor turns it on"}}
	out = append(out, optionRows(base, info.OptionSchema)...)
	for _, s := range scannersOf(info, c.serving[info.Name]) {
		if s.analyzer {
			continue // enabled under config.reachability, and refused as a block
		}
		key := base + "." + controllers.ScannerConfigKey(s.name)
		def := "true"
		if s.optIn {
			def = "false"
		}
		out = append(out, configKey{key: key + ".enabled", accepts: acceptsBool, def: def})
		out = append(out, optionRows(key, c.schemas[s.name])...)
	}
	return out
}

// all is every key, each control's and each tool's included: what --all prints and a prefix
// narrows.
func (c keyCatalog) all() []configKey {
	var out []configKey
	for _, r := range machineRows() {
		if strings.Contains(r.key, toolPlaceholder) {
			out = append(out, toolRows(r)...)
			continue
		}
		out = append(out, r)
	}
	for _, ctrl := range c.reg.Controllers() {
		out = append(out, c.controlRows(ctrl.Info())...)
	}
	return out
}

// names is every key and every section above one, for the nearest match to a mistyped key.
func (c keyCatalog) names() map[string]bool {
	out := map[string]bool{}
	for _, r := range c.all() {
		parts := strings.Split(r.key, ".")
		for i := range parts {
			out[strings.Join(parts[:i+1], ".")] = true
		}
	}
	return out
}

// optionRows is a row for each setting a schema declares, under prefix.
func optionRows(prefix string, schema json.RawMessage) []configKey {
	opts := plugin.Options(schema)
	out := make([]configKey, 0, len(opts))
	for _, o := range opts {
		out = append(out, configKey{key: prefix + "." + o.Name, accepts: optionAccepts(o), def: optionDefault(o)})
	}
	return out
}

// typeWords names a JSON Schema type as pkg/config names the Go type behind a key.
var typeWords = map[string]string{
	"boolean": acceptsBool,
	"integer": "a whole number",
	"number":  "a number",
	"string":  "a string",
	"array":   "a list",
	"object":  "a mapping",
}

// optionAccepts says what an option takes: its values when the schema names them, the words a
// refusal of its pattern uses, or else its type.
func optionAccepts(o plugin.Option) string {
	var s string
	switch {
	case len(o.Enum) > 0 && o.Type == "array":
		s = "a list of " + strings.Join(o.Enum, ", ")
	case len(o.Enum) > 0:
		s = list(o.Enum)
	case plugin.PatternName(o.Pattern) != "":
		s = plugin.PatternName(o.Pattern)
	case typeWords[o.Type] != "":
		s = typeWords[o.Type]
	default:
		s = "a value"
	}
	if o.Required {
		s += ", required"
	}
	return s
}

// optionDefault is the default an option's schema declares, or "-" where it declares none.
func optionDefault(o plugin.Option) string {
	var node map[string]json.RawMessage
	if json.Unmarshal(o.Schema, &node) != nil {
		return "-"
	}
	raw, ok := node["default"]
	if !ok {
		return "-"
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "-"
	}
	return defaultText(v)
}

// defaultText writes a declared default as it would be typed into the file: a list as its items.
func defaultText(v any) string {
	switch t := v.(type) {
	case []any:
		items := make([]string, len(t))
		for i, item := range t {
			items[i] = defaultText(item)
		}
		return strings.Join(items, ", ")
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

func newConfigKeysCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "keys [prefix]",
		Short: "List every key, what it accepts and its default",
		Long: "List the keys draugr.config.yaml can hold, with what each accepts and its default.\n" +
			"`draugr config show` prints the values in effect.\n\n" +
			"Each control is one line naming its scanners' keys. A prefix lists the keys under it,\n" +
			"and a control's name lists that control's keys:\n\n" +
			"  draugr config keys controls.sca",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := ""
			if len(args) == 1 {
				prefix = args[0]
			}
			return runConfigKeys(cmd.OutOrStdout(), builtins.Registry(), prefix, all)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false,
		"list every key on a line of its own, each control's and each tool's included")
	return cmd
}

// runConfigKeys prints the catalog: every key outside `controls` and a line per control, or, with
// a prefix or all, every key it covers on a line of its own.
func runConfigKeys(w io.Writer, reg *engine.Registry, prefix string, all bool) error {
	cat := newKeyCatalog(reg)
	col := tui.For(w)
	prefix = config.CurrentKey(strings.TrimSuffix(prefix, "."))
	if prefix == "" && !all {
		writeKeySummary(w, col, cat)
		return nil
	}
	var rows []configKey
	for _, r := range cat.all() {
		if prefix == "" || r.key == prefix || strings.HasPrefix(r.key, prefix+".") {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		return unknownKey(prefix, cat)
	}
	writeKeyTable(w, col, rows)
	if note := optionsNote(rows); note != "" {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, note))
	}
	return nil
}

// writeKeyTable renders rows as Key, Accepts and Default.
func writeKeyTable(w io.Writer, col tui.Painter, rows []configKey) {
	t := tui.NewTable(col, "Key", "Accepts", "Default")
	for _, r := range rows {
		t.Row(tui.PlainCell(r.key), tui.PlainCell(r.accepts), tui.PlainCell(r.def))
	}
	t.Render(w)
}

// writeKeySummary renders the keys outside `controls`, the tools a pin may name, and a line per
// control naming its scanners' keys.
func writeKeySummary(w io.Writer, col tui.Painter, cat keyCatalog) {
	writeKeyTable(w, col, machineRows())

	names := tools.Installable()
	sort.Strings(names)
	_, _ = fmt.Fprintf(w, "\n%s\n", wrapWords("Tools: "+strings.Join(names, ", ")+".", 80))

	_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleAccent, "Controls, each a block of its own:"))
	t := tui.NewTable(col).Indent("  ")
	optIn := false
	for _, ctrl := range cat.reg.Controllers() {
		info := ctrl.Info()
		var keys []string
		for _, s := range scannersOf(info, cat.serving[info.Name]) {
			switch {
			case s.analyzer:
			case s.optIn:
				keys = append(keys, controllers.ScannerConfigKey(s.name)+"*")
				optIn = true
			default:
				keys = append(keys, controllers.ScannerConfigKey(s.name))
			}
		}
		t.Row(tui.PlainCell("controls."+info.Name), tui.PlainCell(strings.Join(keys, ", ")))
	}
	t.Render(w)
	note := "`draugr config keys controls.<control>` lists one control's keys."
	if optIn {
		note = "* opt-in. " + note
	}
	_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, note))
}

// optionsNote points from a listing of control keys at what each option does, saying first what
// a `-` default is when the listing shows one, or is "" for a listing with no control keys.
func optionsNote(rows []configKey) string {
	controls := map[string]bool{}
	dash := false
	for _, r := range rows {
		parts := strings.Split(r.key, ".")
		if len(parts) > 2 && parts[0] == "controls" {
			controls[parts[1]] = true
		}
		dash = dash || r.def == "-"
	}
	note := "`draugr controls --options` says what each option does."
	switch len(controls) {
	case 0:
		return ""
	case 1:
		for name := range controls {
			note = fmt.Sprintf("`draugr controls %s --options` says what each option does.", name)
		}
	}
	if dash {
		note = "- no default of its own. " + note
	}
	return note
}

// wrapWords breaks s into lines of at most width, between words.
func wrapWords(s string, width int) string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return strings.Join(append(lines, line), "\n")
}

// unknownKey is the error for a key, or a prefix, that names nothing the file can hold.
func unknownKey(key string, cat keyCatalog) error {
	msg := fmt.Sprintf("%q is not a setting Draugr has", key)
	if near := suggest.Nearest(key, cat.names()); near != "" {
		return fmt.Errorf("%s, did you mean %q? %s", msg, near, config.KeysHint)
	}
	return fmt.Errorf("%s; %s", msg, config.KeysHint)
}

// configKeysMarkdown is the table of keys outside `controls` that docs/reference/cli.md carries:
// the rows `draugr config keys` prints, with what each does from schema, the config schema, so the
// page and the command read one source and an editor's hover reads the same sentence.
func configKeysMarkdown(schema []byte) (string, error) {
	desc, err := schemaDescriptions(schema)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("| Key | Accepts | Default | What it does |\n|---|---|---|---|\n")
	for _, r := range machineRows() {
		d, ok := desc[r.key]
		if !ok {
			return "", fmt.Errorf("the config schema says nothing about %s; describe it in configFields "+
				"(internal/schemagen/config.go) and run `go generate ./pkg/saga/...`", r.key)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.key, cellText(r.accepts), cellText(r.def), cellText(d))
	}
	return b.String(), nil
}

// cellText escapes what would end a markdown table cell.
func cellText(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// schemaDescriptions reads the description of every key outside `controls` from the config
// schema, by dotted key, a tool's name read as <tool>.
func schemaDescriptions(doc []byte) (map[string]string, error) {
	var root map[string]any
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("parse the config schema: %w", err)
	}
	defs, _ := root["$defs"].(map[string]any)
	out := map[string]string{}
	var walk func(node map[string]any, path string)
	walk = func(node map[string]any, path string) {
		if ref, ok := node["$ref"].(string); ok {
			if def, found := defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any); found {
				node = def
			}
		}
		if d, ok := node["description"].(string); ok && path != "" {
			out[path] = d
		}
		props, _ := node["properties"].(map[string]any)
		for name, child := range props {
			sub, ok := child.(map[string]any)
			if !ok || (path == "" && (name == "controls" || name == "controllers")) {
				continue
			}
			key := name
			switch {
			case path == "tools":
				key = path + "." + toolPlaceholder
			case path != "":
				key = path + "." + name
			}
			walk(sub, key)
		}
	}
	walk(root, "")
	return out, nil
}
