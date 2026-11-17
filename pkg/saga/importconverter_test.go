package saga

import (
	"strings"
	"testing"
)

// The descriptor is what grants a converter anything, so it is held to the fixed list: a property
// no converter may set is refused as such, an unknown one as unknown, and a converter beside a
// format that reads none, or a converter's format with none declared, is refused.
func TestAnImportsConverterIsHeldToTheFixedList(t *testing.T) {
	conv := func(c ImportConverter) Import {
		return Import{Control: "sca", File: "deps.draugr.json", Format: ImportFormatConverter, Converter: &c}
	}
	for _, c := range []struct {
		name string
		imp  Import
		want string // "" for none
	}{
		{"every allowed property", conv(ImportConverter{Name: "acme-deps", Contract: 1,
			Sets: []string{"package", "cwe", "labels", "reachable", "raise"}}), ""},
		{"none", conv(ImportConverter{Name: "acme-deps", Contract: 1}), ""},
		{"a forbidden property", conv(ImportConverter{Name: "acme-deps", Contract: 1, Sets: []string{"cwe", "aside"}}),
			"imports[0].converter.sets[1] is aside, which no converter may set"},
		{"a suppression", conv(ImportConverter{Name: "acme-deps", Contract: 1, Sets: []string{"suppression"}}),
			"imports[0].converter.sets[0] is suppression, which no converter may set"},
		{"an unknown property", conv(ImportConverter{Name: "acme-deps", Contract: 1, Sets: []string{"CWE"}}),
			`imports[0].converter.sets[0] is "CWE", not package, cwe, labels, reachable or raise`},
		{"listed twice", conv(ImportConverter{Name: "acme-deps", Contract: 1, Sets: []string{"cwe", "cwe"}}),
			"imports[0].converter.sets lists cwe twice"},
		{"a name in capitals", conv(ImportConverter{Name: "Acme", Contract: 1}),
			`imports[0].converter.name "Acme" is not lowercase letters, digits and hyphens`},
		{"no contract", conv(ImportConverter{Name: "acme-deps"}),
			"imports[0].converter.contract is missing. Draugr reads contract version 1"},
		{"another contract", conv(ImportConverter{Name: "acme-deps", Contract: 2}),
			"imports[0].converter.contract is 2, and Draugr reads contract version 1"},
		{"no converter", Import{Control: "sca", File: "x.json", Format: ImportFormatConverter},
			"imports[0]: format draugr-converter needs converter, the converter that wrote the file"},
		{"a converter beside SARIF", Import{Control: "sca", File: "x.sarif", Converter: &ImportConverter{Name: "acme-deps", Contract: 1}},
			"imports[0].converter is set, and format sarif reads no converter's file. Set format draugr-converter"},
		{"suppressions", func() Import {
			i := conv(ImportConverter{Name: "acme-deps", Contract: 1})
			i.Suppressions = ImportSuppressionsCount
			return i
		}(), "imports[0].suppressions has nothing to apply to, since a converter's file records none. Remove it"},
		{"a severity mapping", func() Import {
			i := conv(ImportConverter{Name: "acme-deps", Contract: 1})
			i.Severity = &ImportSeverity{Property: "p", Values: map[string]string{"x": "high"}}
			return i
		}(), "imports[0].severity maps a SARIF property"},
	} {
		t.Run(c.name, func(t *testing.T) {
			errs := validateImports([]Import{c.imp}, nil, "components[0]")
			if c.want == "" {
				if len(errs) > 0 {
					t.Errorf("refused: %v", errs)
				}
				return
			}
			found := false
			for _, err := range errs {
				found = found || strings.Contains(err.Error(), c.want)
			}
			if !found {
				t.Errorf("errors %v, want one saying %q", errs, c.want)
			}
		})
	}
}

// A fragment may come from another team, and a converter's properties rest on the reviewed
// descriptor, so a fragment declaring one, or importing a converter's file, is refused, naming the
// fragment and where to declare it, in a reason the errors block shows whole.
func TestAFragmentMayNotDeclareAConverter(t *testing.T) {
	for _, c := range []struct{ name, imp string }{
		{"a converter", "format: draugr-converter\n        converter: {name: npm-audit, contract: 1, sets: [package]}"},
		{"the format alone", "format: draugr-converter"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadFragment([]byte(`components:
  - name: web
    imports:
      - control: sca
        file: npm-audit.draugr.json
        `+c.imp+`
`), "team.saga-fragment.yaml")
			if err == nil {
				t.Fatal("a fragment declared a converter")
			}
			msg := err.Error()
			reason := msg[strings.LastIndex(msg, ": ")+2:]
			if !strings.HasPrefix(msg, `fragment "team.saga-fragment.yaml": `) ||
				!strings.Contains(msg, `component "web" imports[0] has a converter. Declare it in the descriptor`) {
				t.Errorf("error %q, want the fragment named and the converter sent to the descriptor", msg)
			}
			if !strings.HasSuffix(reason, "Declare it in the descriptor") || len(reason) > 80 {
				t.Errorf("the errors block shows %q, %d columns", reason, len(reason))
			}
		})
	}
	// The same import in the descriptor itself loads.
	if _, err := Load([]byte("project: shop\ncomponents:\n  - name: web\n    imports:\n      - control: sca\n" +
		"        file: npm-audit.draugr.json\n        format: draugr-converter\n" +
		"        converter: {name: npm-audit, contract: 1, sets: [package]}\n")); err != nil {
		t.Errorf("the descriptor's own converter import: %v", err)
	}
}

func TestADescriptorLoadsAConverterImport(t *testing.T) {
	m, err := Load([]byte(`project: shop
components:
  - name: web
    repositories:
      - url: .
    imports:
      - control: sca
        file: npm-audit.draugr.json
        format: draugr-converter
        converter:
          name: npm-audit
          contract: 1
          sets: [package, cwe]
`))
	if err != nil {
		t.Fatal(err)
	}
	c := m.Components[0].Imports[0].Converter
	if c == nil || c.Name != "npm-audit" || c.Contract != 1 || strings.Join(c.Sets, ",") != "package,cwe" {
		t.Errorf("converter %+v", c)
	}
}
