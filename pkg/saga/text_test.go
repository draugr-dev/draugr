package saga

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A value YAML reads as a boolean or a number, in a field that takes text, still loads as written
// and is named with its line and the quoted spelling to copy.
func TestAnUnquotedValueInATextFieldIsNamedWithItsFix(t *testing.T) {
	m, err := Load([]byte(`project: shop
release:
  version: 1.0
components:
  - name: web
    repositories:
      - url: .
        revision: 20240101
config:
  publishers:
    - kind: file
      dir: true
      reports:
        - format: sarif
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`release.version: 1.0 on line 3 is read as a number, and this field takes text. Write it in quotes, "1.0"; a later release refuses it unquoted.`,
		`components[0].repositories[0].revision: 20240101 on line 8 is read as a number, and this field takes text. Write it in quotes, "20240101"; a later release refuses it unquoted.`,
		`config.publishers[0].dir: true on line 12 is read as a boolean, and this field takes text. Write it in quotes, "true"; a later release refuses it unquoted.`,
	}
	if got := m.TextWarnings(); !slices.Equal(got, want) {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if m.Release.Version != "1.0" || m.Config.Publishers[0].Dir != "true" || m.Components[0].Repositories[0].Revision != "20240101" {
		t.Errorf("the values did not load as written: %q %q %q", m.Release.Version,
			m.Config.Publishers[0].Dir, m.Components[0].Repositories[0].Revision)
	}
}

// Each kind of scalar YAML reads as something other than text is caught, and nothing else is: a
// quoted value, a value under a map such as a label, and a field whose Go type is a number or a
// boolean.
func TestOnlyUnquotedTextIsNamed(t *testing.T) {
	for _, c := range []struct {
		name, doc string
		want      []string
	}{
		{"a boolean", "release: {version: false}", []string{"release.version: false on line 1 is read as a boolean"}},
		{"an integer", "release: {version: 2}", []string{"release.version: 2 on line 1 is read as a number"}},
		{"a float", "release: {version: 1.10}", []string{"release.version: 1.10 on line 1 is read as a number"}},
		{"a list item", "components: [{name: a, repositories: [{url: ., paths: [src, 404]}]}]",
			[]string{"components[0].repositories[0].paths[1]: 404 on line 1"}},
		{"a cluster's version under a map of structs", "clusters:\n  prod:\n    version: 1.34",
			[]string{"clusters.prod.version: 1.34 on line 3"}},
		{"double quotes", `release: {version: "1.0"}`, nil},
		{"single quotes", `release: {version: '1.0'}`, nil},
		{"a block scalar", "release:\n  version: |\n    1.0", nil},
		{"an explicit tag", "release: {version: !!str 1.0}", nil},
		{"text that is text", "release: {version: v1.0}", nil},
		{"a label", "components: [{name: a, labels: {pci: true, tier: 1}}]", nil},
		{"a number field", "config: {publishers: [{kind: github-pr-comment, pr: 12}]}", nil},
		{"a boolean field", "config: {sbom: {enabled: true}}", nil},
		{"a float field", "config: {exploitability: {epssThreshold: 0.5}}", nil},
		{"scanner options", "config: {controls: {sast: {semgrep: {jobs: 2}}}}", nil},
		{"allowEffects, which decodes itself", "config: {allowEffects: [network]}", nil},
		{"a key no field has", "bogus: true", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var root yaml.Node
			if err := yaml.Unmarshal([]byte(c.doc), &root); err != nil {
				t.Fatal(err)
			}
			got := textWarnings(&root, reflect.TypeOf(Model{}), "")
			if len(got) != len(c.want) {
				t.Fatalf("warnings %q, want %d", got, len(c.want))
			}
			for i := range got {
				if !strings.HasPrefix(got[i], c.want[i]) {
					t.Errorf("warning %q, want it to start %q", got[i], c.want[i])
				}
			}
		})
	}
}

// An alias is followed to the value it names, which is where the line is.
func TestAnAliasedValueIsNamedWhereItIsWritten(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("clusters:\n  a: &c\n    version: 1.34\n  b: *c\n"), &root); err != nil {
		t.Fatal(err)
	}
	got := UnquotedTexts(&root, reflect.TypeOf(Model{}))
	if len(got) != 2 || got[1].Path != "clusters.b.version" || got[1].Line != 3 {
		t.Errorf("found %+v, want both clusters' version, on line 3", got)
	}
}

// A fragment's warnings name the fragment, on its own and once merged into the descriptor that
// collects it.
func TestAFragmentsUnquotedTextIsNamedWithTheFragment(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	frag := write("team.saga-fragment.yaml", "components:\n  - name: 2026\n    repositories:\n      - url: .\n")
	root := write("draugr.saga.yaml", "project: shop\nfragments:\n  - path: team.saga-fragment.yaml\n")

	data, err := os.ReadFile(frag) // #nosec G304 -- a file this test wrote
	if err != nil {
		t.Fatal(err)
	}
	f, err := LoadFragment(data, frag)
	if err != nil {
		t.Fatal(err)
	}
	want := `fragment "` + frag + `": components[0].name: 2026 on line 2 is read as a number`
	if got := f.TextWarnings(); len(got) != 1 || !strings.HasPrefix(got[0], want) {
		t.Errorf("fragment warnings %q, want one starting %q", got, want)
	}

	res, err := ResolveFile(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	merged := `fragment "` + filepath.Join(dir, "team.saga-fragment.yaml") + `": components[0].name: 2026`
	if got := res.Model.TextWarnings(); len(got) != 1 || !strings.HasPrefix(got[0], merged) {
		t.Errorf("merged warnings %q, want one starting %q", got, merged)
	}
}
