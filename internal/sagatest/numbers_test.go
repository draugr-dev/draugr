package sagatest

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestAnUnquotedScalarIsKeptAsWritten holds both readers to a free-form value YAML reads as a
// number or a boolean. The editor sees 1.10, 2024 and true; draugr keeps the text, so the version
// is "1.10" rather than "1.1", and neither reader refuses the file.
func TestAnUnquotedScalarIsKeptAsWritten(t *testing.T) {
	descriptor := []byte(`project: 2024
release:
  version: 1.10
components:
  - name: 2024
    labels:
      tier: 01
      pci: true
    repositories:
      - url: .
        revision: 20240101
  - name: true
    repositories:
      - url: .
`)
	BothAccept(t, descriptor, false)
	s, err := saga.Load(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Project != "2024" || s.Release.Version != "1.10" {
		t.Errorf("project, release.version = %q, %q, want 2024 and 1.10 as written", s.Project, s.Release.Version)
	}
	var names []string
	for _, c := range s.Components {
		names = append(names, c.Name)
	}
	if len(names) != 2 || names[0] != "2024" || names[1] != "true" {
		t.Errorf("component names = %q, want [2024 true]", names)
	}
	if got := s.Components[0].Labels; got["tier"] != "01" || got["pci"] != "true" {
		t.Errorf("labels = %v, want tier 01 and pci true as written", got)
	}
	if got := s.Components[0].Repositories[0].Revision; got != "20240101" {
		t.Errorf("revision = %q, want 20240101", got)
	}

	fragment := []byte(`components:
  - name: 2026
    labels:
      tier: 2
    repositories:
      - url: .
`)
	BothAccept(t, fragment, true)
}

// A project name is lowercase letters, digits and dashes, so an integer or a boolean is one and a
// fraction or a negative number is not, to either reader.
func TestAProjectThatIsNotANameIsRefusedByBoth(t *testing.T) {
	for _, project := range []string{"1.5", "-1"} {
		descriptor := []byte("project: " + project + "\nrelease:\n  version: \"1\"\ncomponents:\n  - name: a\n    repositories:\n      - url: .\n")
		if _, err := saga.Load(descriptor); err == nil {
			t.Errorf("project: %s: draugr validate accepts it", project)
		}
		var doc any
		if err := yaml.Unmarshal(descriptor, &doc); err != nil {
			t.Fatal(err)
		}
		if SchemaError(t, doc, false) == nil {
			t.Errorf("project: %s: the schema accepts it", project)
		}
	}
}
