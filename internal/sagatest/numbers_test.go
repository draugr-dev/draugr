package sagatest

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestAnUnquotedNumberIsKeptAsWritten holds both readers to a free-form value YAML reads as a
// number. The editor sees 1.10 and 2024; draugr keeps the text, so the version is "1.10" rather
// than "1.1", and neither reader refuses the file.
func TestAnUnquotedNumberIsKeptAsWritten(t *testing.T) {
	descriptor := []byte(`project: numbers
release:
  version: 1.10
components:
  - name: 2024
    repositories:
      - url: .
        revision: 20240101
  - name: 2025
    repositories:
      - url: .
`)
	BothAccept(t, descriptor, false)
	s, err := saga.Load(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Release.Version != "1.10" {
		t.Errorf("release.version = %q, want 1.10 as written", s.Release.Version)
	}
	var names []string
	for _, c := range s.Components {
		names = append(names, c.Name)
	}
	if len(names) != 2 || names[0] != "2024" || names[1] != "2025" {
		t.Errorf("component names = %q, want [2024 2025]", names)
	}
	if got := s.Components[0].Repositories[0].Revision; got != "20240101" {
		t.Errorf("revision = %q, want 20240101", got)
	}

	fragment := []byte(`components:
  - name: 2026
    repositories:
      - url: .
`)
	BothAccept(t, fragment, true)
}
