package saga

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validSaga = `
release:
  name: my-app
  version: "1.0"
  stage: dev
config:
  controllers:
    images:
      enabled: true
    sast:
      enabled: false
    dast: {}
components:
  - name: backend
    labels:
      team: platform
    repositories:
      - url: https://github.com/acme/backend.git
        revision: 1.0
    images:
      - image: registry.example.com/acme/backend:1.0
    hosts:
      - name: api
        url: https://api.acme.com
        type: api
    infrastructure:
      - kind: kubernetes
        ref: prod
    controllers:
      sast:
        enabled: true
references:
  - type: ThreatModel
    link: https://example.com/tm
notApplicable:
  - type: DAST
    reason: no web surface
`

func TestLoadValid(t *testing.T) {
	m, err := Load([]byte(validSaga))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if m.Release.Name != "my-app" || m.Release.Version != "1.0" {
		t.Errorf("release = %+v", m.Release)
	}
	if len(m.Components) != 1 || m.Components[0].Name != "backend" {
		t.Fatalf("components = %+v", m.Components)
	}
	c := m.Components[0]
	if c.Repositories[0].URL == "" || c.Images[0].Image == "" || c.Hosts[0].URL == "" {
		t.Errorf("component surface not parsed: %+v", c)
	}
	if c.Infrastructure[0].Kind != "kubernetes" {
		t.Errorf("infra = %+v", c.Infrastructure)
	}
	if len(m.References) != 1 || len(m.NotApplicable) != 1 {
		t.Errorf("references/na not parsed")
	}
}

func TestControllerEnabled(t *testing.T) {
	m, err := Load([]byte(validSaga))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Config.ControllerEnabled("images") {
		t.Error("images should be enabled")
	}
	if m.Config.ControllerEnabled("sast") {
		t.Error("sast should be disabled at project level")
	}
	if !m.Config.ControllerEnabled("dast") {
		t.Error("dast with empty config should default to enabled")
	}
	if m.Config.ControllerEnabled("absent") {
		t.Error("absent controller should be disabled")
	}

	// Component override: sast enabled on the component even though disabled at project level.
	c := m.Components[0]
	if !c.ControllerEnabled("sast", m.Config) {
		t.Error("component override should enable sast")
	}
	// Falls back to project setting when no override.
	if !c.ControllerEnabled("images", m.Config) {
		t.Error("component should inherit project images=enabled")
	}
}

func TestEnvSubstitution(t *testing.T) {
	t.Setenv("RELEASE_VERSION", "9.9")
	t.Setenv("IMG_TAG", "abc")
	src := `
release:
  name: x
  version: "${{ RELEASE_VERSION }}"
components:
  - name: c
    images:
      - image: repo/x:${{IMG_TAG}}
`
	m, err := Load([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if m.Release.Version != "9.9" {
		t.Errorf("version = %q, want 9.9", m.Release.Version)
	}
	if m.Components[0].Images[0].Image != "repo/x:abc" {
		t.Errorf("image = %q", m.Components[0].Images[0].Image)
	}
}

func TestEnvSubstitutionMissing(t *testing.T) {
	src := `
release:
  version: "${{ NOT_SET_VAR_XYZ }}"
`
	_, err := Load([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "NOT_SET_VAR_XYZ") {
		t.Fatalf("expected missing-var error, got %v", err)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	if _, err := Load([]byte("release: [unclosed")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(p, []byte(validSaga), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
