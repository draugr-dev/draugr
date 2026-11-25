package saga

import (
	"reflect"
	"testing"
)

// A setting substituted from a pipeline variable reads back as the reference the descriptor wrote,
// whatever value the variable holds on this run, at any depth and inside a longer string. Values of
// other types are left alone.
func TestASettingReadsBackAsWritten(t *testing.T) {
	doc := []byte(rootHeader + `config:
  controls:
    sast:
      enabled: true
      semgrep:
        config: ${{ RULES }}
        extra: ["${{ RULES }}/more.yml", plain]
        nested: { at: "x-${{ RULES }}-y", depth: 3, on: true }
components:
  - name: api
    controls:
      sast:
        semgrep: { config: "${{ RULES }}" }
    repositories:
      - url: .
`)
	t.Setenv(SagaEnvsVar, "RULES")
	want := ControllerSettings{
		"enabled": true,
		"semgrep": ControllerSettings{
			"config": "${{ RULES }}",
			"extra":  []any{"${{ RULES }}/more.yml", "plain"},
			"nested": ControllerSettings{"at": "x-${{ RULES }}-y", "depth": 3, "on": true},
		},
	}
	for _, value := range []string{"/tmp/run-1/semgrep.yaml", "/tmp/run-22/semgrep.yaml"} {
		t.Setenv("RULES", value)
		m, err := Load(doc)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Config.Controls["sast"]["semgrep"].(ControllerSettings)["config"]; got != value {
			t.Fatalf("the run reads %v, want the substituted %q", got, value)
		}
		if got := m.SettingsAsWritten(m.Config.Controls["sast"]); !reflect.DeepEqual(got, want) {
			t.Errorf("RULES=%s: as written = %#v\nwant %#v", value, got, want)
		}
		if got := m.SettingsAsWritten(m.Components[0].Controls["sast"]); !reflect.DeepEqual(got,
			ControllerSettings{"semgrep": ControllerSettings{"config": "${{ RULES }}"}}) {
			t.Errorf("the component's = %#v", got)
		}
		if got := m.AsWritten([]string{value, "x"}); !reflect.DeepEqual(got, []string{"${{ RULES }}", "x"}) {
			t.Errorf("a list of strings = %#v", got)
		}
	}

	// A plain map, as a model built in code may hold, is read the same way.
	m := &Model{substituted: map[string]string{"RULES": "/tmp/run-1/semgrep.yaml"}}
	if got := m.AsWritten(map[string]any{"config": "/tmp/run-1/semgrep.yaml"}); !reflect.DeepEqual(got,
		map[string]any{"config": "${{ RULES }}"}) {
		t.Errorf("a plain map = %#v", got)
	}

	// A model that substituted nothing, built in code, reads as it is.
	plain := &Model{}
	if got := plain.AsWritten("/tmp/run-1/semgrep.yaml"); got != "/tmp/run-1/semgrep.yaml" {
		t.Errorf("as written = %v", got)
	}
	if plain.SettingsAsWritten(nil) != nil {
		t.Error("nil settings read back as something")
	}
}

// Where one variable's value holds another's, the longer is put back whole.
func TestTheLongerValueIsPutBackFirst(t *testing.T) {
	m := &Model{substituted: map[string]string{"ROOT": "/work", "RULES": "/work/rules.yml", "EMPTY": ""}}
	if got := m.AsWritten("/work/rules.yml and /work/x"); got != "${{ RULES }} and ${{ ROOT }}/x" {
		t.Errorf("as written = %v", got)
	}
}

// A fragment's substitutions travel with it into the descriptor it merges into.
func TestAFragmentsSubstitutionsMergeWithIt(t *testing.T) {
	t.Setenv(SagaEnvsVar, "SIGNER")
	t.Setenv("SIGNER", "https://token.example/run-7")
	frag, err := LoadFragment([]byte(`config:
  controls:
    provenance:
      signers:
        - workflow: ${{ SIGNER }}
`), "f.saga-fragment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := &Model{}
	Merge(m, frag)
	if got := m.AsWritten("https://token.example/run-7"); got != "${{ SIGNER }}" {
		t.Errorf("as written = %v", got)
	}
}
