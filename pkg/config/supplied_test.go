package config

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// mustParse is a file's parsed form, for a test that builds sources in memory.
func mustParse(t *testing.T, body string) File {
	t.Helper()
	f, err := Parse([]byte(body), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// suppliedByPath is MergeControls' attribution as path → settings, for comparing.
func suppliedByPath(s []Supplied) map[string][]string {
	out := map[string][]string{}
	for _, x := range s {
		out[x.Source.Path] = x.Settings
	}
	return out
}

// Each default that reaches the descriptor is the most specific file's, and a file that supplied
// nothing to it is left out: one setting only tools, and one whose only default the descriptor
// overrode. sca is turned on by one component of two, and its default reaches that component.
func TestMergeControlsNamesTheFileBehindEachDefault(t *testing.T) {
	machine := Source{Path: "machine.yaml", File: mustParse(t, `
controls:
  secrets:
    gitleaks:
      config: /etc/draugr/gitleaks-org.toml
      history: false
  sca:
    trivyFs:
      includeDevDeps: true
`)}
	project := Source{Path: "project.yaml", File: mustParse(t, `
controls:
  secrets:
    gitleaks:
      history: true
tools:
  gitleaks:
    version: 8.30.1
`)}
	toolsOnly := Source{Path: "tools.yaml", File: mustParse(t, "tools:\n  trivy:\n    version: 0.69.3\n")}
	overridden := Source{Path: "overridden.yaml", File: mustParse(t, `
controls:
  sast:
    semgrep:
      config: p/org
`)}
	res := Resolve([]Source{machine, toolsOnly, overridden, project})

	descriptor := map[string]saga.ControllerSettings{
		"secrets": {"enabled": true},
		"sast":    {"semgrep": map[string]any{"config": "p/default"}},
	}
	components := []saga.Component{
		{Name: "api", Controls: map[string]saga.ControllerSettings{"sca": {}}},
		{Name: "web"},
	}
	merged, supplied := res.MergeControls(descriptor, components)

	want := map[string][]string{
		"machine.yaml": {"sca.trivyFs.includeDevDeps", "secrets.gitleaks.config"},
		"project.yaml": {"secrets.gitleaks.history"},
	}
	if got := suppliedByPath(supplied); !reflect.DeepEqual(got, want) {
		t.Errorf("supplied = %v, want %v", got, want)
	}
	if len(supplied) != 2 || supplied[0].Source.Path != "machine.yaml" {
		t.Errorf("not least specific first: %+v", supplied)
	}
	gitleaks, _ := asSettings(merged["secrets"]["gitleaks"])
	if gitleaks["history"] != true || merged["secrets"]["enabled"] != true {
		t.Errorf("the project's default and the descriptor's setting did not both reach: %+v", merged["secrets"])
	}
	if semgrep, _ := asSettings(merged["sast"]["semgrep"]); semgrep["config"] != "p/default" {
		t.Errorf("a default overrode the descriptor: %+v", merged["sast"])
	}
	if _, ok := descriptor["sca"]; ok {
		t.Error("the descriptor's own map was written to")
	}
}

// A value the descriptor sets above a default's setting replaces the default's whole block, as
// DeepMerge keeps it, so the default reached nothing.
func TestMergeControlsAttributesNothingUnderAValueTheDescriptorSet(t *testing.T) {
	res := Resolve([]Source{{Path: "c.yaml", File: mustParse(t, `
controls:
  secrets:
    gitleaks:
      history: true
`)}})
	_, supplied := res.MergeControls(map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": false},
	}, nil)
	if len(supplied) != 0 {
		t.Errorf("a default under a value the descriptor set was attributed: %+v", supplied)
	}
}

// An empty block still reaches a descriptor that sets nothing there, and changes what its digest is
// taken over, so it is attributed. One the descriptor fills is not.
func TestMergeControlsAttributesAnEmptyBlock(t *testing.T) {
	res := Resolve([]Source{{Path: "c.yaml", File: mustParse(t, "controls:\n  secrets: {}\n  sast: {}\n")}})
	merged, supplied := res.MergeControls(map[string]saga.ControllerSettings{
		"sast": {"enabled": true},
	}, []saga.Component{{Name: "api", Controls: map[string]saga.ControllerSettings{"secrets": {}}}})
	if got := suppliedByPath(supplied); !reflect.DeepEqual(got, map[string][]string{"c.yaml": {"secrets"}}) {
		t.Errorf("supplied = %v", got)
	}
	if _, ok := merged["secrets"]; !ok {
		t.Error("the empty block did not reach the descriptor")
	}
}

// An empty block in a more specific file keeps the settings a less specific file wrote under it,
// and a value replaces them, so the setting is then the more specific file's alone.
func TestMergeControlsFollowsTheLayeringBetweenFiles(t *testing.T) {
	res := Resolve([]Source{
		{Path: "a.yaml", File: mustParse(t, "controls:\n  secrets:\n    gitleaks:\n      history: true\n")},
		{Path: "b.yaml", File: mustParse(t, "controls:\n  secrets:\n    gitleaks: {}\n")},
	})
	secretsOn := map[string]saga.ControllerSettings{"secrets": {}}
	_, supplied := res.MergeControls(secretsOn, nil)
	if got := suppliedByPath(supplied); !reflect.DeepEqual(got, map[string][]string{"a.yaml": {"secrets.gitleaks.history"}}) {
		t.Errorf("supplied = %v", got)
	}

	res = Resolve([]Source{
		{Path: "a.yaml", File: mustParse(t, "controls:\n  secrets:\n    gitleaks:\n      history: true\n")},
		{Path: "b.yaml", File: mustParse(t, "controls:\n  secrets:\n    gitleaks: off\n")},
	})
	_, supplied = res.MergeControls(secretsOn, nil)
	if got := suppliedByPath(supplied); !reflect.DeepEqual(got, map[string][]string{"b.yaml": {"secrets.gitleaks"}}) {
		t.Errorf("supplied = %v", got)
	}

	// And the other way round: a block replaces a less specific file's value.
	res = Resolve([]Source{
		{Path: "a.yaml", File: mustParse(t, "controls:\n  secrets:\n    gitleaks: off\n")},
		{Path: "b.yaml", File: mustParse(t, "controls:\n  secrets:\n    gitleaks:\n      history: true\n")},
	})
	_, supplied = res.MergeControls(secretsOn, nil)
	if got := suppliedByPath(supplied); !reflect.DeepEqual(got, map[string][]string{"b.yaml": {"secrets.gitleaks.history"}}) {
		t.Errorf("supplied = %v", got)
	}
}

// With no control defaults the descriptor's controls come back as they were, attributed to nobody.
func TestMergeControlsWithoutDefaultsChangesNothing(t *testing.T) {
	controls := map[string]saga.ControllerSettings{"sca": {"enabled": true}}
	res := Resolve([]Source{{Path: "t.yaml", File: mustParse(t, "tools:\n  trivy:\n    version: 1.0.0\n")}})
	merged, supplied := res.MergeControls(controls, nil)
	if supplied != nil || !reflect.DeepEqual(merged, controls) {
		t.Errorf("merged = %v, supplied = %v", merged, supplied)
	}
	if merged, _ := (Resolved{}).MergeControls(nil, nil); merged != nil {
		t.Errorf("no configuration invented controls: %v", merged)
	}
}

// A resolution assembled without its sources merges as one built by Resolve, and names no file,
// because it has none to name.
func TestMergeControlsWithNoSourcesNamesNoFile(t *testing.T) {
	res := Resolved{File: mustParse(t, "controls:\n  secrets:\n    gitleaks:\n      history: true\n")}
	merged, supplied := res.MergeControls(map[string]saga.ControllerSettings{"secrets": {}}, nil)
	if len(supplied) != 0 {
		t.Errorf("supplied = %+v", supplied)
	}
	if _, ok := merged["secrets"]; !ok {
		t.Error("the default was not merged")
	}
}

// A block supplies settings to a control the descriptor turns on and never turns one on itself, so
// a machine-wide scanner option adds no control to a descriptor that left it out, and nothing is
// attributed for it. A top-level `enabled: false`, and a component's, turn a control off as well.
func TestMergeControlsLeavesAControlNothingTurnsOnOff(t *testing.T) {
	res := Resolve([]Source{{Path: "machine.yaml", File: mustParse(t, `
controls:
  sast:
    semgrep:
      config: p/org
  dast:
    zap:
      maxDuration: 5m
  sca:
    trivyFs:
      includeDevDeps: true
`)}})
	descriptor := map[string]saga.ControllerSettings{"dast": {"enabled": false}}
	components := []saga.Component{
		{Name: "api", Controls: map[string]saga.ControllerSettings{"sca": {"enabled": false}}},
		{Name: "web"},
	}
	merged, supplied := res.MergeControls(descriptor, components)
	if len(supplied) != 0 {
		t.Errorf("a default for a control nothing turns on was attributed: %+v", supplied)
	}
	if _, ok := merged["sast"]; ok {
		t.Errorf("a scanner option turned its control on: %+v", merged["sast"])
	}
	if _, ok := merged["sca"]; ok {
		t.Errorf("a component's enabled: false let a default in: %+v", merged["sca"])
	}
	if !reflect.DeepEqual(merged["dast"], saga.ControllerSettings{"enabled": false}) {
		t.Errorf("dast = %+v, want the descriptor's block alone", merged["dast"])
	}
}

// `enabled: true` in a block turns its control on for a descriptor that leaves it out, and a
// descriptor that turns it off still wins.
func TestMergeControlsTurnsAControlOnWithEnabledTrue(t *testing.T) {
	res := Resolve([]Source{{Path: "machine.yaml", File: mustParse(t, `
controls:
  sast:
    enabled: true
    semgrep:
      config: p/org
`)}})
	merged, supplied := res.MergeControls(nil, []saga.Component{{Name: "api"}, {Name: "web"}})
	want := map[string][]string{"machine.yaml": {"sast.enabled", "sast.semgrep.config"}}
	if got := suppliedByPath(supplied); !reflect.DeepEqual(got, want) {
		t.Errorf("supplied = %v, want %v", got, want)
	}
	if !(saga.Config{Controls: merged}).ControllerEnabled("sast") {
		t.Errorf("enabled: true did not turn sast on: %+v", merged["sast"])
	}

	merged, _ = res.MergeControls(map[string]saga.ControllerSettings{"sast": {"enabled": false}}, nil)
	if (saga.Config{Controls: merged}).ControllerEnabled("sast") {
		t.Errorf("the block overrode the descriptor's enabled: false: %+v", merged["sast"])
	}
}

// A control only some components turn on gets the defaults under a top-level block that is off,
// so those components inherit the settings and the others stay as the descriptor left them.
// Whether the top level leaves the control out or turns it off, the result is the same.
func TestMergeControlsReachesAControlOnlyComponentsTurnOn(t *testing.T) {
	res := Resolve([]Source{{Path: "machine.yaml", File: mustParse(t, `
controls:
  sast:
    semgrep:
      config: p/org
`)}})
	components := []saga.Component{
		{Name: "api", Controls: map[string]saga.ControllerSettings{"sast": {}}},
		{Name: "web"},
	}
	for name, descriptor := range map[string]map[string]saga.ControllerSettings{
		"left out":   nil,
		"turned off": {"sast": {"enabled": false}},
	} {
		merged, supplied := res.MergeControls(descriptor, components)
		project := saga.Config{Controls: merged}
		if !components[0].ControllerEnabled("sast", project) || components[1].ControllerEnabled("sast", project) {
			t.Errorf("%s: sast on for api %v and web %v, want api only", name,
				components[0].ControllerEnabled("sast", project), components[1].ControllerEnabled("sast", project))
		}
		if semgrep, _ := asSettings(merged["sast"]["semgrep"]); semgrep["config"] != "p/org" {
			t.Errorf("%s: the default did not reach: %+v", name, merged["sast"])
		}
		want := map[string][]string{"machine.yaml": {"sast.semgrep.config"}}
		if got := suppliedByPath(supplied); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: supplied = %v, want %v", name, got, want)
		}
	}
}

// Load records the digest of each file's bytes, so a run can say which text of it applied.
func TestLoadRecordsEachFilesDigest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "named.yaml")
	body := "# a comment is part of the text\ncontrols:\n  secrets:\n    gitleaks:\n      history: true\n"
	write(t, path, body)

	got, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if len(got.Sources) != 1 || got.Sources[0].Digest != want {
		t.Errorf("sources = %+v, want digest %s", got.Sources, want)
	}
	if Digest([]byte(body)) != want {
		t.Errorf("Digest = %s, want %s", Digest([]byte(body)), want)
	}
}
