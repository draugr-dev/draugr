package ciguard

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// marketplaceDescriptionLimit is what the GitHub Marketplace accepts for an action's description.
//
// Not documented in the action metadata schema, and not checked by anything that runs before
// publishing: `action.yml` is valid YAML, the action works, CI is green, and the limit is enforced
// at the moment somebody clicks publish on a release that has already been tagged and built.
const marketplaceDescriptionLimit = 125

// TestTheActionDescriptionFitsTheMarketplace keeps a release from reaching its last step and
// failing there.
//
// The description is prose, so it grows: every capability worth naming is worth naming here, and
// nothing between writing it and publishing the release reports that it has become too long.
func TestTheActionDescriptionFitsTheMarketplace(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}
	var action struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	if action.Description == "" {
		t.Fatal("action.yml has no description")
	}
	// Runes, not bytes: the description contains an em dash, and a limit counted in bytes would
	// reject a description the Marketplace accepts.
	if n := len([]rune(action.Description)); n > marketplaceDescriptionLimit {
		t.Errorf("action description is %d characters, and the Marketplace accepts %d:\n%s",
			n, marketplaceDescriptionLimit, action.Description)
	}
}

// TestTheActionManifestHasNoDuplicateKeys keeps a malformed manifest from reaching a runner.
//
// A repeated key inside an input — the second `required:` left behind when a description is
// rewritten — is accepted silently by most YAML readers, which keep the last value. The Actions
// runner is not one of them: it refuses the whole file with "'required' is already defined", and
// every workflow using the action fails at load, before a single step runs.
//
// Nothing else catches it. The file is valid YAML by the permissive reading, so a linter passes, a
// hand check passes, and the first evidence is a red workflow.
func TestTheActionManifestHasNoDuplicateKeys(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}
	// yaml.v3 rejects duplicate mapping keys, which is the behaviour we want to borrow.
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("action.yml is not loadable as the runner loads it: %v", err)
	}
	if _, ok := doc["inputs"]; !ok {
		t.Error("action.yml declares no inputs; this guard is checking the wrong file")
	}
}
