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
