package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestRegistryControllersSorted(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(fakeController{name: "sast", scope: plugin.ScopeComponent})
	reg.RegisterController(fakeController{name: "images", scope: plugin.ScopeComponent})

	got := reg.Controllers()
	if len(got) != 2 {
		t.Fatalf("Controllers() len = %d, want 2", len(got))
	}
	if got[0].Info().Name != "images" || got[1].Info().Name != "sast" {
		t.Errorf("Controllers() not sorted by name: %q, %q", got[0].Info().Name, got[1].Info().Name)
	}
}
