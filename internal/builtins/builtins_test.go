package builtins

import "testing"

func TestRegistryHasDefaults(t *testing.T) {
	reg := Registry()
	if _, ok := reg.Controller("images"); !ok {
		t.Error("images controller should be registered")
	}
	if _, ok := reg.Scanner("trivy"); !ok {
		t.Error("trivy scanner should be registered")
	}
}

func TestSurveyorRegistryHasDefaults(t *testing.T) {
	reg := SurveyorRegistry()
	for _, name := range []string{"k8s-images", "github-org-repos"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("%s surveyor should be registered", name)
		}
	}
}
