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
