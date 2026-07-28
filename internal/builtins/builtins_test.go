package builtins

import "testing"

func TestRegistryHasDefaults(t *testing.T) {
	reg := Registry()
	for _, c := range []string{"images", "sca", "licenses", "secrets", "sast", "iac", "headers", "dast", "tls"} {
		if _, ok := reg.Controller(c); !ok {
			t.Errorf("%s controller should be registered", c)
		}
	}
	for _, s := range []string{"trivy", "trivy-fs", "trivy-license", "gitleaks", "semgrep", "gosec", "trivy-config", "http-headers", "nuclei", "tls-probe"} {
		if _, ok := reg.Scanner(s); !ok {
			t.Errorf("%s scanner should be registered", s)
		}
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
