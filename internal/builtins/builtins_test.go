package builtins

import (
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
)

func TestRegistryHasDefaults(t *testing.T) {
	reg := Registry()
	for _, c := range []string{"images", "sca", "licenses", "secrets", "sast", "iac", "headers", "dast", "tls"} {
		if _, ok := reg.Controller(c); !ok {
			t.Errorf("%s controller should be registered", c)
		}
	}
	for _, s := range []string{"trivy", "trivy-fs", "trivy-license", "gitleaks", "semgrep", "gosec", "trivy-config", "draugr-headers", "nuclei", "draugr-tls"} {
		if _, ok := reg.Scanner(s); !ok {
			t.Errorf("%s scanner should be registered", s)
		}
	}
}

func TestSurveyorRegistryHasDefaults(t *testing.T) {
	reg := SurveyorRegistry()
	for _, name := range []string{
		"k8s-images", "k8s-cluster", "github-org-repos", "gitlab-group-projects", "azure-devops-repos",
	} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("%s surveyor should be registered", name)
		}
	}
}

// TestScannersReadAfterRegisteredScannersWithoutACycle holds every ReadsAfter declaration to a
// scanner that exists and to an order that can be kept. A name nothing registers orders nothing,
// so the result it was meant to make stable stays unstable, and a cycle is two jobs a run can only
// report and leave unordered.
func TestScannersReadAfterRegisteredScannersWithoutACycle(t *testing.T) {
	t.Parallel()
	if err := Registry().CheckReadsAfter(); err != nil {
		t.Fatal(err)
	}
}

// trivy-license reads a Go dependency's license from the module cache, and each of these scanners
// fills that cache as it loads a module's packages. A scanner added to the list of those that load
// Go packages belongs here too.
func TestTheLicenseScannerReadsAfterTheGoModuleLoaders(t *testing.T) {
	t.Parallel()
	sc, ok := Registry().Scanner("trivy-license")
	if !ok {
		t.Fatal("trivy-license is not registered")
	}
	got := sc.Info().ReadsAfter
	for _, want := range []string{"govulncheck", "gosec"} {
		if !slices.Contains(got, want) {
			t.Errorf("trivy-license ReadsAfter = %v, want it to include %s", got, want)
		}
	}
}

// TestEveryHyphenatedScannerHasAConfigKey closes a gap unit tests cannot see.
//
// Scanner names appear in reports and rule output, and several are hyphenated. Descriptor fields
// are camelCase, so the two diverge for any scanner whose name has more than one word, and a
// scanner registered without an entry is one a descriptor cannot configure. Validation rejects
// the block as naming a scanner the control does not have, which reads as the scanner not
// existing at all.
//
// Nothing else catches it: a controller's own tests build a plugin.Config directly and never
// travel through descriptor validation, so they pass with the mapping missing.
func TestEveryHyphenatedScannerHasAConfigKey(t *testing.T) {
	t.Parallel()

	for _, s := range Registry().Scanners() {
		name := s.Info().Name
		if !strings.Contains(name, "-") {
			// Key and name are equal, so there is nothing to record.
			continue
		}
		key := controllers.ScannerConfigKey(name)
		if key == name {
			t.Errorf("scanner %q is hyphenated and has no camelCase key: a descriptor cannot "+
				"configure it, and validation rejects the block as naming a scanner that does "+
				"not exist. Add it to scannerConfigKey in internal/controllers/config.go", name)
			continue
		}
		if strings.Contains(key, "-") {
			t.Errorf("scanner %q maps to %q, which is not camelCase", name, key)
		}
	}
}
