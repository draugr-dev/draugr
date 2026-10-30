package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// declaredDefault is the `default` an option's schema declares, as JSON decodes it.
func declaredDefault(t *testing.T, s plugin.Scanner, option string) any {
	t.Helper()
	for _, o := range plugin.Options(s.Info().ConfigSchema) {
		if o.Name != option {
			continue
		}
		var node map[string]any
		if err := json.Unmarshal(o.Schema, &node); err != nil {
			t.Fatal(err)
		}
		v, ok := node["default"]
		if !ok {
			t.Fatalf("%s.%s declares no default", s.Info().Name, option)
		}
		return v
	}
	t.Fatalf("%s has no option %q", s.Info().Name, option)
	return nil
}

// A default declared in a schema is what `draugr config keys` and an editor show, and the scanner
// reads its own constant. The two are written apart, so each pair is held together here: a
// constant that moves without its schema has the catalog stating a default the scan does not use.
func TestDeclaredOptionDefaultsAreTheOnesTheScannerApplies(t *testing.T) {
	for _, tc := range []struct {
		scanner plugin.Scanner
		option  string
		want    any
	}{
		{NewTLSProbe(), "expiryErrorDays", defaultExpiryErrorDays},
		{NewTLSProbe(), "expiryWarnDays", defaultExpiryWarnDays},
		{NewVirusTotal(), "requestsPerMinute", virusTotalFreeRate.Requests},
		{NewProwler(), "compliance", prowlerDefaultCompliance},
		{NewSemgrep(), "config", semgrepDefaultRuleset},
		{NewKubeBench(), "targets", defaultKubeBenchTargets},
		{NewKubeBenchJob(), "targets", defaultJobTargets},
		{NewKubeBenchJob(), "namespace", defaultJobNamespace},
		{NewKubeBenchJob(), "timeout", defaultJobTimeout},
		{NewMendSCA(), "resultTimeout", defaultResultTimeout},
		{NewMendLicenses(), "resultTimeout", defaultResultTimeout},
	} {
		name := tc.scanner.Info().Name + "." + tc.option
		got := declaredDefault(t, tc.scanner, tc.option)
		switch want := tc.want.(type) {
		case time.Duration:
			d, err := time.ParseDuration(fmt.Sprint(got))
			if err != nil || d != want {
				t.Errorf("%s declares %v, the scanner waits %s", name, got, want)
			}
		case int:
			if n, ok := got.(float64); !ok || int(n) != want {
				t.Errorf("%s declares %v, the scanner uses %d", name, got, want)
			}
		default:
			if got != want {
				t.Errorf("%s declares %v, the scanner uses %v", name, got, want)
			}
		}
	}
}

// The booleans have no constant to compare with, so each is held by what the scanner does when the
// option is left out: the same as when it is set to the declared default.
func TestDeclaredBooleanDefaultsAreWhatAnUnsetOptionDoes(t *testing.T) {
	if got := declaredDefault(t, NewGitleaks(), "history"); got != gitleaksWantsHistory(nil) {
		t.Errorf("gitleaks.history declares %v, an unset one reads history=%v", got, gitleaksWantsHistory(nil))
	}
	if got := declaredDefault(t, NewTrivyLicense(), "full"); got != false ||
		!slices.Equal(licenseFullArg(nil, nil), licenseFullArg(nil, plugin.Config{"full": false})) {
		t.Errorf("trivy-license.full declares %v, which is not what an unset one does", got)
	}
	for _, s := range []plugin.Scanner{NewGrype(), NewGrypeFS()} {
		got := declaredDefault(t, s, "byCve")
		target := plugin.ImageTarget{Ref: "repo/app:1.0"}
		unset, _ := grypeArgv(target, nil)
		set, _ := grypeArgv(target, plugin.Config{"byCve": got})
		if !slices.Equal(unset, set) {
			t.Errorf("%s.byCve declares %v, and an unset one runs %v rather than %v", s.Info().Name, got, unset, set)
		}
	}
}
