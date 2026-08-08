package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestGitleaksTakesASharedRuleset(t *testing.T) {
	got := gitleaksArgs("/tree", plugin.Config{"config": "rules/gitleaks.toml"})
	i := slices.Index(got, "--config")
	if i < 0 || i+1 >= len(got) {
		t.Fatalf("--config not passed: %v", got)
	}
	// Absolute, because the tool runs with the checkout as its working directory and a relative
	// path would resolve inside a temporary clone that does not contain the operator's file.
	if !filepath.IsAbs(got[i+1]) {
		t.Errorf("config path %q should be absolute", got[i+1])
	}
	if !strings.HasSuffix(got[i+1], "rules/gitleaks.toml") {
		t.Errorf("config path %q lost the value", got[i+1])
	}
}

func TestGitleaksWithoutAConfigIsUnchanged(t *testing.T) {
	if got := gitleaksArgs("/tree", nil); slices.Contains(got, "--config") {
		t.Errorf("no config option should mean no flag: %v", got)
	}
}

func TestGosecTakesRuleSelectionAndBuildTags(t *testing.T) {
	got := gosecArgs("", plugin.Config{
		"include": []any{"G101", "G204"},
		"exclude": []any{"G104"},
		"tags":    []any{"integration"},
	})
	for _, want := range []string{"-include=G101,G204", "-exclude=G104", "-tags=integration"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	// gosec reads flags before the package pattern; an option after it becomes part of it.
	if got[len(got)-1] != "./..." {
		t.Errorf("package pattern must stay last: %v", got)
	}
}

func TestGosecWithNoOptionsIsUnchanged(t *testing.T) {
	want := []string{"gosec", "-fmt", "sarif", "-no-fail", "./..."}
	if got := gosecArgs("", nil); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTrivyFSTakesPackageTypesAndAMirror(t *testing.T) {
	got := trivyFSArgs("/tree", plugin.Config{
		"pkgTypes":     []any{"library"},
		"dbRepository": []any{"registry.internal/trivy-db:2", "ghcr.io/aquasecurity/trivy-db:2"},
	})
	for _, want := range [][2]string{
		{"--pkg-types", "library"},
		{"--db-repository", "registry.internal/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2"},
	} {
		i := slices.Index(got, want[0])
		if i < 0 || got[i+1] != want[1] {
			t.Errorf("%s = %v, want %q", want[0], got, want[1])
		}
	}
	// Trivy takes flags ahead of the target, so the directory has to stay last.
	if got[len(got)-1] != "/tree" {
		t.Errorf("target must stay last: %v", got)
	}
}

func TestTrivyImageTakesTheSameOptions(t *testing.T) {
	got, err := trivyArgv(plugin.ImageTarget{Ref: "registry.example.com/api:1.0"},
		plugin.Config{"pkgTypes": []any{"os"}})
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(got, "--pkg-types")
	if i < 0 || got[i+1] != "os" {
		t.Errorf("--pkg-types not passed: %v", got)
	}
	if got[len(got)-1] != "registry.example.com/api:1.0" {
		t.Errorf("image ref must stay last: %v", got)
	}
}

func TestTrivyConfigTakesCustomChecks(t *testing.T) {
	got := trivyConfigArgs("/tree", plugin.Config{
		"checks":     []any{"policies/a", "policies/b"},
		"namespaces": []any{"user", "acme"},
	})
	// One flag per path: Trivy's --config-check is repeatable and a comma-joined value would be
	// taken as a single path.
	n := 0
	for i, a := range got {
		if a != "--config-check" {
			continue
		}
		n++
		if !filepath.IsAbs(got[i+1]) {
			t.Errorf("check path %q should be absolute", got[i+1])
		}
	}
	if n != 2 {
		t.Errorf("got %d --config-check flags, want 2: %v", n, got)
	}
	i := slices.Index(got, "--check-namespaces")
	if i < 0 || got[i+1] != "user,acme" {
		t.Errorf("--check-namespaces not passed: %v", got)
	}
	if got[len(got)-1] != "/tree" {
		t.Errorf("target must stay last: %v", got)
	}
}

// The line every curated option is held to: it changes what the tool examines, never which
// findings survive. A severity or ignore-file flag would drop findings inside the tool, where
// Draugr cannot mark them suppressed or record who accepted them — which is what `exclusions`
// and the gate thresholds are for.
func TestNoScannerOptionFiltersFindings(t *testing.T) {
	banned := []string{"severity", "ignorefile", "ignore-file", "confidence", "exit-code"}
	for _, s := range []plugin.Scanner{NewGitleaks(), NewGosec(), NewTrivy(), NewTrivyFS(), NewTrivyConfig()} {
		info := s.Info()
		for _, opt := range plugin.Options(info.ConfigSchema) {
			for _, b := range banned {
				if strings.EqualFold(opt.Name, b) {
					t.Errorf("%s: option %q filters findings inside the tool; use exclusions "+
						"and the gate thresholds instead", info.Name, opt.Name)
				}
			}
		}
	}
}

// Every option a scanner reads must be declared, or the descriptor that sets it is rejected while
// the code goes on quietly supporting it.
func TestCuratedOptionsValidateAgainstTheirOwnSchema(t *testing.T) {
	cases := []struct {
		scanner plugin.Scanner
		cfg     plugin.Config
	}{
		{NewGitleaks(), plugin.Config{"config": "rules.toml"}},
		{NewGosec(), plugin.Config{"include": []any{"G101"}, "exclude": []any{"G104"}, "tags": []any{"x"}}},
		{NewTrivyFS(), plugin.Config{"pkgTypes": []any{"library"}, "dbRepository": []any{"r"}}},
		{NewTrivy(), plugin.Config{"pkgTypes": []any{"os"}}},
		{NewTrivyConfig(), plugin.Config{"checks": []any{"p"}, "namespaces": []any{"user"}}},
	}
	for _, c := range cases {
		info := c.scanner.Info()
		if err := plugin.ValidateConfig(info.ConfigSchema, c.cfg); err != nil {
			t.Errorf("%s: rejected its own options: %v", info.Name, err)
		}
	}
}

func TestPkgTypesRejectsAValueTrivyDoesNotAccept(t *testing.T) {
	err := plugin.ValidateConfig(NewTrivyFS().Info().ConfigSchema,
		plugin.Config{"pkgTypes": []any{"packages"}})
	if err == nil {
		t.Fatal("an invalid package type was accepted")
	}
	if !strings.Contains(err.Error(), "os") || !strings.Contains(err.Error(), "library") {
		t.Errorf("the error should name the accepted values: %v", err)
	}
}

// A schema that does not parse would silently accept everything, which is the failure the
// declarations exist to prevent.
func TestCuratedSchemasAreValidJSON(t *testing.T) {
	for _, s := range []string{
		gitleaksConfigSchema, gosecConfigSchema, trivyConfigSchema, trivyConfigCheckSchema,
	} {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Errorf("schema is not valid JSON: %v\n%s", err, s)
		}
	}
}

func TestAbsPathLeavesAnEmptyValueEmpty(t *testing.T) {
	if got := absPath("   "); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got := absPath("x.toml"); got != filepath.Join(wd, "x.toml") {
		t.Errorf("got %q, want it resolved against the process directory", got)
	}
}
