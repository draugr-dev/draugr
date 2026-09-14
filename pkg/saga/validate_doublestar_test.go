package saga

import "testing"

// `**` reads as supported and is not. `path.Match` takes the second star as another
// single-segment wildcard, so the pattern matches one level down and the author believes it
// matches every level, which is the opposite of a suppression they can rely on.
func TestExcludeRefusesDoubleStarAndNamesTheSpellingThatWorks(t *testing.T) {
	for _, tc := range []struct{ pattern, want string }{
		{"tests/**", `"tests/"`},
		{"tests/**/*.go", `"tests/"`},
		{"**/vendor", `"./"`},
		{"**", `"./"`},
		{"src/**/gen", `"src/"`},
	} {
		errs := validateExclusions([]ExcludeRule{
			{Reason: "test files", Paths: []string{tc.pattern}},
		}, "config.exclude")
		if len(errs) != 1 {
			t.Fatalf("%q: errs = %v, want exactly the double-star refusal", tc.pattern, errs)
		}
		got := errs[0].Error()
		if !contains(got, tc.want) {
			t.Errorf("%q: %q does not name %s", tc.pattern, got, tc.want)
		}
		// The reader is told why, not only that it is refused. `*` stopping at a separator is the
		// fact the whole trap rests on.
		if !contains(got, "cross /") {
			t.Errorf("%q: %q does not say what * does at a separator", tc.pattern, got)
		}
	}
}

// A single star is the matcher's own syntax and stays legal. Refusing it would break every
// descriptor that names a file pattern, which is what this field is mostly used for.
func TestExcludeKeepsSingleStar(t *testing.T) {
	for _, p := range []string{"tests/*.go", "*.md", "vendor/", "internal/gen_*.go"} {
		if errs := validateExclusions([]ExcludeRule{
			{Reason: "generated", Paths: []string{p}},
		}, "config.exclude"); len(errs) != 0 {
			t.Errorf("%q: errs = %v, want none", p, errs)
		}
	}
}
