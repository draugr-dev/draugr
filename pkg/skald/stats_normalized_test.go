package skald

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/test/sealed"
)

// stableStats are the keys under stats that every run of a sealed scenario writes the same way, so
// the scenario's golden pins them. A path is below stats, with "*" for every element of a list or
// every value of a map, and names a key the normalizer does not clear or drop.
var stableStats = []string{
	// The planned jobs, one per control, scanner and target: fixed by the descriptor and the
	// scenario's tree.
	"jobs",
	// The jobs that ran a fresh scan and succeeded. Which jobs fail is part of the scenario, and a
	// sealed run never passes --cache-dir, so no job is served from a cache instead.
	"scans",
	// Zero on every sealed run, which never passes --cache-dir.
	"cacheHits",
	// `enabled: false` and `hits: 0` for the same reason. A scenario that passed --cache-dir would
	// write the cache's directory, which the run's replacements cover, and the time of its oldest
	// hit, which they do not.
	"cache",
	// Jobs identical to one already planned. The in-run singleflight keeps every result it computed,
	// so a duplicate is counted whichever of the pair starts first.
	"deduped",
	// The scanners that refreshed their data and what each refreshed, in the order they were warmed:
	// the run's plan, where the refresh's duration (ms) is the network's and is cleared.
	"dataRefresh.*.scanner",
	"dataRefresh.*.data",
	// A sealed run has no network to lose, so a refresh fails or succeeds the same way every time.
	"dataRefresh.*.failed",
}

// unnormalizedStats are the keys under stats whose value or presence depends on the machine or the
// moment, and which ReportNormalizer does not yet clear or drop. No golden holds one today. Each
// entry is one the normalizer should take, and the test fails once it does so the entry goes too.
var unnormalizedStats = []string{
	// Written only when a Trivy job waited for the scanner cache another job held, so whether it
	// appears depends on which job finished first, as for orderWaitsMs.
	"toolWaitsMs",
}

// Every key the report can write under stats is either normalized for the sealed scenarios or pinned
// by their goldens on purpose. A key that is neither, and whose value differs between runs, fails
// every scenario in the integration job and nothing before it.
func TestEveryStatsKeyIsNormalizedOrStable(t *testing.T) {
	n := sealed.ReportNormalizer(nil)
	var normalized [][]string
	for _, path := range slices.Concat(n.Clear, n.ClearPresent, n.Drop) {
		if len(path) > 1 && path[0] == "stats" {
			normalized = append(normalized, path[1:])
		}
	}
	listed := map[string]bool{}
	for _, key := range slices.Concat(stableStats, unnormalizedStats) {
		listed[key] = false
	}

	var walk func(typ reflect.Type, prefix []string)
	walk = func(typ reflect.Type, prefix []string) {
		for _, field := range reflect.VisibleFields(typ) {
			name, ok := jsonKey(field)
			if !ok {
				continue
			}
			path := append(slices.Clone(prefix), name)
			key := strings.Join(path, ".")
			switch {
			case slices.ContainsFunc(normalized, func(p []string) bool { return slices.Equal(p, path) }):
			case slices.ContainsFunc(normalized, func(p []string) bool { return len(p) > len(path) && slices.Equal(p[:len(path)], path) }):
				// The normalizer reaches inside this key, so each key inside it is classified on its own.
				elem, inner := descend(field.Type, path)
				if elem.Kind() != reflect.Struct {
					t.Errorf("ReportNormalizer addresses a path inside stats.%s, which holds no object", key)
					continue
				}
				walk(elem, inner)
			default:
				if _, ok := listed[key]; !ok {
					t.Errorf("stats.%s is in neither ReportNormalizer (test/sealed/normalize.go), which clears or drops a key whose value or presence depends on the machine or the moment, nor stableStats (pkg/skald/stats_normalized_test.go), which lists a key every run of a scenario writes the same way", key)
					continue
				}
				listed[key] = true
			}
		}
	}
	walk(reflect.TypeFor[statsInfo](), nil)

	for key, used := range listed {
		if !used {
			t.Errorf("stats.%s is listed beside this test, but the report writes no such key or ReportNormalizer already handles it; remove the entry", key)
		}
	}
	// A ClearPresent or Drop path that names nothing matches nothing and says nothing.
	for _, path := range normalized {
		if !reachable(reflect.TypeFor[statsInfo](), path) {
			t.Errorf("ReportNormalizer names stats.%s, which the report never writes", strings.Join(path, "."))
		}
	}
}

// jsonKey is the key encoding/json writes a field under, and false for a field it never writes.
func jsonKey(field reflect.StructField) (string, bool) {
	if !field.IsExported() || field.Anonymous {
		return "", false
	}
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	switch name {
	case "-":
		return "", false
	case "":
		return field.Name, true
	}
	return name, true
}

// descend follows a field's type through pointers, lists and maps to the type of what the JSON
// holds, adding a "*" to the path for each list or map it passes.
func descend(typ reflect.Type, path []string) (reflect.Type, []string) {
	for {
		switch typ.Kind() {
		case reflect.Pointer:
			typ = typ.Elem()
		case reflect.Slice, reflect.Array, reflect.Map:
			typ, path = typ.Elem(), append(slices.Clone(path), "*")
		default:
			return typ, path
		}
	}
}

// reachable reports whether a path below stats names a key the report can write.
func reachable(typ reflect.Type, path []string) bool {
	for len(path) > 0 {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if path[0] == "*" {
			switch typ.Kind() {
			case reflect.Slice, reflect.Array, reflect.Map:
				typ, path = typ.Elem(), path[1:]
				continue
			}
			return false
		}
		if typ.Kind() != reflect.Struct {
			return false
		}
		var next reflect.Type
		for _, field := range reflect.VisibleFields(typ) {
			if name, ok := jsonKey(field); ok && name == path[0] {
				next = field.Type
			}
		}
		if next == nil {
			return false
		}
		typ, path = next, path[1:]
	}
	return true
}
