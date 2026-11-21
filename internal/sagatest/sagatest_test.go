package sagatest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// recorder stands in for the test a helper is given, so a helper's own failure can be observed
// rather than failing the test that checks it.
type recorder struct {
	testing.TB
	failures []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

func (r *recorder) Fatal(args ...any) {
	r.failures = append(r.failures, fmt.Sprint(args...))
	runtime.Goexit()
}

// observe runs f against a recorder, in its own goroutine so a fatal failure ends f and not the test.
func observe(t *testing.T, f func(testing.TB)) []string {
	t.Helper()
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(r)
	}()
	<-done
	return r.failures
}

const validSaga = "project: shop\ncomponents:\n  - name: web\n    images:\n      - image: alpine:3.19\n"

func TestEditorAcceptsReportsWhatAnEditorWouldMark(t *testing.T) {
	if got := observe(t, func(tb testing.TB) { EditorAccepts(tb, []byte(validSaga), false) }); len(got) != 0 {
		t.Errorf("a valid descriptor failed: %v", got)
	}
	cases := map[string]struct {
		data     string
		fragment bool
		want     string
	}{
		"not YAML":              {"project: [", false, "not YAML"},
		"refused by the schema": {"project: shop\nzzUnknown: 1\n", false, "an editor rejects"},
		"a deprecated key":      {validSaga + "config:\n  controllers:\n    sast: {}\n", false, "no longer writes"},
		"a fragment":            {"zzUnknown: 1\n", true, "an editor rejects"},
	}
	for name, c := range cases {
		got := observe(t, func(tb testing.TB) { EditorAccepts(tb, []byte(c.data), c.fragment) })
		if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), c.want) {
			t.Errorf("%s: failures %q, want one saying %q", name, got, c.want)
		}
	}
}

func TestBothAcceptNamesTheReaderThatRefused(t *testing.T) {
	got := observe(t, func(tb testing.TB) { BothAccept(tb, []byte("project: shop\nzzUnknown: 1\n"), false) })
	if !strings.Contains(strings.Join(got, "\n"), "draugr validate rejects") {
		t.Errorf("an unknown key: failures %q, want one naming draugr validate", got)
	}
	if got := observe(t, func(tb testing.TB) { BothAccept(tb, []byte("components: []\n"), true) }); len(got) != 0 {
		t.Errorf("an empty fragment failed: %v", got)
	}
	if got := observe(t, func(tb testing.TB) { FragmentAccepted(tb, saga.Fragment{}) }); len(got) != 0 {
		t.Errorf("a fragment Draugr writes failed: %v", got)
	}
}

func TestSchemaErrorJudgesEitherDocument(t *testing.T) {
	if err := SchemaError(t, map[string]any{"components": []any{}}, true); err != nil {
		t.Errorf("an empty fragment: %v", err)
	}
	if err := SchemaError(t, map[string]any{"zz": 1}, false); err == nil {
		t.Error("an unknown top-level key was accepted")
	}
	if JSONOf(make(chan int)) != nil {
		t.Error("a value JSON cannot hold should come back nil")
	}
	if _, err := resolve([]byte("not json")); err == nil {
		t.Error("resolve accepted something that is not a schema")
	}
}

func TestMutationsChangeOneThingAtATime(t *testing.T) {
	base := map[string]any{"project": "shop", "tags": []any{"a"}, "enabled": true}
	kinds := map[string]int{}
	for _, m := range Mutations(base) {
		kinds[m.Kind+" "+m.Path]++
		doc := m.Doc.(map[string]any)
		if m.Kind == "upper" && m.Path == "project" && doc["project"] != "SHOP" {
			t.Errorf("upper project: got %v", doc["project"])
		}
		if m.Kind == "string" {
			if _, isBool := doc["enabled"].(bool); isBool {
				t.Errorf("string enabled: still a boolean, %v", doc["enabled"])
			}
		}
	}
	for _, want := range []string{
		"extra-key ", "null project", "upper project", "unknown project", "number project",
		"bool project", "null tags", "null tags.0", "upper tags.0", "unknown tags.0",
		"null enabled", "string enabled",
	} {
		if kinds[want] != 1 {
			t.Errorf("mutation %q made %d times, want once", want, kinds[want])
		}
	}
	if base["project"] != "shop" || base["tags"].([]any)[0] != "a" || base["enabled"] != true {
		t.Errorf("a mutation changed the document it was made from: %v", base)
	}
}

// TestMutationsDropAndTransplant: each key deleted rather than nulled, and each key of one sibling
// copied onto the others that lack it, in a list and in a mapping of mappings, once per value.
func TestMutationsDropAndTransplant(t *testing.T) {
	base := map[string]any{
		"imports": []any{
			map[string]any{"file": "a.sarif"},
			map[string]any{"file": "b.json", "format": "trivy-json"},
			map[string]any{"file": "c.json", "format": "osv-scanner-json"},
			"not a mapping",
		},
		"accounts": map[string]any{
			"prod": map[string]any{"provider": "aws", "account": "011111111111"},
			"dev":  map[string]any{"provider": "gcp", "project": "dev-1"},
		},
		"labels": map[string]any{"team": "payments", "tier": map[string]any{"x": "y"}},
	}
	byKind := map[string][]Mutation{}
	for _, m := range Mutations(base) {
		byKind[m.Kind+" "+m.Path] = append(byKind[m.Kind+" "+m.Path], m)
	}
	drop := byKind["drop imports.1.format"]
	if len(drop) != 1 {
		t.Fatalf("drop imports.1.format made %d times, want once", len(drop))
	}
	if _, has := drop[0].Doc.(map[string]any)["imports"].([]any)[1].(map[string]any)["format"]; has {
		t.Error("drop left the key in place")
	}
	for _, c := range []struct {
		key  string
		want []string
	}{
		// Two donors offer format with two values, and each is a different rule.
		{"transplant from 1 imports.0.format", []string{"trivy-json"}},
		{"transplant from 2 imports.0.format", []string{"osv-scanner-json"}},
		{"transplant from dev accounts.prod.project", []string{"dev-1"}},
		{"transplant from prod accounts.dev.account", []string{"011111111111"}},
	} {
		got := byKind[c.key]
		if len(got) != len(c.want) {
			t.Errorf("%s made %d times, want %d", c.key, len(got), len(c.want))
			continue
		}
		path := strings.Split(strings.SplitN(c.key, " ", 4)[3], ".")
		if v := at(got[0].Doc, path); v != c.want[0] {
			t.Errorf("%s copied %v, want %v", c.key, v, c.want[0])
		}
	}
	for key := range byKind {
		// A mapping holding anything but mappings has no siblings, and a key an item already has is
		// not copied over its own value.
		if strings.HasPrefix(key, "transplant") && (strings.Contains(key, " labels.") || strings.HasSuffix(key, "imports.1.file")) {
			t.Errorf("unexpected mutation %s", key)
		}
	}
	if _, has := base["imports"].([]any)[0].(map[string]any)["format"]; has {
		t.Errorf("a transplant changed the document it was made from: %v", base)
	}
}

func TestCopyDirCopiesTheTree(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a", "b"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a", "b", "draugr.saga.yaml"), []byte(validSaga), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy")
	CopyDir(t, src, dst)
	copied := filepath.Join(dst, "a", "b", "draugr.saga.yaml")
	EditorAcceptsFile(t, copied, false)

	if got := observe(t, func(tb testing.TB) { CopyDir(tb, filepath.Join(src, "missing"), dst) }); len(got) == 0 {
		t.Error("copying a directory that does not exist succeeded")
	}
	if got := observe(t, func(tb testing.TB) { EditorAcceptsFile(tb, filepath.Join(src, "missing.yaml"), false) }); len(got) == 0 {
		t.Error("reading a file that does not exist succeeded")
	}
}
