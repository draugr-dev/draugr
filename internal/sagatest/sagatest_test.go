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
	base := map[string]any{"project": "shop", "tags": []any{"a"}}
	kinds := map[string]int{}
	for _, m := range Mutations(base) {
		kinds[m.Kind+" "+m.Path]++
		doc := m.Doc.(map[string]any)
		if m.Kind == "upper" && m.Path == "project" && doc["project"] != "SHOP" {
			t.Errorf("upper project: got %v", doc["project"])
		}
	}
	for _, want := range []string{
		"extra-key ", "null project", "upper project", "unknown project", "number project",
		"bool project", "null tags", "null tags.0", "upper tags.0", "unknown tags.0",
	} {
		if kinds[want] != 1 {
			t.Errorf("mutation %q made %d times, want once", want, kinds[want])
		}
	}
	if base["project"] != "shop" || base["tags"].([]any)[0] != "a" {
		t.Errorf("a mutation changed the document it was made from: %v", base)
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
