package detect

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// trees hands each repository the tree a test gave it, and records which ones were read.
type trees struct {
	by   map[string]inventory.Tree
	read []string
}

func (f *trees) read1(url string) inventory.Tree {
	f.read = append(f.read, url)
	return f.by[url]
}

func repos(urls ...string) []saga.Repository {
	out := make([]saga.Repository, len(urls))
	for i, u := range urls {
		out[i] = saga.Repository{URL: u}
	}
	return out
}

func enabled(t *testing.T, controls map[string]saga.ControllerSettings) []string {
	t.Helper()
	var out []string
	for name, s := range controls {
		if on, _ := s["enabled"].(bool); on {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// A descriptor without config.detect is left exactly as written, its repositories unread: one that
// names no control, such as one that only imports another tool's results, runs nothing more.
func TestApplyLeavesADescriptorWithoutDetectAlone(t *testing.T) {
	dir := t.TempDir()
	m := &saga.Model{Project: "p", Components: []saga.Component{{Name: "a", Repositories: repos(dir)}}}
	f := &trees{}
	res, err := ApplyWith(m, f.read1)
	if err != nil || res != nil {
		t.Fatalf("res = %v, err = %v; want nothing", res, err)
	}
	if m.Config.Controls != nil || m.Config.Reachability != nil || len(f.read) > 0 {
		t.Errorf("controls = %v, reachability = %v, read = %v; want the model untouched", m.Config.Controls,
			m.Config.Reachability, f.read)
	}
	if res, err := Apply(nil); res != nil || err != nil {
		t.Errorf("Apply(nil) = %v, %v", res, err)
	}
}

// Two repositories, a Go module in one and a Dockerfile in the other: the controls are one set for
// the descriptor, so both repositories' files decide it, and a repository two components name is
// read once and listed under both.
func TestApplyDecidesFromEveryRepository(t *testing.T) {
	api, web := t.TempDir(), t.TempDir()
	f := &trees{by: map[string]inventory.Tree{
		api: {Go: []string{"."}},
		web: {Dockerfiles: []string{"Dockerfile"}},
	}}
	m := &saga.Model{Project: "p", Config: saga.Config{Detect: true}, Components: []saga.Component{
		{Name: "api", Repositories: repos(api)},
		{Name: "web", Repositories: repos(web)},
		{Name: "worker", Repositories: repos(api)},
	}}
	res, err := ApplyWith(m, f.read1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{api, web}; !slices.Equal(f.read, want) {
		t.Errorf("read %v, want each repository once, in order: %v", f.read, want)
	}
	if got := enabled(t, m.Config.Controls); !slices.Equal(got, []string{"iac", "sast", "sca", "secrets"}) {
		t.Errorf("controls on = %v", got)
	}
	if _, ok := m.Config.Controls["sast"]["gosec"]; !ok {
		t.Errorf("sast = %v, want gosec for the go.mod", m.Config.Controls["sast"])
	}
	if m.Config.Reachability == nil || !slices.Equal(m.Config.Reachability.Analyzers, []string{"govulncheck"}) {
		t.Errorf("reachability = %v, want govulncheck for the go.mod", m.Config.Reachability)
	}
	if len(res.Read) != 2 || !slices.Equal(res.Read[0].Components, []string{"api", "worker"}) ||
		!slices.Equal(res.Read[1].Components, []string{"web"}) {
		t.Errorf("read = %+v", res.Read)
	}
}

// A repository named by a remote url has no copy on this machine while the controls are decided, so
// it is listed as unread, once, under each component naming it, and only the base controls are on.
func TestApplyNamesARemoteRepositoryUnread(t *testing.T) {
	remote := "https://github.com/example/app.git"
	m := &saga.Model{Project: "p", Config: saga.Config{Detect: true}, Components: []saga.Component{
		{Name: "a", Repositories: repos(remote)},
		{Name: "b", Repositories: repos(remote)},
	}}
	f := &trees{}
	res, err := ApplyWith(m, f.read1)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.read) > 0 || len(res.Read) > 0 {
		t.Errorf("read %v; want nothing read", f.read)
	}
	if want := []Unread{{URL: remote, Components: []string{"a", "b"}}}; !reflect.DeepEqual(res.Unread, want) {
		t.Errorf("unread = %+v, want %+v", res.Unread, want)
	}
	if got := enabled(t, m.Config.Controls); !slices.Equal(got, []string{"sast", "sca", "secrets"}) {
		t.Errorf("controls on = %v, want the base", got)
	}
}

// A control the descriptor writes is set as written over what was detected: `enabled: false` turns
// it off, a setting it adds is kept beside the detected ones, and reachability it writes is its own.
// AsWritten gives back the descriptor's own settings.
func TestWrittenControlsLayOverDetectedOnes(t *testing.T) {
	dir := t.TempDir()
	f := &trees{by: map[string]inventory.Tree{dir: {Go: []string{"."}, Dockerfiles: []string{"Dockerfile"}}}}
	written := map[string]saga.ControllerSettings{
		"iac":  {"enabled": false},
		"sast": {"semgrep": map[string]any{"config": "p/ci"}},
	}
	reach := &saga.ReachabilityConfig{}
	m := &saga.Model{Project: "p", Config: saga.Config{Detect: true, Controls: maps.Clone(written), Reachability: reach},
		Components: []saga.Component{{Name: "a", Repositories: repos(dir)}}}
	res, err := ApplyWith(m, f.read1)
	if err != nil {
		t.Fatal(err)
	}
	if got := enabled(t, m.Config.Controls); !slices.Equal(got, []string{"sast", "sca", "secrets"}) {
		t.Errorf("controls on = %v, want iac off as written", got)
	}
	sast := m.Config.Controls["sast"]
	if _, ok := sast["gosec"]; !ok || sast["semgrep"] == nil || sast["enabled"] != true {
		t.Errorf("sast = %v, want the written semgrep setting beside the detected ones", sast)
	}
	if m.Config.Reachability != reach {
		t.Errorf("reachability = %v, want the descriptor's own", m.Config.Reachability)
	}
	as := res.AsWritten(m)
	if !reflect.DeepEqual(as.Config.Controls, written) || as.Config.Reachability != reach {
		t.Errorf("as written = %v, %v; want %v", as.Config.Controls, as.Config.Reachability, written)
	}
	if m.Config.Controls["sca"] == nil {
		t.Error("AsWritten changed the model it was given")
	}
}

func TestLayerOfNothingIsNil(t *testing.T) {
	if got := Layer(nil, nil); got != nil {
		t.Errorf("Layer(nil, nil) = %v", got)
	}
}

// Merge carries every list a Tree holds, so a kind of file the inventory learns to find reaches
// detect without an edit here.
func TestMergeCarriesEveryList(t *testing.T) {
	var a, b inventory.Tree
	n := 0
	for _, tree := range []*inventory.Tree{&a, &b} {
		v := reflect.ValueOf(tree).Elem()
		for i := range v.NumField() {
			f := v.Field(i)
			if f.Kind() != reflect.Slice {
				continue
			}
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			n++
		}
	}
	got := reflect.ValueOf(Merge(a, b))
	for i := range got.NumField() {
		if f := got.Field(i); f.Kind() == reflect.Slice && f.Len() != 2 {
			t.Errorf("%s has %d entries, want 2", got.Type().Field(i).Name, f.Len())
		}
	}
	if n == 0 {
		t.Fatal("inventory.Tree has no lists")
	}
}

// Apply reads the repository from disk.
func TestApplyReadsTheRepository(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"go.mod": "module app\n\ngo 1.22\n", "main.go": "package main\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := &saga.Model{Project: "p", Config: saga.Config{Detect: true}, Components: []saga.Component{{Name: "a", Repositories: repos(dir)}}}
	if _, err := Apply(m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Config.Controls["sast"]["gosec"]; !ok {
		t.Errorf("sast = %v, want gosec for the go.mod on disk", m.Config.Controls["sast"])
	}
}
