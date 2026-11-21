package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/draugrhome"
)

// DRAUGR_HOME moves everything the install writes: the binary to its bin/, the data to its data/.
// Then a lookup on a PATH that starts with BinDir, which is what every command runs under, finds
// the binary there and its data with it, and nothing was written under the home directory.
func TestInstallIntoDraugrHomeIsFoundThere(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(draugrhome.EnvVar, root)

	archive := tarGz(t, map[string]string{
		"hometool":        "#!/bin/sh\necho hometool 9.9.9\n",
		"cfg/config.yaml": "benchmarks",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "hometool", srv.URL, sha256Hex(archive), "hometool")
	spec := installable["hometool"]
	spec.DataDir = "hometool"
	asset := spec.Assets[platformKey()]
	asset.DataInArchive = "cfg/"
	spec.Assets = map[string]Asset{platformKey(): asset}
	installable["hometool"] = spec

	bin, err := BinDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "bin"); bin != want {
		t.Fatalf("BinDir() = %q, want %q", bin, want)
	}
	got, err := Install(context.Background(), "hometool", bin, srv.Client(), false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if want := filepath.Join(root, "bin", "hometool"); got.Path != want {
		t.Errorf("installed to %q, want %q", got.Path, want)
	}
	data := filepath.Join(root, "data", "hometool", "config.yaml")
	if _, err := os.Stat(data); err != nil {
		t.Errorf("the data did not go under DRAUGR_HOME: %v", err)
	}
	if DataDirFor("hometool") != filepath.Join(root, "data", "hometool") {
		t.Errorf("DataDirFor = %q", DataDirFor("hometool"))
	}
	if _, err := os.Stat(filepath.Join(home, ".draugr")); err == nil {
		t.Error("the install wrote under ~/.draugr with DRAUGR_HOME set")
	}

	t.Setenv("PATH", bin)
	tool := Tool{
		Binary:      "hometool",
		VersionArgs: []string{"--version"},
		DataFiles:   []string{"{dataroot}/hometool/config.yaml"},
	}
	st := Detect(context.Background(), tool, nil, nil)
	if !st.Found || st.Path != got.Path {
		t.Fatalf("Detect found=%v at %q, want the copy in %s", st.Found, st.Path, bin)
	}
	if st.Version != "9.9.9" {
		t.Errorf("version = %q, the installed copy was not the one run", st.Version)
	}
	if !st.DataFound || st.DataDetail != data {
		t.Errorf("data found=%v at %q, want %s", st.DataFound, st.DataDetail, data)
	}
}

// kube-bench's own catalog entry names the install's data through {dataroot}, so the copy
// `draugr tools install` puts under DRAUGR_HOME is the one doctor finds.
func TestKubeBenchDataFollowsDraugrHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv(draugrhome.EnvVar, root)
	kb, ok := Catalog()["kube-bench"]
	if !ok {
		t.Fatal("kube-bench is not in the catalog")
	}
	cfg := filepath.Join(root, "data", "kube-bench", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(context.Context, []string, ...string) ([]byte, error) { return []byte("0.15.6"), nil }
	st := Detect(context.Background(), kb, func(string) (string, error) { return "/nowhere/kube-bench", nil }, run)
	if !st.DataFound || st.DataDetail != cfg {
		t.Errorf("data found=%v at %q, want %s", st.DataFound, st.DataDetail, cfg)
	}
}

// A {dataroot} that cannot be worked out is left as written, a path that exists nowhere, so the
// data reads as absent rather than being looked for somewhere else.
func TestExpandDataPathWithARelativeDraugrHome(t *testing.T) {
	t.Setenv(draugrhome.EnvVar, "relative")
	if got := expandDataPath("{dataroot}/x"); got != "{dataroot}/x" {
		t.Errorf("expandDataPath = %q", got)
	}
	if _, err := BinDir(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("BinDir() = %v, want the refusal", err)
	}
	if _, err := DataRoot(); err == nil {
		t.Error("DataRoot() accepted a relative DRAUGR_HOME")
	}
}
