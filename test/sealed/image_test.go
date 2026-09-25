package sealed

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestServeImage(t *testing.T) {
	s := Scenario{Name: "demo", Dir: t.TempDir()}
	writeFixture(t, filepath.Join(s.Dir, "image", "usr", "lib", "METADATA"+FixtureSuffix), "Name: Flask\n")
	served := t.TempDir()
	if err := s.ServeImage(served); err != nil {
		t.Fatal(err)
	}
	if ServedImage(s.Name) != "127.0.0.1:18080/demo:1.0" {
		t.Errorf("ServedImage = %s", ServedImage(s.Name))
	}
	dir := filepath.Join(served, "v2", "demo")
	manifest, err := os.ReadFile(filepath.Join(dir, "manifests", "1.0")) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifest)
	if byDigest, err := os.ReadFile(filepath.Join(dir, "manifests", "sha256:"+hex.EncodeToString(sum[:]))); err != nil || !bytes.Equal(byDigest, manifest) { // #nosec G304 G703 -- under t.TempDir()
		t.Errorf("the manifest is not served under its digest: %v", err)
	}
	var m struct {
		MediaType string
		Config    struct{ Digest string }
		Layers    []struct{ Digest string }
	}
	if err := json.Unmarshal(manifest, &m); err != nil || len(m.Layers) != 1 {
		t.Fatalf("manifest %s (%v)", manifest, err)
	}
	blob := func(digest string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "blobs", digest)) // #nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(b); "sha256:"+hex.EncodeToString(got[:]) != digest {
			t.Errorf("blob %s holds other bytes", digest)
		}
		return b
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(blob(m.Config.Digest), &config); err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(blob(m.Layers[0].Digest)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if diff := sha256.Sum256(raw); len(config.RootFS.DiffIDs) != 1 || config.RootFS.DiffIDs[0] != "sha256:"+hex.EncodeToString(diff[:]) {
		t.Errorf("diff_ids %v do not name the layer", config.RootFS.DiffIDs)
	}
	var names []string
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if want := []string{"usr/", "usr/lib/", "usr/lib/METADATA"}; !slices.Equal(names, want) {
		t.Errorf("layer holds %v, want %v", names, want)
	}

	// The same tree gives the same image, so the digests a golden records hold across runs.
	again := t.TempDir()
	if err := s.ServeImage(again); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.ReadFile(filepath.Join(again, "v2", "demo", "manifests", "1.0")); !bytes.Equal(second, manifest) { // #nosec G304 -- under t.TempDir()
		t.Error("the image differs between two writes of one tree")
	}
}

func TestServeImageWithout(t *testing.T) {
	s := Scenario{Name: "demo", Dir: t.TempDir()}
	served := t.TempDir()
	if err := s.ServeImage(served); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(served); len(entries) != 0 {
		t.Errorf("a scenario without image/ served %v", entries)
	}
	// A served directory that cannot be written.
	writeFixture(t, filepath.Join(s.Dir, "image", "a"), "a")
	blocked := filepath.Join(served, "file")
	writeFixture(t, blocked, "x")
	if err := s.ServeImage(blocked); err == nil {
		t.Error("served an image into a file")
	}
}
