package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// makeTarGz builds an in-memory .tar.gz containing one regular file.
func makeTarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// registerTestTool injects a temporary installable entry pointing at url, and removes it when
// the test ends.
func registerTestTool(t *testing.T, name, url, sha, binaryInArchive string) {
	t.Helper()
	installable[name] = InstallSpec{
		Binary:  binaryInArchive,
		Version: "9.9.9",
		Assets:  map[string]Asset{platformKey(): {URL: url, SHA256: sha, BinaryInArchive: binaryInArchive}},
	}
	t.Cleanup(func() { delete(installable, name) })
}

func TestInstallSuccess(t *testing.T) {
	content := []byte("#!/bin/sh\necho fake-tool\n")
	archive := makeTarGz(t, "faketool", content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")

	dest := t.TempDir()
	got, err := Install(context.Background(), "faketool", dest, srv.Client())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got.Version != "9.9.9" || got.Name != "faketool" {
		t.Errorf("Installed = %+v", got)
	}

	binPath := filepath.Join(dest, "faketool")
	if got.Path != binPath {
		t.Errorf("Path = %q, want %q", got.Path, binPath)
	}
	on, err := os.ReadFile(binPath) //nolint:gosec // test reads a file it just wrote under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(on, content) {
		t.Error("installed content does not match archive")
	}
	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("installed binary is not executable: mode %v", info.Mode())
	}
}

func TestInstallChecksumMismatch(t *testing.T) {
	archive := makeTarGz(t, "faketool", []byte("real"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	// Register with a deliberately wrong checksum.
	registerTestTool(t, "faketool", srv.URL, sha256Hex([]byte("something else")), "faketool")

	dest := t.TempDir()
	if _, err := Install(context.Background(), "faketool", dest, srv.Client()); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if _, err := os.Stat(filepath.Join(dest, "faketool")); !os.IsNotExist(err) {
		t.Error("nothing should be written on checksum mismatch")
	}
}

func TestInstallHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, "irrelevant", "faketool")

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client()); err == nil {
		t.Fatal("expected error on HTTP 404")
	}
}

func TestInstallDefaultClient(t *testing.T) {
	archive := makeTarGz(t, "faketool", []byte("x"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")

	// nil client exercises the default-client branch.
	if _, err := Install(context.Background(), "faketool", t.TempDir(), nil); err != nil {
		t.Fatalf("Install with default client: %v", err)
	}
}

func TestInstallDestDirError(t *testing.T) {
	archive := makeTarGz(t, "faketool", []byte("x"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")

	// destDir is a regular file, so MkdirAll fails after a valid download+verify.
	destAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(destAsFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), "faketool", destAsFile, srv.Client()); err == nil {
		t.Fatal("expected error when destDir is not a directory")
	}
}

func TestInstallDownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now connections are refused
	registerTestTool(t, "faketool", url, "irrelevant", "faketool")

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client()); err == nil {
		t.Fatal("expected a download error against a closed server")
	}
}

func TestExtractFromTarGzBadGzip(t *testing.T) {
	if _, err := extractFromTarGz([]byte("not a gzip stream"), "x"); err == nil {
		t.Fatal("expected an error for non-gzip data")
	}
}

func TestWriteExecutableError(t *testing.T) {
	// A path whose parent is a regular file, not a directory, makes CreateTemp fail.
	notADir := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeExecutable(filepath.Join(notADir, "bin"), []byte("data")); err == nil {
		t.Fatal("expected error when the destination directory is invalid")
	}
}

func TestInstallUnknownTool(t *testing.T) {
	if _, err := Install(context.Background(), "nope", t.TempDir(), nil); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestInstallUnsupportedPlatform(t *testing.T) {
	installable["noplatform"] = InstallSpec{Binary: "noplatform", Version: "1.0.0", Assets: map[string]Asset{}}
	t.Cleanup(func() { delete(installable, "noplatform") })
	if _, err := Install(context.Background(), "noplatform", t.TempDir(), nil); err == nil {
		t.Fatal("expected error for unsupported platform")
	}
}

func TestExtractFromTarGzMissingBinary(t *testing.T) {
	archive := makeTarGz(t, "other", []byte("x"))
	if _, err := extractFromTarGz(archive, "faketool"); err == nil {
		t.Fatal("expected error when the binary is absent from the archive")
	}
}

func TestInstallableAndSpec(t *testing.T) {
	names := Installable()
	if len(names) < 3 || names[0] != "gitleaks" || names[1] != "gosec" || names[2] != "trivy" {
		t.Errorf("Installable() = %v, want sorted [gitleaks gosec trivy ...]", names)
	}
	spec, ok := Spec("trivy")
	if !ok || spec.Version == "" || len(spec.Assets) == 0 {
		t.Errorf("Spec(trivy) = %+v, ok=%v", spec, ok)
	}
	if _, ok := Spec("semgrep"); ok {
		t.Error("semgrep should not be installable as a binary")
	}
}

func TestSemgrepHelpers(t *testing.T) {
	if SemgrepVersion() == "" {
		t.Error("empty SemgrepVersion")
	}
	if got := SemgrepPipxCommand(); got != "pipx install semgrep=="+SemgrepVersion() {
		t.Errorf("SemgrepPipxCommand = %q", got)
	}
}

func TestBinDir(t *testing.T) {
	t.Setenv("HOME", "/tmp/draugr-home-test")
	dir, err := BinDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/tmp/draugr-home-test", ".draugr", "bin"); dir != want {
		t.Errorf("BinDir = %q, want %q", dir, want)
	}
}
