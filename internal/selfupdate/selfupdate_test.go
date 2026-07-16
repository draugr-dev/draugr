package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

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
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func assetName(version string) string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	return "draugr_" + version + "_" + runtime.GOOS + "_" + runtime.GOARCH + "." + ext
}

// releaseServer serves the redirect + assets for a fake release and points githubBase at it.
func releaseServer(t *testing.T, version string, archive []byte, corruptChecksum bool) {
	t.Helper()
	sum := sha256Hex(archive)
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/v"+version, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/releases/download/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case filepath.Base(r.URL.Path) == "checksums.txt":
			s := sum
			if corruptChecksum {
				s = sha256Hex([]byte("different"))
			}
			_, _ = w.Write([]byte(s + "  " + assetName(version) + "\n"))
		case filepath.Base(r.URL.Path) == "checksums.txt.sigstore.json":
			_, _ = w.Write([]byte("{}"))
		case filepath.Ext(r.URL.Path) == ".gz" || filepath.Ext(r.URL.Path) == ".zip":
			_, _ = w.Write(archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	orig := githubBase
	githubBase = srv.URL
	t.Cleanup(func() { githubBase = orig })
}

// stubCosign sets whether the cosign CLI is "present" and what verification returns.
func stubCosign(t *testing.T, present bool, verifyErr error) {
	t.Helper()
	origLook, origRun := cosignLookPath, runCosign
	if present {
		cosignLookPath = func() (string, error) { return "/usr/bin/cosign", nil }
	} else {
		cosignLookPath = func() (string, error) { return "", os.ErrNotExist }
	}
	runCosign = func(context.Context, string, []string) error { return verifyErr }
	t.Cleanup(func() { cosignLookPath, runCosign = origLook, origRun })
}

// withExe points resolveExe at a temp file so tests never overwrite themselves.
func withExe(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "draugr")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // fixture
		t.Fatal(err)
	}
	orig := resolveExe
	resolveExe = func() (string, error) { return exe, nil }
	t.Cleanup(func() { resolveExe = orig })
	return exe
}

func TestLatestVersion(t *testing.T) {
	releaseServer(t, "9.9.9", makeTarGz(t, "draugr", []byte("x")), false)
	got, err := LatestVersion(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "9.9.9" {
		t.Errorf("LatestVersion = %q, want 9.9.9", got)
	}
}

func TestLatestVersionBadURL(t *testing.T) {
	// Server whose /releases/latest doesn't redirect to a /tag/ URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)
	orig := githubBase
	githubBase = srv.URL
	t.Cleanup(func() { githubBase = orig })
	if _, err := LatestVersion(context.Background(), nil); err == nil {
		t.Fatal("expected an error when the URL has no /tag/ segment")
	}
}

func TestUpdateReplacesBinary_SHAOnly(t *testing.T) {
	newBin := []byte("#!/bin/sh\necho new\n")
	releaseServer(t, "9.9.9", makeTarGz(t, binName(), newBin), false)
	stubCosign(t, false, nil) // cosign absent → SHA-256 only
	exe := withExe(t)

	res, err := Update(context.Background(), Options{Version: "9.9.9"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.SignatureVerified || res.Note == "" {
		t.Errorf("expected SHA-only with a note, got %+v", res)
	}
	if on, _ := os.ReadFile(exe); !bytes.Equal(on, newBin) { //nolint:gosec // temp path
		t.Errorf("binary not replaced: %q", on)
	}
}

func TestUpdateCosignVerified(t *testing.T) {
	releaseServer(t, "9.9.9", makeTarGz(t, binName(), []byte("new")), false)
	stubCosign(t, true, nil) // cosign present + verifies
	withExe(t)
	res, err := Update(context.Background(), Options{Version: "9.9.9"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !res.SignatureVerified {
		t.Error("expected SignatureVerified with cosign present + passing")
	}
}

func TestUpdateCosignFails(t *testing.T) {
	releaseServer(t, "9.9.9", makeTarGz(t, binName(), []byte("new")), false)
	stubCosign(t, true, errors.New("bad signature"))
	exe := withExe(t)
	if _, err := Update(context.Background(), Options{Version: "9.9.9"}); err == nil {
		t.Fatal("expected error when cosign verification fails")
	}
	if on, _ := os.ReadFile(exe); string(on) != "old" { //nolint:gosec // temp path
		t.Error("binary must not be replaced when signature verification fails")
	}
}

func TestUpdateChecksumMismatch(t *testing.T) {
	releaseServer(t, "9.9.9", makeTarGz(t, binName(), []byte("payload")), true)
	stubCosign(t, false, nil)
	exe := withExe(t)
	if _, err := Update(context.Background(), Options{Version: "9.9.9"}); err == nil {
		t.Fatal("expected a checksum verification error")
	}
	if on, _ := os.ReadFile(exe); string(on) != "old" { //nolint:gosec // temp path
		t.Error("binary must not be replaced on checksum mismatch")
	}
}

func TestUpdateNoChange(t *testing.T) {
	res, err := Update(context.Background(), Options{Version: CurrentVersion()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoChange {
		t.Error("same version should be a no-op")
	}
}

func TestUpdateDownloadError(t *testing.T) {
	// Server returns 404 for everything → archive download fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	t.Cleanup(srv.Close)
	orig := githubBase
	githubBase = srv.URL
	t.Cleanup(func() { githubBase = orig })
	withExe(t)
	if _, err := Update(context.Background(), Options{Version: "9.9.9"}); err == nil {
		t.Fatal("expected a download error")
	}
}

func TestUpdateResolveExeError(t *testing.T) {
	// Download + verify + extract all succeed; resolving the running binary fails.
	releaseServer(t, "9.9.9", makeTarGz(t, binName(), []byte("new")), false)
	stubCosign(t, false, nil)
	orig := resolveExe
	resolveExe = func() (string, error) { return "", errors.New("cannot find self") }
	t.Cleanup(func() { resolveExe = orig })
	if _, err := Update(context.Background(), Options{Version: "9.9.9"}); err == nil {
		t.Fatal("expected an error when the running binary can't be resolved")
	}
}

func TestExtractTarGzMissing(t *testing.T) {
	if _, err := extractTarGz(makeTarGz(t, "other", []byte("x")), "draugr"); err == nil {
		t.Fatal("expected error when the binary is absent from the archive")
	}
}

func TestExtractTarGzBadGzip(t *testing.T) {
	if _, err := extractTarGz([]byte("not a gzip stream"), "draugr"); err == nil {
		t.Fatal("expected an error for non-gzip data")
	}
}

func TestUpdateBundleDownloadError(t *testing.T) {
	// cosign present, but the signature bundle 404s → signature verification errors out.
	archive := makeTarGz(t, binName(), []byte("new"))
	sum := sha256Hex(archive)
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/download/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case filepath.Base(r.URL.Path) == "checksums.txt":
			_, _ = w.Write([]byte(sum + "  " + assetName("9.9.9") + "\n"))
		case filepath.Ext(r.URL.Path) == ".gz" || filepath.Ext(r.URL.Path) == ".zip":
			_, _ = w.Write(archive)
		default: // bundle → 404
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	orig := githubBase
	githubBase = srv.URL
	t.Cleanup(func() { githubBase = orig })
	stubCosign(t, true, nil) // present → tries to download the bundle
	withExe(t)

	if _, err := Update(context.Background(), Options{Version: "9.9.9"}); err == nil {
		t.Fatal("expected an error when the signature bundle can't be downloaded")
	}
}

func TestChecksumListed(t *testing.T) {
	data := []byte("abc  draugr_1_linux_amd64.tar.gz\n")
	if !checksumListed(data, "draugr_1_linux_amd64.tar.gz", "ABC") {
		t.Error("should match case-insensitively")
	}
	if checksumListed(data, "other.tar.gz", "abc") {
		t.Error("should not match a different file")
	}
}

func binName() string {
	if runtime.GOOS == "windows" {
		return "draugr.exe"
	}
	return "draugr"
}

func makeZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestExtractZip(t *testing.T) {
	z := makeZip(t, "draugr.exe", []byte("winbin"))
	got, err := extract(z, "zip", "draugr.exe")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "winbin" {
		t.Errorf("extract zip = %q, want winbin", got)
	}
	if _, err := extractZip(z, "absent"); err == nil {
		t.Error("expected a not-found error")
	}
	if _, err := extractZip([]byte("not a zip"), "x"); err == nil {
		t.Error("expected a bad-zip error")
	}
}

func TestUpdateResolvesLatest(t *testing.T) {
	releaseServer(t, "9.9.9", makeTarGz(t, binName(), []byte("new")), false)
	stubCosign(t, false, nil)
	withExe(t)
	res, err := Update(context.Background(), Options{}) // no Version → resolve latest
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "9.9.9" {
		t.Errorf("resolved target = %q, want 9.9.9", res.Target)
	}
}

func TestReplaceBinaryError(t *testing.T) {
	// A destination whose parent directory doesn't exist makes CreateTemp fail.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "draugr")
	if err := replaceBinary(bad, []byte("x")); err == nil {
		t.Fatal("expected an error when the destination directory is invalid")
	}
}
