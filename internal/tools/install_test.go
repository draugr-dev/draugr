package tools

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// makeZip builds an in-memory .zip containing one file.
func makeZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
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
	got, err := Install(context.Background(), "faketool", dest, srv.Client(), false)
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

func TestInstallBareBinary(t *testing.T) {
	// A bare binary asset (no archive): BinaryInArchive == "" → the download IS the binary.
	content := []byte("#!/bin/sh\necho bare\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	installable["barebin"] = InstallSpec{
		Binary:  "barebin",
		Version: "1.0.0",
		Assets:  map[string]Asset{platformKey(): {URL: srv.URL, SHA256: sha256Hex(content)}}, // BinaryInArchive empty
	}
	t.Cleanup(func() { delete(installable, "barebin") })

	dest := t.TempDir()
	got, err := Install(context.Background(), "barebin", dest, srv.Client(), false)
	if err != nil {
		t.Fatalf("Install bare binary: %v", err)
	}
	on, err := os.ReadFile(filepath.Join(dest, "barebin")) //nolint:gosec // test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(on, content) {
		t.Errorf("bare binary content mismatch: got %q", on)
	}
	_ = got
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
	if _, err := Install(context.Background(), "faketool", dest, srv.Client(), false); err == nil {
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

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client(), false); err == nil {
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
	if _, err := Install(context.Background(), "faketool", t.TempDir(), nil, false); err != nil {
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
	if _, err := Install(context.Background(), "faketool", destAsFile, srv.Client(), false); err == nil {
		t.Fatal("expected error when destDir is not a directory")
	}
}

func TestInstallDownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now connections are refused
	registerTestTool(t, "faketool", url, "irrelevant", "faketool")

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client(), false); err == nil {
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
	if _, err := Install(context.Background(), "nope", t.TempDir(), nil, false); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestInstallUnsupportedPlatform(t *testing.T) {
	installable["noplatform"] = InstallSpec{Binary: "noplatform", Version: "1.0.0", Assets: map[string]Asset{}}
	t.Cleanup(func() { delete(installable, "noplatform") })
	if _, err := Install(context.Background(), "noplatform", t.TempDir(), nil, false); err == nil {
		t.Fatal("expected error for unsupported platform")
	}
}

func TestExtractFromTarGzMissingBinary(t *testing.T) {
	archive := makeTarGz(t, "other", []byte("x"))
	if _, err := extractFromTarGz(archive, "faketool"); err == nil {
		t.Fatal("expected error when the binary is absent from the archive")
	}
}

func TestInstallZipArchive(t *testing.T) {
	// A .zip asset (Nuclei ships zips) is detected by magic bytes and extracted.
	content := []byte("#!/bin/sh\necho zipped\n")
	archive := makeZip(t, "faketool", content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")

	dest := t.TempDir()
	if _, err := Install(context.Background(), "faketool", dest, srv.Client(), false); err != nil {
		t.Fatalf("Install from zip: %v", err)
	}
	on, err := os.ReadFile(filepath.Join(dest, "faketool")) //nolint:gosec // test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(on, content) {
		t.Errorf("extracted zip content mismatch: got %q", on)
	}
}

func TestExtractFromZip(t *testing.T) {
	archive := makeZip(t, "nested/dir/nuclei", []byte("binary-bytes"))
	got, err := extractFromZip(archive, "nuclei")
	if err != nil {
		t.Fatalf("extractFromZip: %v", err)
	}
	if string(got) != "binary-bytes" {
		t.Errorf("content = %q", got)
	}
}

func TestExtractFromZipMissingBinary(t *testing.T) {
	archive := makeZip(t, "other", []byte("x"))
	if _, err := extractFromZip(archive, "nuclei"); err == nil {
		t.Fatal("expected error when the binary is absent from the zip")
	}
}

func TestExtractFromZipBadData(t *testing.T) {
	if _, err := extractFromZip([]byte("not a zip"), "x"); err == nil {
		t.Fatal("expected an error for non-zip data")
	}
}

func TestExtractBinaryDispatch(t *testing.T) {
	// gzip data → tar path; zip-magic data → zip path.
	tgz := makeTarGz(t, "t", []byte("from-tar"))
	if got, err := extractBinary(tgz, "t"); err != nil || string(got) != "from-tar" {
		t.Errorf("tar dispatch: got %q err %v", got, err)
	}
	zp := makeZip(t, "t", []byte("from-zip"))
	if got, err := extractBinary(zp, "t"); err != nil || string(got) != "from-zip" {
		t.Errorf("zip dispatch: got %q err %v", got, err)
	}
}

func TestInstallableAndSpec(t *testing.T) {
	names := Installable()
	want := []string{"cosign", "gitleaks", "gosec", "grype", "kube-bench", "nuclei", "retire", "semgrep", "syft", "trivy"}
	if len(names) < len(want) {
		t.Fatalf("Installable() = %v, want at least %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("Installable()[%d] = %q, want %q (full: %v)", i, names[i], w, names)
		}
	}
	if _, ok := Spec("nuclei"); !ok {
		t.Error("nuclei should be installable")
	}
	spec, ok := Spec("trivy")
	if !ok || spec.Version == "" || len(spec.Assets) == 0 {
		t.Errorf("Spec(trivy) = %+v, ok=%v", spec, ok)
	}
	if _, ok := Spec("semgrep"); ok {
		t.Error("semgrep should not be installable as a binary")
	}
}

func TestSemgrepVersionIsPinned(t *testing.T) {
	if SemgrepVersion() == "" {
		t.Error("empty SemgrepVersion")
	}
	// The two have to agree: one drives what is installed, the other what the plan and the report
	// say was installed.
	if got := PythonVersion("semgrep"); got != SemgrepVersion() {
		t.Errorf("PythonVersion(semgrep) = %q, SemgrepVersion() = %q", got, SemgrepVersion())
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

// Re-provisioning is the common case in CI. A tool already present at the pinned build must not
// be downloaded again — but "already present" has to mean the exact bytes we installed, or a
// modified binary would be silently accepted.
func TestInstallSkipsWhenAlreadyPresent(t *testing.T) {
	content := []byte("#!/bin/sh\necho fake-tool\n")
	archive := makeTarGz(t, "faketool", content)
	var downloads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads++
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")
	dest := t.TempDir()

	first, err := Install(context.Background(), "faketool", dest, srv.Client(), false)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	if first.AlreadyPresent {
		t.Error("a fresh install should not report AlreadyPresent")
	}

	second, err := Install(context.Background(), "faketool", dest, srv.Client(), false)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !second.AlreadyPresent {
		t.Error("the second install should have been skipped")
	}
	if downloads != 1 {
		t.Errorf("downloaded %d times, want 1", downloads)
	}
	if second.Path != first.Path || second.Version != first.Version {
		t.Errorf("skip should still report the install: %+v", second)
	}
}

func TestInstallForceReinstalls(t *testing.T) {
	archive := makeTarGz(t, "faketool", []byte("x"))
	var downloads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads++
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")
	dest := t.TempDir()

	if _, err := Install(context.Background(), "faketool", dest, srv.Client(), false); err != nil {
		t.Fatal(err)
	}
	got, err := Install(context.Background(), "faketool", dest, srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.AlreadyPresent {
		t.Error("--force should reinstall, not skip")
	}
	if downloads != 2 {
		t.Errorf("downloaded %d times, want 2", downloads)
	}
}

// The security-relevant case: if the installed binary has been modified, "already installed"
// must not accept it — Draugr repairs it instead.
func TestInstallReplacesModifiedBinary(t *testing.T) {
	content := []byte("#!/bin/sh\necho fake-tool\n")
	archive := makeTarGz(t, "faketool", content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()
	registerTestTool(t, "faketool", srv.URL, sha256Hex(archive), "faketool")
	dest := t.TempDir()

	if _, err := Install(context.Background(), "faketool", dest, srv.Client(), false); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dest, "faketool")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nrm -rf /\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Install(context.Background(), "faketool", dest, srv.Client(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.AlreadyPresent {
		t.Fatal("a modified binary must not count as already installed")
	}
	on, err := os.ReadFile(binPath) //nolint:gosec // test reads a file under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(on, content) {
		t.Error("the modified binary should have been replaced with the pinned build")
	}
}

// A pin bump must not be masked by a previous install of the older build.
func TestInstallReinstallsWhenPinChanges(t *testing.T) {
	first := makeTarGz(t, "faketool", []byte("v1"))
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(first)
	}))
	defer srv1.Close()
	registerTestTool(t, "faketool", srv1.URL, sha256Hex(first), "faketool")
	dest := t.TempDir()
	if _, err := Install(context.Background(), "faketool", dest, srv1.Client(), false); err != nil {
		t.Fatal(err)
	}

	// Same tool name, new upstream build: the recorded asset checksum no longer matches.
	second := makeTarGz(t, "faketool", []byte("v2"))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(second)
	}))
	defer srv2.Close()
	registerTestTool(t, "faketool", srv2.URL, sha256Hex(second), "faketool")

	got, err := Install(context.Background(), "faketool", dest, srv2.Client(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.AlreadyPresent {
		t.Fatal("a changed pin must reinstall")
	}
	on, _ := os.ReadFile(filepath.Join(dest, "faketool")) //nolint:gosec // test file under t.TempDir()
	if string(on) != "v2" {
		t.Errorf("installed content = %q, want the new build", on)
	}
}

// tarGz builds an archive from a path→contents map, for testing extraction.
func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []io.Closer{tw, gz} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestExtractTreeWritesTheWholeSubtree(t *testing.T) {
	// kube-bench's cfg/ is 276 files across per-benchmark directories; the layout below the
	// prefix is what kube-bench resolves against, so it has to survive.
	archive := tarGz(t, map[string]string{
		"kube-bench":               "binary",
		"cfg/config.yaml":          "root",
		"cfg/cis-1.12/master.yaml": "master",
		"cfg/cis-1.12/node.yaml":   "node",
		"README.md":                "not ours",
	})
	dest := filepath.Join(t.TempDir(), "cfg")
	n, err := extractTree(archive, "cfg/", dest)
	if err != nil {
		t.Fatalf("extractTree: %v", err)
	}
	if n != 3 {
		t.Errorf("wrote %d files, want 3", n)
	}
	//nolint:gosec // dest is this test's own temp directory
	if b, err := os.ReadFile(filepath.Join(dest, "cis-1.12", "master.yaml")); err != nil || string(b) != "master" {
		t.Errorf("nested layout not preserved: %v %q", err, b)
	}
	if _, err := os.Stat(filepath.Join(dest, "README.md")); err == nil {
		t.Error("only the prefix should be extracted")
	}
}

func TestExtractTreeClearsWhatWasThere(t *testing.T) {
	// A definition left over from an older release is a benchmark nobody chose, and kube-bench
	// would read it as happily as the new ones.
	dest := t.TempDir()
	stale := filepath.Join(dest, "cis-1.0", "old.yaml")
	if err := os.MkdirAll(filepath.Dir(stale), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := extractTree(tarGz(t, map[string]string{"cfg/config.yaml": "new"}), "cfg/", dest); err != nil {
		t.Fatalf("extractTree: %v", err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the previous tree should be gone")
	}
}

func TestExtractTreeRefusesAnEscapingEntry(t *testing.T) {
	// A matching checksum proves the archive is the one upstream published, not that it is
	// well-behaved.
	dest := filepath.Join(t.TempDir(), "cfg")
	_, err := extractTree(tarGz(t, map[string]string{"cfg/../../escaped.yaml": "x"}), "cfg/", dest)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "not a safe relative path") {
		t.Errorf("the error should say why: %v", err)
	}
}

func TestExtractTreeReportsAnEmptyPrefix(t *testing.T) {
	// Silently writing nothing would leave a tool installed and unusable, reported as installed.
	if _, err := extractTree(tarGz(t, map[string]string{"other/x": "y"}), "cfg/", t.TempDir()); err == nil {
		t.Error("expected an error when the prefix matches nothing")
	}
}

func TestKubeBenchSpecCarriesItsData(t *testing.T) {
	spec, ok := Spec("kube-bench")
	if !ok {
		t.Fatal("kube-bench should be installable")
	}
	if spec.DataDir == "" {
		t.Error("it needs somewhere for cfg/ to go")
	}
	for platform, asset := range spec.Assets {
		if asset.DataInArchive == "" {
			t.Errorf("%s: the binary alone is a half-install", platform)
		}
	}
	if DataDirFor("kube-bench") == "" {
		t.Error("DataDirFor should resolve it")
	}
	if DataDirFor("trivy") != "" {
		t.Error("a tool with no data should resolve to nothing")
	}
}

// TestInstallVersionRoutesLanguagePackages covers the dispatch every `draugr tools install <tool>`
// goes through.
//
// The language-package installers are tested directly elsewhere, which proves they work and not
// that anything reaches them. If this dispatch stopped matching, the command would fall through to
// the release-archive path and fail looking for assets a package-managed tool has never had — and
// no test of the installers themselves would notice.
func TestInstallVersionRoutesLanguagePackages(t *testing.T) {
	t.Run("python package", func(t *testing.T) {
		root := t.TempDir()
		fakePython(t, filepath.Join(t.TempDir(), "calls"), "--require-hashes")

		got, err := InstallVersion(t.Context(), "semgrep", "", filepath.Join(root, "bin"), nil, false)
		if err != nil {
			t.Fatalf("semgrep did not reach the Python installer: %v", err)
		}
		if got.Path != filepath.Join(root, "bin", "semgrep") {
			t.Errorf("path = %q", got.Path)
		}
	})

	t.Run("npm package", func(t *testing.T) {
		root := t.TempDir()
		stubNodeTools(t, fakeNPM(t, filepath.Join(t.TempDir(), "calls"), "ci"))

		got, err := InstallVersion(t.Context(), "retire", "", filepath.Join(root, "bin"), nil, false)
		if err != nil {
			t.Fatalf("retire did not reach the npm installer: %v", err)
		}
		if got.Path != filepath.Join(root, "bin", "retire") {
			t.Errorf("path = %q", got.Path)
		}
		if got.Version != retireVersion {
			t.Errorf("version = %q, want the pinned %q", got.Version, retireVersion)
		}
	})
}
