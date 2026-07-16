package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// cosignTestServer serves an archive, a checksums file, and a signature bundle for a fake
// tool, and registers an installable spec (with a Cosign config) pointing at them.
func cosignTestServer(t *testing.T, listChecksum bool) (*httptest.Server, []byte) {
	t.Helper()
	archive := makeTarGz(t, "faketool", []byte("#!/bin/sh\necho fake\n"))
	assetFile := "faketool_9.9.9_linux.tar.gz"
	sum := sha256Hex(archive)
	checksums := "deadbeef  some_other_file.tar.gz\n"
	if listChecksum {
		checksums += sum + "  " + assetFile + "\n"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/"+assetFile, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksums)) })
	mux.HandleFunc("/checksums.sigstore.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	installable["faketool"] = InstallSpec{
		Binary:  "faketool",
		Version: "9.9.9",
		Cosign: &CosignSpec{
			ChecksumsURL:   srv.URL + "/checksums.txt",
			BundleURL:      srv.URL + "/checksums.sigstore.json",
			IdentityRegexp: `^https://example\.test/.*$`,
			OIDCIssuer:     "https://token.example.test",
		},
		Assets: map[string]Asset{platformKey(): {
			URL:             srv.URL + "/" + assetFile,
			SHA256:          sum,
			BinaryInArchive: "faketool",
		}},
	}
	t.Cleanup(func() { delete(installable, "faketool") })
	return srv, archive
}

// stubCosign overrides the cosign hooks for a test and restores them afterwards.
func stubCosign(t *testing.T, found bool, verifyErr error) *[]string {
	t.Helper()
	origLook, origRun := cosignLookPath, runCosignVerify
	t.Cleanup(func() { cosignLookPath, runCosignVerify = origLook, origRun })

	var gotArgs []string
	if found {
		cosignLookPath = func() (string, error) { return "/usr/bin/cosign", nil }
	} else {
		cosignLookPath = func() (string, error) { return "", os.ErrNotExist }
	}
	runCosignVerify = func(_ context.Context, _ string, args []string) error {
		gotArgs = args
		return verifyErr
	}
	return &gotArgs
}

func TestInstallCosignVerified(t *testing.T) {
	srv, _ := cosignTestServer(t, true)
	args := stubCosign(t, true, nil)

	got, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !got.SignatureVerified {
		t.Error("SignatureVerified = false, want true")
	}
	if got.ProvenanceNote != "cosign signature verified" {
		t.Errorf("ProvenanceNote = %q", got.ProvenanceNote)
	}
	// The verify-blob invocation carries the pinned identity + new bundle format.
	joined := ""
	for _, a := range *args {
		joined += a + " "
	}
	for _, want := range []string{"verify-blob", "--new-bundle-format", "--certificate-identity-regexp", "--certificate-oidc-issuer"} {
		if !contains(joined, want) {
			t.Errorf("cosign args missing %q; got %v", want, *args)
		}
	}
}

func TestInstallCosignSkippedWhenAbsent(t *testing.T) {
	srv, _ := cosignTestServer(t, true)
	stubCosign(t, false, nil) // cosign not installed

	got, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client())
	if err != nil {
		t.Fatalf("Install should succeed on the SHA-256 floor when cosign is absent: %v", err)
	}
	if got.SignatureVerified {
		t.Error("SignatureVerified = true, want false when cosign is absent")
	}
	if got.ProvenanceNote == "" {
		t.Error("expected a note explaining the skipped signature check")
	}
}

func TestInstallCosignVerifyFails(t *testing.T) {
	srv, _ := cosignTestServer(t, true)
	stubCosign(t, true, os.ErrPermission) // cosign present but verification fails

	dest := t.TempDir()
	if _, err := Install(context.Background(), "faketool", dest, srv.Client()); err == nil {
		t.Fatal("expected a hard error when cosign verification fails")
	}
	if _, err := os.Stat(filepath.Join(dest, "faketool")); !os.IsNotExist(err) {
		t.Error("nothing should be installed when provenance verification fails")
	}
}

func TestInstallCosignChecksumNotListed(t *testing.T) {
	srv, _ := cosignTestServer(t, false) // signature verifies, but the archive isn't listed
	stubCosign(t, true, nil)

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client()); err == nil {
		t.Fatal("expected an error when the archive is not in the signed checksums")
	}
}

func TestInstallCosignChecksumsDownloadError(t *testing.T) {
	srv, _ := cosignTestServer(t, true)
	stubCosign(t, true, nil)
	cs := installable["faketool"].Cosign
	cs.ChecksumsURL = srv.URL + "/missing-checksums" // 404

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client()); err == nil {
		t.Fatal("expected an error when the signed checksums cannot be downloaded")
	}
}

func TestInstallCosignBundleDownloadError(t *testing.T) {
	srv, _ := cosignTestServer(t, true)
	stubCosign(t, true, nil)
	cs := installable["faketool"].Cosign
	cs.BundleURL = srv.URL + "/missing-bundle" // 404

	if _, err := Install(context.Background(), "faketool", t.TempDir(), srv.Client()); err == nil {
		t.Fatal("expected an error when the signature bundle cannot be downloaded")
	}
}

func TestRunCosignVerifyDefaultWrapper(t *testing.T) {
	// Exercise the real (non-stubbed) wrapper: invoking a missing binary must error.
	if err := runCosignVerify(context.Background(), "/nonexistent/cosign-xyz", []string{"version"}); err == nil {
		t.Fatal("expected an error invoking a missing cosign binary")
	}
}

func TestCosignLookPathDefault(_ *testing.T) {
	// Exercise the default resolver; cosign may or may not be present, both are valid.
	_, _ = cosignLookPath()
}

func TestChecksumsContain(t *testing.T) {
	data := []byte("abc123  tool_linux.tar.gz\ndef456  tool_darwin.tar.gz\n")
	if !checksumsContain(data, "tool_linux.tar.gz", "abc123") {
		t.Error("should find the listed file+sha")
	}
	if !checksumsContain(data, "tool_darwin.tar.gz", "DEF456") {
		t.Error("sha comparison should be case-insensitive")
	}
	if checksumsContain(data, "tool_linux.tar.gz", "wrongsha") {
		t.Error("should not match a wrong sha")
	}
	if checksumsContain(data, "absent.tar.gz", "abc123") {
		t.Error("should not match an absent file")
	}
}

// contains is a tiny substring helper (avoids importing strings just for tests).
func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
