// Package selfupdate updates the running draugr binary to a released version. Downloads are
// verified against the release's SHA-256 checksums (mandatory) and its keyless cosign
// signature (best-effort, when the cosign CLI is present) before the binary is replaced.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/version"
)

const (
	repo        = "draugr-dev/draugr"
	maxDownload = 512 << 20 // guard against a malicious/corrupt server
)

// Injectable seams for tests.
var (
	githubBase = "https://github.com/" + repo
	resolveExe = os.Executable

	cosignLookPath = func() (string, error) { return exec.LookPath("cosign") }
	runCosign      = func(ctx context.Context, cosignPath string, args []string) error {
		out, err := exec.CommandContext(ctx, cosignPath, args...).CombinedOutput() //nolint:gosec // cosignPath from LookPath; args built here
		if err != nil {
			return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
		}
		return nil
	}

	// identityRegexp/oidcIssuer are draugr's own keyless release-signing identity.
	identityRegexp = `^https://github\.com/draugr-dev/draugr/\.github/workflows/release\.yml@refs/tags/v.*$`
	oidcIssuer     = "https://token.actions.githubusercontent.com"
)

// CurrentVersion is the running binary's version (build stamp), without a leading "v".
func CurrentVersion() string { return strings.TrimPrefix(version.Version, "v") }

// LatestVersion resolves the latest published release version (no leading "v") via the
// github.com releases/latest redirect — deliberately not the api.github.com REST endpoint,
// which is rate-limited and has been flaky. Use a short timeout for interactive/offline paths.
func LatestVersion(ctx context.Context, client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubBase+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	final := resp.Request.URL.String() // the URL after redirects: .../releases/tag/vX.Y.Z
	i := strings.LastIndex(final, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("could not resolve the latest release from %q", final)
	}
	return strings.TrimPrefix(final[i+len("/tag/"):], "v"), nil
}

// Result describes a self-update outcome.
type Result struct {
	Previous          string // version before (may be "dev")
	Target            string // version updated (or would update) to
	NoChange          bool   // already on the target version
	SignatureVerified bool   // cosign signature verified (vs SHA-256-only)
	Note              string // provenance note (e.g. why cosign was skipped)
	Path              string // the binary that was replaced
}

// Options configure an update.
type Options struct {
	Version string       // "" = latest
	Client  *http.Client // nil = default
}

// Update replaces the running binary with the target release (latest if unset), after
// verifying its checksum and (best-effort) cosign signature. It is a no-op when already on
// the target version.
func Update(ctx context.Context, opts Options) (Result, error) {
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Minute}
	}

	target := strings.TrimPrefix(opts.Version, "v")
	if target == "" {
		v, err := LatestVersion(ctx, &http.Client{Timeout: 15 * time.Second})
		if err != nil {
			return Result{}, fmt.Errorf("resolve latest version: %w", err)
		}
		target = v
	}

	res := Result{Previous: CurrentVersion(), Target: target}
	if res.Previous == target {
		res.NoChange = true
		return res, nil
	}

	goos, goarch := runtime.GOOS, runtime.GOARCH
	ext, binName := "tar.gz", "draugr"
	if goos == "windows" {
		ext, binName = "zip", "draugr.exe"
	}
	asset := fmt.Sprintf("draugr_%s_%s_%s.%s", target, goos, goarch, ext)
	base := githubBase + "/releases/download/v" + target

	archive, err := get(ctx, client, base+"/"+asset)
	if err != nil {
		return res, fmt.Errorf("download %s: %w", asset, err)
	}
	checksums, err := get(ctx, client, base+"/checksums.txt")
	if err != nil {
		return res, fmt.Errorf("download checksums: %w", err)
	}

	sum := sha256.Sum256(archive)
	if !checksumListed(checksums, asset, hex.EncodeToString(sum[:])) {
		return res, fmt.Errorf("%s failed SHA-256 checksum verification", asset)
	}

	res.SignatureVerified, res.Note, err = verifySignature(ctx, client, base, checksums)
	if err != nil {
		return res, fmt.Errorf("signature verification failed: %w", err)
	}

	bin, err := extract(archive, ext, binName)
	if err != nil {
		return res, fmt.Errorf("extract %s: %w", binName, err)
	}

	exe, err := resolveExe()
	if err != nil {
		return res, err
	}
	if resolved, e := filepath.EvalSymlinks(exe); e == nil {
		exe = resolved
	}
	if err := replaceBinary(exe, bin); err != nil {
		return res, fmt.Errorf("replace binary: %w", err)
	}
	res.Path = exe
	return res, nil
}

// verifySignature verifies the (already checksum-matched) checksums file was signed by
// draugr's release workflow. cosign absent → skip with a note (SHA-256 remains the floor);
// present but failing → error (fail closed).
func verifySignature(ctx context.Context, client *http.Client, base string, checksums []byte) (bool, string, error) {
	cosignPath, err := cosignLookPath()
	if err != nil {
		return false, "cosign not installed — verified by SHA-256 only", nil
	}
	bundle, err := get(ctx, client, base+"/checksums.txt.sigstore.json")
	if err != nil {
		return false, "", fmt.Errorf("download signature bundle: %w", err)
	}
	dir, err := os.MkdirTemp("", "draugr-selfupdate-")
	if err != nil {
		return false, "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	cks := filepath.Join(dir, "checksums.txt")
	bun := filepath.Join(dir, "checksums.sigstore.json")
	if err := os.WriteFile(cks, checksums, 0o600); err != nil {
		return false, "", err
	}
	if err := os.WriteFile(bun, bundle, 0o600); err != nil {
		return false, "", err
	}
	args := []string{
		"verify-blob", "--bundle", bun,
		"--certificate-identity-regexp", identityRegexp,
		"--certificate-oidc-issuer", oidcIssuer,
		cks,
	}
	if err := runCosign(ctx, cosignPath, args); err != nil {
		return false, "", fmt.Errorf("cosign verify-blob: %w", err)
	}
	return true, "cosign signature verified", nil
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // release URL derived from the pinned repo + version
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// checksumListed reports whether a "<sha>  <file>" checksums file lists file with sha.
func checksumListed(checksums []byte, file, sha string) bool {
	sc := bufio.NewScanner(bytes.NewReader(checksums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == file && strings.EqualFold(f[0], sha) {
			return true
		}
	}
	return false
}

func extract(archive []byte, ext, name string) ([]byte, error) {
	if ext == "zip" {
		return extractZip(archive, name)
	}
	return extractTarGz(archive, name)
}

func extractTarGz(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%q not found in archive", name)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == name {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}

func extractZip(data []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(io.LimitReader(rc, maxDownload))
	}
	return nil, fmt.Errorf("%q not found in archive", name)
}

// replaceBinary atomically replaces exe with data (executable). On Windows a running binary
// can't be renamed over, so the current one is moved aside first.
func replaceBinary(exe string, data []byte) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".draugr-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil { //nolint:gosec // an executable must be executable
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Rename(exe, exe+".old") // a running .exe can be renamed, not overwritten
	}
	return os.Rename(tmpName, exe)
}
