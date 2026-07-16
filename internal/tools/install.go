package tools

import (
	"archive/tar"
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
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Provisioning downloads pinned, checksum-verified scanner binaries into a Draugr-managed
// directory. It is deliberately explicit: only `draugr tools install` triggers it, every
// download is verified against a SHA-256 pinned below before it touches disk, and nothing is
// fetched during a scan. Pins come from each upstream's published `*_checksums.txt`.

// semgrepVersion is the pinned Semgrep release. Semgrep ships as a Python package, not a
// standalone binary, so it is provisioned via pipx rather than downloaded here.
const semgrepVersion = "1.169.0"

// Download/extract size caps guard against a malicious or corrupt server (decompression
// bombs, endless bodies). Scanner archives are tens of MB; 512 MiB is comfortably above that.
const (
	maxDownloadBytes = 512 << 20
	maxBinaryBytes   = 512 << 20
)

// Asset is one platform's download for an installable tool.
type Asset struct {
	URL             string
	SHA256          string
	BinaryInArchive string // name of the binary within the .tar.gz
}

// CosignSpec describes how to verify a tool release's provenance with cosign, for upstreams
// that publish a keyless signature over their checksums file. It is optional and additive:
// the SHA-256 pin remains the mandatory integrity floor; cosign proves the checksums file was
// signed by the upstream's expected release identity. Verification uses the cosign CLI (no Go
// sigstore dependency) and the new Sigstore bundle format.
type CosignSpec struct {
	// ChecksumsURL is the upstream's signed checksums file, listing each asset's SHA-256.
	ChecksumsURL string
	// BundleURL is the Sigstore bundle (.sigstore.json) signing ChecksumsURL.
	BundleURL string
	// IdentityRegexp is the required signing certificate identity (--certificate-identity-regexp).
	IdentityRegexp string
	// OIDCIssuer is the required OIDC issuer (--certificate-oidc-issuer).
	OIDCIssuer string
}

// InstallSpec pins an installable tool to a version and its per-platform assets, keyed by
// "GOOS/GOARCH" (e.g. "linux/amd64").
type InstallSpec struct {
	Binary  string
	Version string
	Assets  map[string]Asset
	// Cosign, when set, verifies the release's provenance in addition to the SHA-256 pin.
	// Nil for upstreams that publish no signature (e.g. gitleaks) — those stay SHA-256-only.
	Cosign *CosignSpec
}

// installable is the pinned manifest. SHA-256 values are copied verbatim from the upstream
// checksums files: trivy_0.69.3_checksums.txt and gitleaks_8.30.1_checksums.txt.
var installable = map[string]InstallSpec{
	"trivy": {
		Binary:  "trivy",
		Version: "0.69.3",
		// Trivy signs its checksums file with keyless cosign (new Sigstore bundle format).
		Cosign: &CosignSpec{
			ChecksumsURL:   "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_checksums.txt",
			BundleURL:      "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_checksums.txt.sigstore.json",
			IdentityRegexp: `^https://github\.com/aquasecurity/trivy/\.github/workflows/.*@refs/tags/v.*$`,
			OIDCIssuer:     "https://token.actions.githubusercontent.com",
		},
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz",
				SHA256:          "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75",
				BinaryInArchive: "trivy",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-ARM64.tar.gz",
				SHA256:          "7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd",
				BinaryInArchive: "trivy",
			},
			"darwin/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_macOS-64bit.tar.gz",
				SHA256:          "fec4a9f7569b624dd9d044fca019e5da69e032700edbb1d7318972c448ec2f4e",
				BinaryInArchive: "trivy",
			},
			"darwin/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_macOS-ARM64.tar.gz",
				SHA256:          "a2f2179afd4f8bb265ca3c7aefb56a666bc4a9a411663bc0f22c3549fbc643a5",
				BinaryInArchive: "trivy",
			},
		},
	},
	"gitleaks": {
		Binary:  "gitleaks",
		Version: "8.30.1",
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
				SHA256:          "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
				BinaryInArchive: "gitleaks",
			},
			"linux/arm64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
				SHA256:          "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
				BinaryInArchive: "gitleaks",
			},
			"darwin/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz",
				SHA256:          "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
				BinaryInArchive: "gitleaks",
			},
			"darwin/arm64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
				SHA256:          "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
				BinaryInArchive: "gitleaks",
			},
		},
	},
}

// Installed describes a successfully provisioned tool.
type Installed struct {
	Name    string
	Version string
	Path    string
	// SignatureVerified is true when an upstream cosign signature was verified (in addition
	// to the always-checked SHA-256 pin).
	SignatureVerified bool
	// ProvenanceNote summarizes the signature outcome for reporting (e.g. why it was skipped);
	// empty when the tool has no cosign provenance configured.
	ProvenanceNote string
}

// cosignLookPath finds the cosign CLI; overridable in tests. A missing cosign is not an error
// — provenance verification degrades to the SHA-256 pin with a note.
var cosignLookPath = func() (string, error) { return exec.LookPath("cosign") }

// runCosignVerify runs `cosign <args>`; overridable in tests.
var runCosignVerify = func(ctx context.Context, cosignPath string, args []string) error {
	cmd := exec.CommandContext(ctx, cosignPath, args...) //nolint:gosec // cosignPath from LookPath; args are built from the pinned manifest
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Installable returns the names of the tools `tools install` can provision, sorted.
func Installable() []string {
	names := make([]string, 0, len(installable))
	for name := range installable {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Spec returns the pinned install spec for a tool.
func Spec(name string) (InstallSpec, bool) {
	s, ok := installable[name]
	return s, ok
}

// SemgrepVersion is the pinned Semgrep version.
func SemgrepVersion() string { return semgrepVersion }

// SemgrepPipxCommand returns the recommended pinned install command for Semgrep, which is a
// Python package rather than a standalone binary.
func SemgrepPipxCommand() string { return "pipx install semgrep==" + semgrepVersion }

// BinDir is Draugr's managed tool directory, ~/.draugr/bin.
func BinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".draugr", "bin"), nil
}

func platformKey() string { return runtime.GOOS + "/" + runtime.GOARCH }

// Install downloads the pinned build of name, verifies its SHA-256, extracts the binary, and
// installs it into destDir with an executable bit. client may be nil (a default is used). The
// download is verified before anything is written, and the binary is placed atomically.
func Install(ctx context.Context, name, destDir string, client *http.Client) (Installed, error) {
	spec, ok := installable[name]
	if !ok {
		return Installed{}, fmt.Errorf("unknown tool %q (installable: %v)", name, Installable())
	}
	asset, ok := spec.Assets[platformKey()]
	if !ok {
		return Installed{}, fmt.Errorf("%s: no pinned build for %s", name, platformKey())
	}
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Minute}
	}

	data, err := download(ctx, client, asset.URL)
	if err != nil {
		return Installed{}, fmt.Errorf("download %s: %w", name, err)
	}

	sum := sha256.Sum256(data)
	gotSHA := hex.EncodeToString(sum[:])
	if gotSHA != asset.SHA256 {
		return Installed{}, fmt.Errorf("%s: checksum mismatch for %s: got %s, want %s",
			name, asset.URL, gotSHA, asset.SHA256)
	}

	// Optional provenance layer: verify the upstream's cosign signature over the checksums
	// file (where published), before anything is written. The SHA-256 pin above is the
	// mandatory floor; this adds signed-by-the-expected-identity assurance on top.
	signatureVerified := false
	provenanceNote := ""
	if spec.Cosign != nil {
		signatureVerified, provenanceNote, err = verifyCosignProvenance(ctx, client, spec.Cosign, asset.URL, gotSHA)
		if err != nil {
			return Installed{}, fmt.Errorf("%s: provenance verification failed: %w", name, err)
		}
	}

	bin, err := extractFromTarGz(data, asset.BinaryInArchive)
	if err != nil {
		return Installed{}, fmt.Errorf("extract %s: %w", name, err)
	}

	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return Installed{}, err
	}
	dest := filepath.Join(destDir, spec.Binary)
	if err := writeExecutable(dest, bin); err != nil {
		return Installed{}, err
	}
	return Installed{
		Name:              name,
		Version:           spec.Version,
		Path:              dest,
		SignatureVerified: signatureVerified,
		ProvenanceNote:    provenanceNote,
	}, nil
}

// verifyCosignProvenance verifies an upstream's cosign signature over its checksums file, then
// confirms the downloaded archive's SHA-256 is listed there. Returns (true, note) on success;
// (false, note) with a nil error when cosign is not installed (graceful degrade to the SHA-256
// floor); an error when cosign is present but verification fails (fail closed).
func verifyCosignProvenance(ctx context.Context, client *http.Client, cs *CosignSpec, assetURL, wantSHA string) (bool, string, error) {
	cosignPath, err := cosignLookPath()
	if err != nil {
		return false, "cosign not installed — skipped signature check", nil
	}

	checksums, err := download(ctx, client, cs.ChecksumsURL)
	if err != nil {
		return false, "", fmt.Errorf("download signed checksums: %w", err)
	}
	bundle, err := download(ctx, client, cs.BundleURL)
	if err != nil {
		return false, "", fmt.Errorf("download signature bundle: %w", err)
	}

	dir, err := os.MkdirTemp("", "draugr-cosign-")
	if err != nil {
		return false, "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	checksumsPath := filepath.Join(dir, "checksums.txt")
	bundlePath := filepath.Join(dir, "checksums.sigstore.json")
	if err := os.WriteFile(checksumsPath, checksums, 0o600); err != nil {
		return false, "", err
	}
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return false, "", err
	}

	args := []string{
		"verify-blob",
		"--bundle", bundlePath,
		"--new-bundle-format",
		"--certificate-identity-regexp", cs.IdentityRegexp,
		"--certificate-oidc-issuer", cs.OIDCIssuer,
		checksumsPath,
	}
	if err := runCosignVerify(ctx, cosignPath, args); err != nil {
		return false, "", fmt.Errorf("cosign verify-blob: %w", err)
	}

	// The checksums file is now proven authentic; confirm our archive is one of its entries.
	assetFile := path.Base(assetURL)
	if !checksumsContain(checksums, assetFile, wantSHA) {
		return false, "", fmt.Errorf("%s (sha256:%s) is not listed in the signed checksums", assetFile, wantSHA)
	}
	return true, "cosign signature verified", nil
}

// checksumsContain reports whether a "<sha256>  <filename>" checksums file lists file with sha.
func checksumsContain(checksums []byte, file, sha string) bool {
	sc := bufio.NewScanner(bytes.NewReader(checksums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[1] == file && strings.EqualFold(fields[0], sha) {
			return true
		}
	}
	return false
}

func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // pinned manifest URL
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
	return io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
}

// extractFromTarGz returns the contents of the first regular file whose base name is binary.
func extractFromTarGz(data []byte, binary string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%q not found in archive", binary)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != binary {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, maxBinaryBytes))
	}
}

// writeExecutable atomically places data at dest with an executable bit, via a temp file in
// the same directory followed by rename (so a partial write never leaves a broken binary).
func writeExecutable(dest string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".draugr-tool-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil { //nolint:gosec // scanner binaries must be executable
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dest)
}
