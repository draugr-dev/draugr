package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// InstallSpec pins an installable tool to a version and its per-platform assets, keyed by
// "GOOS/GOARCH" (e.g. "linux/amd64").
type InstallSpec struct {
	Binary  string
	Version string
	Assets  map[string]Asset
}

// installable is the pinned manifest. SHA-256 values are copied verbatim from the upstream
// checksums files: trivy_0.69.3_checksums.txt and gitleaks_8.30.1_checksums.txt.
var installable = map[string]InstallSpec{
	"trivy": {
		Binary:  "trivy",
		Version: "0.69.3",
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
	if got := hex.EncodeToString(sum[:]); got != asset.SHA256 {
		return Installed{}, fmt.Errorf("%s: checksum mismatch for %s: got %s, want %s",
			name, asset.URL, got, asset.SHA256)
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
	return Installed{Name: name, Version: spec.Version, Path: dest}, nil
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
