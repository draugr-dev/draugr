package tools

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

// Provisioning downloads pinned, checksum-verified scanner binaries into a Draugr-managed
// directory. It is deliberately explicit: only `draugr tools install` triggers it, every
// download is verified against a SHA-256 pinned below before it touches disk, and nothing is
// fetched during a scan. Pins come from each upstream's published `*_checksums.txt`.

// semgrepVersion is the pinned Semgrep release.
//
// Semgrep publishes no release binary — its GitHub releases carry no assets at all — so it is
// installed from PyPI into a virtual environment Draugr owns, with every artifact in the resolved
// tree pinned by the digest PyPI publishes. See python.go.
//
// Bumping it means regenerating the pins:
//
//	python3 internal/tools/pythonpins/generate.py semgrep <version>
const semgrepVersion = "1.173.0"

// Download/extract size caps guard against a malicious or corrupt server (decompression
// bombs, endless bodies). Scanner archives are tens of MB; 512 MiB is comfortably above that.
const (
	maxDownloadBytes = 512 << 20
	maxBinaryBytes   = 512 << 20
)

// Asset is one platform's download for an installable tool. When BinaryInArchive is empty the
// downloaded file is the binary itself (a bare release binary, e.g. cosign), not an archive.
type Asset struct {
	URL string
	// URLTemplate renders the download URL for a version other than the pinned one, with
	// {version} substituted (no leading "v"). Empty means Draugr cannot fetch another version of
	// this platform's build, and will say so rather than guessing at a URL shape.
	URLTemplate     string
	SHA256          string
	BinaryInArchive string // name of the binary within the .tar.gz; "" = the download is the binary
	// DataInArchive is a directory prefix inside the archive to extract alongside the binary,
	// e.g. "cfg/" for kube-bench's benchmark definitions.
	//
	// Some tools are not one file. kube-bench without its cfg/ tree exits complaining about a
	// missing "target_mapping" section, which names an internal structure rather than the 276
	// files nobody copied — so installing the binary alone is a half-install that looks whole.
	DataInArchive string
}

// CosignSpec describes how to verify a tool release's provenance with cosign, for upstreams
// that publish a keyless signature over their checksums file. It is optional and additive:
// the SHA-256 pin remains the mandatory integrity floor; cosign proves the checksums file was
// signed by the upstream's expected release identity. Verification uses the cosign CLI (no Go
// sigstore dependency) and the new Sigstore bundle format.
type CosignSpec struct {
	// ChecksumsURL is the upstream's signed checksums file, listing each asset's SHA-256.
	ChecksumsURL string
	// ChecksumsURLTemplate and BundleURLTemplate render those URLs for another version.
	ChecksumsURLTemplate string
	BundleURLTemplate    string
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
	// ChecksumsURLTemplate is an *unsigned* checksums file for an arbitrary version, for an
	// upstream that publishes one but signs nothing. Weaker than Cosign and much better than
	// nothing: it catches a corrupted or truncated download.
	ChecksumsURLTemplate string
	Assets               map[string]Asset
	// Cosign, when set, verifies the release's provenance in addition to the SHA-256 pin.
	// Nil for upstreams that publish no signature (e.g. gitleaks) — those stay SHA-256-only.
	Cosign *CosignSpec
	// DataDir is where Asset.DataInArchive is written, relative to Draugr's own directory.
	// Namespaced by tool so a second tool with data files does not collide with the first.
	DataDir string
}

// installable is the pinned manifest. SHA-256 values are copied verbatim from the upstream
// checksums files: trivy_0.69.3_checksums.txt and gitleaks_8.30.1_checksums.txt.
var installable = map[string]InstallSpec{
	"trivy": {
		Binary:  "trivy",
		Version: "0.69.3",
		// Trivy signs its checksums file with keyless cosign (new Sigstore bundle format).
		Cosign: &CosignSpec{
			ChecksumsURL:         "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_checksums.txt",
			ChecksumsURLTemplate: "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt",
			BundleURL:            "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_checksums.txt.sigstore.json",
			BundleURLTemplate:    "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt.sigstore.json",
			IdentityRegexp:       `^https://github\.com/aquasecurity/trivy/\.github/workflows/.*@refs/tags/v.*$`,
			OIDCIssuer:           "https://token.actions.githubusercontent.com",
		},
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-64bit.tar.gz",
				SHA256:          "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75",
				BinaryInArchive: "trivy",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-ARM64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-ARM64.tar.gz",
				SHA256:          "7e3924a974e912e57b4a99f65ece7931f8079584dae12eb7845024f97087bdfd",
				BinaryInArchive: "trivy",
			},
			"darwin/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_macOS-64bit.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-64bit.tar.gz",
				SHA256:          "fec4a9f7569b624dd9d044fca019e5da69e032700edbb1d7318972c448ec2f4e",
				BinaryInArchive: "trivy",
			},
			"darwin/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_macOS-ARM64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-ARM64.tar.gz",
				SHA256:          "a2f2179afd4f8bb265ca3c7aefb56a666bc4a9a411663bc0f22c3549fbc643a5",
				BinaryInArchive: "trivy",
			},
		},
	},
	"cosign": {
		Binary:  "cosign",
		Version: "3.1.1",
		// cosign ships bare release binaries (no archive), so BinaryInArchive is empty. It is
		// the tool Draugr uses to verify other tools, so it is pinned by SHA-256 (the mandatory
		// floor) — using cosign to verify itself would be circular.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.1/cosign-linux-amd64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-linux-amd64",
				SHA256:      "ae1ecd212663f3693ad9edf8b1a183900c9a52d3155ba6e354237f9a0f6463fc",
			},
			"linux/arm64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.1/cosign-linux-arm64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-linux-arm64",
				SHA256:      "2ec865872e331c32fd12b08dae15332d3f92c0aa029219589684a4903ca85d11",
			},
			"darwin/amd64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.1/cosign-darwin-amd64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-darwin-amd64",
				SHA256:      "14d2678dfbfde18798151e86fbd91ebdadbb7424b18412a42a155dd8a2df4c7a",
			},
			"darwin/arm64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.1/cosign-darwin-arm64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-darwin-arm64",
				SHA256:      "94b42a9e697be95675f6160ab031a9a5f1ec1e646d6f648d7b2f5cd59ececbc5",
			},
		},
	},
	// kube-bench is the alternative infrastructure scanner: the native reader is the default,
	// and this exists for anyone who wants the upstream tool's own answers. Its release carries
	// the binary and a 276-file cfg/ tree of benchmark definitions — installing one without the
	// other produces a tool that cannot run.
	//
	// SHA-256 only: kube-bench publishes a checksums file and no signature over it.
	"kube-bench": {
		Binary:  "kube-bench",
		Version: "0.15.6",
		DataDir: "kube-bench",
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/kube-bench/releases/download/v0.15.6/kube-bench_0.15.6_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/kube-bench/releases/download/v{version}/kube-bench_{version}_linux_amd64.tar.gz",
				SHA256:          "783882d23a13837ffd9d2a3dc713d86bed121802f51c93465f47add4dae9eb23",
				BinaryInArchive: "kube-bench",
				DataInArchive:   "cfg/",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/kube-bench/releases/download/v0.15.6/kube-bench_0.15.6_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/kube-bench/releases/download/v{version}/kube-bench_{version}_linux_arm64.tar.gz",
				SHA256:          "69a3870f5ce3578429de8d5d771b7703a062eec64b8d7e6d014b15350fcb4a35",
				BinaryInArchive: "kube-bench",
				DataInArchive:   "cfg/",
			},
		},
	},

	"gosec": {
		Binary:  "gosec",
		Version: "2.28.0",
		// gosec signs with a key-based (not keyless) cosign bundle, which the identity-based
		// CosignSpec doesn't cover — SHA-256 pin only for now.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.28.0/gosec_2.28.0_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_linux_amd64.tar.gz",
				SHA256:          "d7882e505b1ff345d458bf0e893eec8019bc849f861ad73a212869540dd505ff",
				BinaryInArchive: "gosec",
			},
			"linux/arm64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.28.0/gosec_2.28.0_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_linux_arm64.tar.gz",
				SHA256:          "63259681b6e4b9e7a24d4e187b485e75d3844d28d512b0c97dc831e51d374720",
				BinaryInArchive: "gosec",
			},
			"darwin/amd64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.28.0/gosec_2.28.0_darwin_amd64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_darwin_amd64.tar.gz",
				SHA256:          "ad23af3a6bfef8112a2da386acd61ede1374c8d022c06d8ef130ccf9748311d4",
				BinaryInArchive: "gosec",
			},
			"darwin/arm64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.28.0/gosec_2.28.0_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_darwin_arm64.tar.gz",
				SHA256:          "6c4993a0ab5e3007d66c87cbcb4e3948f8000971f8eeaf3ac269cbc87a603ba4",
				BinaryInArchive: "gosec",
			},
		},
	},
	"gitleaks": {
		Binary:  "gitleaks",
		Version: "8.30.1",
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
				URLTemplate:     "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_x64.tar.gz",
				SHA256:          "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
				BinaryInArchive: "gitleaks",
			},
			"linux/arm64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_arm64.tar.gz",
				SHA256:          "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
				BinaryInArchive: "gitleaks",
			},
			"darwin/amd64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz",
				URLTemplate:     "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_darwin_x64.tar.gz",
				SHA256:          "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
				BinaryInArchive: "gitleaks",
			},
			"darwin/arm64": {
				URL:             "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_darwin_arm64.tar.gz",
				SHA256:          "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
				BinaryInArchive: "gitleaks",
			},
		},
	},
	"syft": {
		Binary:  "syft",
		Version: "1.49.0",
		// SHA-256 only, though Syft does sign. It publishes the older cosign cert+signature
		// pair (checksums.txt.pem / .sig) rather than a Sigstore bundle, and CosignSpec models
		// the bundle format — so install-time verification cannot be expressed here yet.
		//
		// The values below were still checked before being copied: cosign verify-blob against
		// syft_1.49.0_checksums.txt with the anchore/syft identity returned "Verified OK", so
		// these hashes come from a file provably signed by Syft's release workflow.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.49.0/syft_1.49.0_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_linux_amd64.tar.gz",
				SHA256:          "7aa2f03ee92739cf643279ba3990548b9925d4e22cae13f46831ee62821147fe",
				BinaryInArchive: "syft",
			},
			"linux/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.49.0/syft_1.49.0_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_linux_arm64.tar.gz",
				SHA256:          "c7c32de183c32368de197edba75e8dba7632915f7761bacd55149a9ca7fe0fa4",
				BinaryInArchive: "syft",
			},
			"darwin/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.49.0/syft_1.49.0_darwin_amd64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_darwin_amd64.tar.gz",
				SHA256:          "a18ba5c48a4e75d0d87cae7b36b93bdfc04ddd5ea69b87bec9f7cd9431a8cdb9",
				BinaryInArchive: "syft",
			},
			"darwin/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.49.0/syft_1.49.0_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_darwin_arm64.tar.gz",
				SHA256:          "4d137302fb3e049cb1b124b1cbd840a77280dc9f50a45a5a4389250a2228b3cb",
				BinaryInArchive: "syft",
			},
		},
	},
	"nuclei": {
		Binary:  "nuclei",
		Version: "3.11.0",
		// Nuclei ships .zip archives (extracted by extractFromZip) and publishes no cosign
		// signature, so it is pinned by SHA-256 only. Values from nuclei_3.11.0_checksums.txt.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_amd64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_amd64.zip",
				SHA256:          "dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283",
				BinaryInArchive: "nuclei",
			},
			"linux/arm64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_linux_arm64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_arm64.zip",
				SHA256:          "78401fc570ed60a48b8a659f65f6645015a8b3b3097a5e50fc6fbe106a4b108a",
				BinaryInArchive: "nuclei",
			},
			"darwin/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_macOS_amd64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_macOS_amd64.zip",
				SHA256:          "70feaf206250e50f7ef8403f914ef6c500e0f2cab0172bedced3fbd5b0caedad",
				BinaryInArchive: "nuclei",
			},
			"darwin/arm64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.0/nuclei_3.11.0_macOS_arm64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_macOS_arm64.zip",
				SHA256:          "e35f513943f07b78d39bcca83f0a7f2db87fafa67669334e647666df7b397467",
				BinaryInArchive: "nuclei",
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
	// AlreadyPresent is true when the pinned build was already installed and left untouched.
	AlreadyPresent bool
}

// cosignLookPath finds the cosign CLI; overridable in tests. A missing cosign is not an error
// — provenance verification degrades to the SHA-256 pin with a note.
var cosignLookPath = func() (string, error) { return exec.LookPath("cosign") }

// runCosignVerify runs `cosign <args>`; overridable in tests.
var runCosignVerify = func(ctx context.Context, cosignPath string, args []string) error {
	cmd := exec.CommandContext(ctx, cosignPath, args...) // #nosec G204 -- cosignPath from LookPath; args are built from the pinned manifest // nosem: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- verifying with the cosign CLI is the point; path from LookPath, args from the pinned manifest
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Installable returns the names of the tools `tools install` can provision, sorted.
func Installable() []string {
	names := make([]string, 0, len(installable)+len(pythonInstallable))
	for name := range installable {
		names = append(names, name)
	}
	for name := range pythonInstallable {
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

// installPythonTool provisions a tool that ships as a Python package, and reports it the way an
// installed binary is reported.
func installPythonTool(ctx context.Context, name, version, destDir string, spec PythonSpec) (Installed, error) {
	if version == "" {
		version = pythonVersions[name]
	}
	root := filepath.Dir(destDir)
	path, level, err := installPython(ctx, root, name, spec, version)
	if err != nil {
		return Installed{}, err
	}
	// The shim is what ends up on PATH, so it is the file the attestation is about — the same
	// rule the binary path follows.
	sum, err := fileSHA256(path)
	if err != nil {
		return Installed{}, err
	}
	// LevelPinned when the embedded set applied: every artifact in the resolved tree matched a
	// digest recorded in this binary, which is the same claim a pinned release archive makes and
	// covers more — the dependencies as well as the tool.
	recordInstall(destDir, name, installRecord{
		Version: version, BinarySHA256: sum, Verified: level,
	})
	return Installed{Name: name, Version: version, Path: path}, nil
}

// pythonVersions pins each Python-packaged tool.
var pythonVersions = map[string]string{"semgrep": semgrepVersion}

// PythonVersion is the pinned version of a tool obtained as a Python package.
func PythonVersion(name string) string { return pythonVersions[name] }

// BinDir is Draugr's managed tool directory, ~/.draugr/bin.
func BinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".draugr", "bin"), nil
}

// DataRoot is where tools that need more than a binary keep it, one directory per tool.
//
// Beside bin/ rather than inside it: a directory of YAML on PATH is confusing, and a tool's data
// has a different lifetime from its binary — reinstalling one should not silently orphan the
// other somewhere a reader has to guess at.
func DataRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".draugr", "data"), nil
}

// DataDirFor returns where a tool's supporting files live, or "" when it has none.
func DataDirFor(name string) string {
	spec, ok := installable[name]
	if !ok || spec.DataDir == "" {
		return ""
	}
	root, err := DataRoot()
	if err != nil {
		return ""
	}
	return filepath.Join(root, spec.DataDir)
}

func platformKey() string { return runtime.GOOS + "/" + runtime.GOARCH }

// PlatformKey is the key into InstallSpec.Assets for the machine Draugr is running on.
func PlatformKey() string { return platformKey() }

// Install downloads the pinned build of name, verifies its SHA-256, extracts the binary, and
// installs it into destDir with an executable bit. client may be nil (a default is used). The
// download is verified before anything is written, and the binary is placed atomically.
// Install provisions a pinned tool into destDir. A tool already present at exactly the pinned
// build is left alone unless force is set — see the install manifest below.
func Install(ctx context.Context, name, destDir string, client *http.Client, force bool) (Installed, error) {
	return InstallVersion(ctx, name, "", destDir, client, force)
}

// InstallVersion installs a specific version, or the pinned one when version is empty.
//
// would hide the order, and the order is the security property.
//
//nolint:gocyclo // one linear sequence: resolve, download, verify, extract, record. Splitting it
func InstallVersion(ctx context.Context, name, version, destDir string, client *http.Client, force bool) (Installed, error) {
	// A tool that ships as a Python package is obtained differently and verified the same way.
	// Handled first so the release-archive path below stays one linear sequence.
	if pySpec, ok := PythonTool(name); ok {
		return installPythonTool(ctx, name, version, destDir, pySpec)
	}
	spec, err := SpecFor(name, version)
	if err != nil {
		return Installed{}, err
	}
	asset, ok := spec.Assets[platformKey()]
	if !ok {
		return Installed{}, fmt.Errorf("%s: no pinned build for %s", name, platformKey())
	}
	if !force {
		if dest, ok := alreadyInstalled(destDir, name, spec, asset); ok {
			return Installed{
				Name:           name,
				Version:        spec.Version,
				Path:           dest,
				AlreadyPresent: true,
			}, nil
		}
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

	// A recorded SHA is the strongest thing available and needs no network. It exists only for
	// the version Draugr ships.
	level := LevelPinned
	if asset.SHA256 != "" {
		if gotSHA != asset.SHA256 {
			return Installed{}, fmt.Errorf("%s: checksum mismatch for %s: got %s, want %s",
				name, asset.URL, gotSHA, asset.SHA256)
		}
	} else {
		level, err = verifyByPublishedChecksums(ctx, client, spec, asset, gotSHA)
		if err != nil {
			return Installed{}, err
		}
	}

	// Optional provenance layer: verify the upstream's cosign signature over the checksums
	// file (where published), before anything is written. The SHA-256 pin above is the
	// mandatory floor; this adds signed-by-the-expected-identity assurance on top.
	signatureVerified := false
	provenanceNote := ""
	if spec.Cosign != nil && level == LevelPinned {
		signatureVerified, provenanceNote, err = verifyCosignProvenance(ctx, client, spec.Cosign, asset.URL, gotSHA)
		if err != nil {
			return Installed{}, fmt.Errorf("%s: provenance verification failed: %w", name, err)
		}
	}

	// A bare binary (BinaryInArchive == "") is the downloaded file itself; otherwise extract it
	// from the archive (.tar.gz or .zip, detected by content).
	bin := data
	if asset.BinaryInArchive != "" {
		bin, err = extractBinary(data, asset.BinaryInArchive)
		if err != nil {
			return Installed{}, fmt.Errorf("extract %s: %w", name, err)
		}
	}

	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return Installed{}, err
	}
	dest := filepath.Join(destDir, spec.Binary)
	if err := writeExecutable(dest, bin); err != nil {
		return Installed{}, err
	}
	// The data tree, if this tool is more than a binary. After the binary so a failure here
	// leaves an installed tool that doctor will report as missing its data — which is true, and
	// better than a rolled-back install that reports nothing at all.
	if asset.DataInArchive != "" && spec.DataDir != "" {
		root, err := DataRoot()
		if err != nil {
			return Installed{}, err
		}
		dataDir := filepath.Join(root, spec.DataDir)
		n, err := extractTree(data, asset.DataInArchive, dataDir)
		if err != nil {
			return Installed{}, fmt.Errorf("extract %s data: %w", name, err)
		}
		slog.Debug("installed tool data", "tool", name, "files", n, "dir", dataDir)
	}

	binSum := sha256.Sum256(bin)
	if signatureVerified && level == LevelPinned {
		level = LevelSigned
	}
	recordInstall(destDir, name, installRecord{
		Version:      spec.Version,
		AssetSHA256:  gotSHA,
		BinarySHA256: hex.EncodeToString(binSum[:]),
		Verified:     level,
	})
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

// zipMagic is the local-file-header signature at the start of every .zip archive ("PK\x03\x04").
var zipMagic = []byte("PK\x03\x04")

// extractBinary pulls the named binary from a downloaded archive, dispatching on the archive's
// magic bytes: .zip archives (Nuclei) start with zipMagic; everything else is treated as .tar.gz
// (Trivy, gitleaks, gosec). Content-based detection avoids depending on the asset's URL suffix,
// which lets tests use bare httptest URLs.
func extractBinary(data []byte, binary string) ([]byte, error) {
	if bytes.HasPrefix(data, zipMagic) {
		return extractFromZip(data, binary)
	}
	return extractFromTarGz(data, binary)
}

// extractFromZip returns the contents of the first file whose base name is binary.
func extractFromZip(data []byte, binary string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binary {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(io.LimitReader(rc, maxBinaryBytes))
	}
	return nil, fmt.Errorf("%q not found in archive", binary)
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

// --- install manifest -------------------------------------------------------------------
//
// Re-provisioning is common: CI runs `tools install` on every job. Downloading and verifying a
// tool that is already present at the pinned version is pure waste (a 162 MB re-download for
// trivy), so we record what we installed and skip when it's still intact.
//
// The record holds the *binary's* checksum, not just a version string. The pinned SHA-256
// covers the upstream archive, so it can't be compared against an extracted binary — but we can
// compare against what we ourselves wrote. That way "already installed" can never quietly accept
// a binary that has been modified since: a mismatch reinstalls.

// manifestName is the record of provisioned tools, kept alongside the binaries.
const manifestName = ".draugr-tools.json"

// installRecord is what we know about a tool we installed into this directory.
type installRecord struct {
	Version      string `json:"version"`
	AssetSHA256  string `json:"assetSha256"`
	BinarySHA256 string `json:"binarySha256"`
	// Verified is how the download was checked. Recorded because install time is the only moment
	// the evidence exists: the checksums file and the signature are not kept, so a later reader
	// asking "how well do we know this binary" has nothing else to go on.
	Verified Level `json:"verified,omitempty"`
}

func manifestPath(destDir string) string { return filepath.Join(destDir, manifestName) }

func loadManifest(destDir string) map[string]installRecord {
	out := map[string]installRecord{}
	data, err := os.ReadFile(manifestPath(destDir)) //nolint:gosec // path is ours, under destDir
	if err != nil {
		return out
	}
	_ = json.Unmarshal(data, &out) // a corrupt manifest just means we reinstall
	return out
}

func recordInstall(destDir, name string, rec installRecord) {
	m := loadManifest(destDir)
	m[name] = rec
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	// Best-effort: failing to record costs a redundant download next time, nothing worse.
	_ = os.WriteFile(manifestPath(destDir), data, 0o600)
}

// fileSHA256 hashes a file on disk, streaming so a large binary doesn't land in memory.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is ours, under destDir
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// alreadyInstalled reports whether the tool is present at exactly the pinned build, unmodified.
func alreadyInstalled(destDir, name string, spec InstallSpec, asset Asset) (string, bool) {
	rec, ok := loadManifest(destDir)[name]
	if !ok || rec.Version != spec.Version || rec.AssetSHA256 != asset.SHA256 {
		return "", false
	}
	dest := filepath.Join(destDir, spec.Binary)
	got, err := fileSHA256(dest)
	if err != nil || got != rec.BinarySHA256 {
		return "", false
	}
	return dest, true
}

// extractTree writes every file under prefix in a .tar.gz to dest, preserving the layout below
// prefix, and returns how many it wrote.
//
// The directory is cleared first: a stale file from an older release left beside new ones is a
// benchmark definition nobody chose, and kube-bench would happily read it.
func extractTree(data []byte, prefix, dest string) (int, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer func() { _ = gz.Close() }()

	if err := os.RemoveAll(dest); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return 0, err
	}

	written := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, err
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasPrefix(hdr.Name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(hdr.Name, prefix)
		// Refuse rather than sanitise. Joining a cleaned path would neutralise `..` and write
		// the file somewhere harmless, which is safe and quiet — and quiet is wrong here. An
		// archive is untrusted input even when its checksum matched: the pin proves it is the
		// file upstream published, not that the file is well-behaved, and a traversal attempt in
		// a signed release is something someone needs to hear about rather than have tidied away.
		if rel == "" || filepath.IsAbs(rel) || slices.Contains(strings.Split(rel, "/"), "..") {
			return written, fmt.Errorf("archive entry %q is not a safe relative path", hdr.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return written, err
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxBinaryBytes))
		if err != nil {
			return written, err
		}
		if err := os.WriteFile(target, body, 0o600); err != nil {
			return written, err
		}
		written++
	}
	if written == 0 {
		return 0, fmt.Errorf("no files under %q in the archive", prefix)
	}
	return written, nil
}

// verifyByPublishedChecksums checks a download Draugr has no recorded hash for, and reports how
// strongly it managed to.
//
// It never refuses for want of evidence — a version somebody asked for is installed even when
// nothing is published to check it against, because refusing would block an operator who knows
// something Draugr does not. It does refuse a **mismatch**: a published checksum that disagrees
// is not missing information, it is information saying the download is wrong, and installing past
// it would be ignoring evidence rather than lacking it.
func verifyByPublishedChecksums(ctx context.Context, client *http.Client, spec InstallSpec, asset Asset, gotSHA string) (Level, error) {
	file := assetFileName(asset.URL)

	if spec.Cosign != nil {
		ok, _, err := verifyCosignProvenance(ctx, client, spec.Cosign, asset.URL, gotSHA)
		switch {
		case err != nil:
			// The signature or the checksums say something is wrong. That is evidence, not a gap.
			return "", fmt.Errorf("%s %s: %w", spec.Binary, spec.Version, err)
		case ok:
			return LevelSigned, nil
		}
		// cosign is not installed, so the signature could not be checked. Fall through to the
		// checksums file on its own rather than treating an absent verifier as a failure.
	}

	url := spec.ChecksumsURLTemplate
	if url == "" && spec.Cosign != nil {
		url = spec.Cosign.ChecksumsURL
	}
	if url == "" {
		return LevelUnverified, nil
	}
	checksums, err := download(ctx, client, url)
	if err != nil {
		// Could not fetch them. Unknown, not wrong.
		return LevelUnverified, nil
	}
	if !checksumsContain(checksums, file, gotSHA) {
		return "", fmt.Errorf("%s %s: %s is not listed with checksum %s in %s — the download does "+
			"not match what the upstream published", spec.Binary, spec.Version, file, gotSHA, url)
	}
	return LevelChecksum, nil
}

// assetFileName is the last path segment of a download URL, which is how a checksums file names
// its entries.
func assetFileName(url string) string {
	if i := strings.LastIndex(url, "/"); i >= 0 {
		return url[i+1:]
	}
	return url
}
