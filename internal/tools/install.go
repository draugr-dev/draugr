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
// Semgrep publishes no release binary, its GitHub releases carry no assets at all. So it is
// installed from PyPI into a virtual environment Draugr owns, with every artifact in the resolved
// tree pinned by the digest PyPI publishes. See python.go.
//
// Bumping it means regenerating the pins:
//
//	python3 internal/tools/pythonpins/generate.py semgrep <version>
const semgrepVersion = "1.177.0"

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
	// missing "target_mapping" section, which names an internal structure rather than the 276 files
	// nobody copied, so installing the binary alone is a half-install that looks whole.
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
	// Cosign, when set, verifies the release's provenance in addition to the SHA-256 pin. Nil for
	// upstreams that publish no signature (e.g. gitleaks). Those stay SHA-256-only.
	Cosign *CosignSpec
	// DataDir is where Asset.DataInArchive is written, relative to Draugr's own directory.
	// Namespaced by tool so a second tool with data files does not collide with the first.
	DataDir string
}

// installable is the pinned manifest.
//
// Every SHA-256 here is the hash of the bytes at the URL beside it, taken by downloading them.
// Where the upstream also publishes a checksums file it is read and compared, because a checksums
// file is a claim and the bytes are the fact. `scripts/update-tool-pins.py` does both and refuses
// to write a manifest where they disagree, which is also what keeps a version bump from being a
// hand-copied column of hex.
var installable = map[string]InstallSpec{
	"trivy": {
		Binary:  "trivy",
		Version: "0.74.0",
		// Trivy signs its checksums file with keyless cosign (new Sigstore bundle format).
		Cosign: &CosignSpec{
			ChecksumsURL:         "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt",
			ChecksumsURLTemplate: "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt",
			BundleURL:            "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt.sigstore.json",
			BundleURLTemplate:    "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt.sigstore.json",
			IdentityRegexp:       `^https://github\.com/aquasecurity/trivy/\.github/workflows/.*@refs/tags/v.*$`,
			OIDCIssuer:           "https://token.actions.githubusercontent.com",
		},
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-64bit.tar.gz",
				SHA256:          "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
				BinaryInArchive: "trivy",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-ARM64.tar.gz",
				SHA256:          "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
				BinaryInArchive: "trivy",
			},
			"darwin/amd64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_macOS-64bit.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-64bit.tar.gz",
				SHA256:          "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485",
				BinaryInArchive: "trivy",
			},
			"darwin/arm64": {
				URL:             "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_macOS-ARM64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_macOS-ARM64.tar.gz",
				SHA256:          "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11",
				BinaryInArchive: "trivy",
			},
		},
	},
	"cosign": {
		Binary:  "cosign",
		Version: "3.1.3",
		// cosign ships bare release binaries (no archive), so BinaryInArchive is empty. It is the tool
		// Draugr uses to verify other tools, so it is pinned by SHA-256 (the mandatory floor), using
		// cosign to verify itself would be circular.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-linux-amd64",
				SHA256:      "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
			},
			"linux/arm64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-arm64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-linux-arm64",
				SHA256:      "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
			},
			"darwin/amd64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-darwin-amd64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-darwin-amd64",
				SHA256:      "2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c",
			},
			"darwin/arm64": {
				URL:         "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-darwin-arm64",
				URLTemplate: "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-darwin-arm64",
				SHA256:      "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76",
			},
		},
	},
	// notation verifies Notary Project signatures, which is the X.509 half of the provenance
	// control: a certificate chaining to a trust store the descriptor names, rather than a
	// short-lived Sigstore identity. Azure Pipelines signs this way, and so does anybody with
	// their own PKI.
	//
	// SHA-256 only. notation publishes a checksums file and cosign signatures over its release
	// assets, and the floor is what every tool here is held to.
	"notation": {
		Binary:  "notation",
		Version: "1.3.2",
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/notaryproject/notation/releases/download/v1.3.2/notation_1.3.2_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/notaryproject/notation/releases/download/v{version}/notation_{version}_linux_amd64.tar.gz",
				SHA256:          "e1a0f060308086bf8020b2d31defb7c5348f133ca0dba6a1a7820ef3cbb6dfe5",
				BinaryInArchive: "notation",
			},
			"linux/arm64": {
				URL:             "https://github.com/notaryproject/notation/releases/download/v1.3.2/notation_1.3.2_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/notaryproject/notation/releases/download/v{version}/notation_{version}_linux_arm64.tar.gz",
				SHA256:          "34143c7b816a50104824278080a5cf12bbf855488e003f62e6acf27ed25c423c",
				BinaryInArchive: "notation",
			},
			"darwin/amd64": {
				URL:             "https://github.com/notaryproject/notation/releases/download/v1.3.2/notation_1.3.2_darwin_amd64.tar.gz",
				URLTemplate:     "https://github.com/notaryproject/notation/releases/download/v{version}/notation_{version}_darwin_amd64.tar.gz",
				SHA256:          "72fade2ccb0765e2ff26b53c9ca663dd33dc4f2020b2b8493e703a9ccf6174a2",
				BinaryInArchive: "notation",
			},
			"darwin/arm64": {
				URL:             "https://github.com/notaryproject/notation/releases/download/v1.3.2/notation_1.3.2_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/notaryproject/notation/releases/download/v{version}/notation_{version}_darwin_arm64.tar.gz",
				SHA256:          "054bf6e9fb2619390dab9c74e5d6c511bde7609f3a060ee512c6aead2440c214",
				BinaryInArchive: "notation",
			},
		},
	},
	// kube-bench is the alternative infrastructure scanner: the native reader is the default, and
	// this exists for anyone who wants the upstream tool's own answers. Its release carries the
	// binary and a 276-file cfg/ tree of benchmark definitions, installing one without the other
	// produces a tool that cannot run.
	//
	// SHA-256 only: kube-bench publishes a checksums file and no signature over it.
	"kube-bench": {
		Binary:  "kube-bench",
		Version: "0.16.0",
		DataDir: "kube-bench",
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/aquasecurity/kube-bench/releases/download/v0.16.0/kube-bench_0.16.0_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/kube-bench/releases/download/v{version}/kube-bench_{version}_linux_amd64.tar.gz",
				SHA256:          "82dbc7e598740dc9344d41f8ad0b8210d57c4c00bdb2c5f1d8a69a2b98baddcf",
				BinaryInArchive: "kube-bench",
				DataInArchive:   "cfg/",
			},
			"linux/arm64": {
				URL:             "https://github.com/aquasecurity/kube-bench/releases/download/v0.16.0/kube-bench_0.16.0_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/aquasecurity/kube-bench/releases/download/v{version}/kube-bench_{version}_linux_arm64.tar.gz",
				SHA256:          "64500561f5fcaa3f86fe951ed26bbfc28f7bbf3d2eac13843abfd2924955d10b",
				BinaryInArchive: "kube-bench",
				DataInArchive:   "cfg/",
			},
		},
	},

	"gosec": {
		Binary:  "gosec",
		Version: "2.29.0",
		// gosec signs with a key-based (not keyless) cosign bundle, which the identity-based
		// CosignSpec doesn't cover, SHA-256 pin only for now.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.29.0/gosec_2.29.0_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_linux_amd64.tar.gz",
				SHA256:          "6431b119741c1f4a50fdfcf94e782e16b9e642afc8c7fa9b5d39d48bf3003095",
				BinaryInArchive: "gosec",
			},
			"linux/arm64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.29.0/gosec_2.29.0_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_linux_arm64.tar.gz",
				SHA256:          "c71244ec8d37488fd479d0d26990968fee03ece48b305d8224ac0c1ebd66e87c",
				BinaryInArchive: "gosec",
			},
			"darwin/amd64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.29.0/gosec_2.29.0_darwin_amd64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_darwin_amd64.tar.gz",
				SHA256:          "a48152c3c009988f1750b6508316339c8b55076d24b1a958789e30ea2a21794c",
				BinaryInArchive: "gosec",
			},
			"darwin/arm64": {
				URL:             "https://github.com/securego/gosec/releases/download/v2.29.0/gosec_2.29.0_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_darwin_arm64.tar.gz",
				SHA256:          "7ab6a92c1983b7cb9df12b3ac20fb270afa43cfa12a143c354edae3109c763e5",
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
		Version: "1.51.1",
		// SHA-256 only, though Syft does sign. It publishes the older cosign cert+signature pair
		// (checksums.txt.pem / .sig) rather than a Sigstore bundle, and CosignSpec models the bundle
		// format, so install-time verification cannot be expressed here yet.
		//
		// The values below were still checked before being copied: cosign verify-blob against
		// syft_1.49.0_checksums.txt with the anchore/syft identity returned "Verified OK", so
		// these hashes come from a file provably signed by Syft's release workflow.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_linux_amd64.tar.gz",
				SHA256:          "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3",
				BinaryInArchive: "syft",
			},
			"linux/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_linux_arm64.tar.gz",
				SHA256:          "a7fd2b784e6664acd44719270574f6cd8c6864fc2b1700bf9099bd1cccda7d7f",
				BinaryInArchive: "syft",
			},
			"darwin/amd64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_darwin_amd64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_darwin_amd64.tar.gz",
				SHA256:          "0e186ce1d4351ec276126851ca3ff258ed070e93e73574ed64858d4fc2339867",
				BinaryInArchive: "syft",
			},
			"darwin/arm64": {
				URL:             "https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_darwin_arm64.tar.gz",
				SHA256:          "ac063af3b9874769deb7ea1e6d76841e68f9e3bb50cd654226fc977de65532c1",
				BinaryInArchive: "syft",
			},
		},
	},
	"grype": {
		Binary:  "grype",
		Version: "0.118.0",
		// SHA-256 only, for the same reason as Syft above: Anchore publishes the older cosign
		// cert+signature pair (checksums.txt.pem / .sig) rather than a Sigstore bundle, and
		// CosignSpec models the bundle format.
		//
		// The values below were checked before being copied. `cosign verify-blob` against
		// grype_0.117.0_checksums.txt, with the anchore/grype workflow identity and the GitHub Actions
		// OIDC issuer, returned "Verified OK". So these hashes come from a file provably signed by
		// Grype's release workflow.
		//
		// The floor is not arbitrary: the v5 database schema reached end of life on 2026-03-06,
		// and a client older than v0.88.0 goes on scanning happily against a database that stopped
		// being updated. Do not lower it.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_amd64.tar.gz",
				URLTemplate:     "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_linux_amd64.tar.gz",
				SHA256:          "1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2",
				BinaryInArchive: "grype",
			},
			"linux/arm64": {
				URL:             "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_arm64.tar.gz",
				URLTemplate:     "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_linux_arm64.tar.gz",
				SHA256:          "32aceeb8ee837244775fcb522372c8b3a47914986385f3148f4ee2c930482a84",
				BinaryInArchive: "grype",
			},
			"darwin/amd64": {
				URL:             "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_darwin_amd64.tar.gz",
				URLTemplate:     "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_darwin_amd64.tar.gz",
				SHA256:          "cfeecf3462321c37ec4bd37dcd8a7f6630cc6c0c9997a07ff34002c5d7ef9bb3",
				BinaryInArchive: "grype",
			},
			"darwin/arm64": {
				URL:             "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_darwin_arm64.tar.gz",
				URLTemplate:     "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_darwin_arm64.tar.gz",
				SHA256:          "938f050bb5076c8aa761867b39843abad2414dfe4cc82b7d36886e634f49c640",
				BinaryInArchive: "grype",
			},
		},
	},
	"nuclei": {
		Binary:  "nuclei",
		Version: "3.11.1",
		// Nuclei ships .zip archives (extracted by extractFromZip) and publishes no cosign
		// signature, so it is pinned by SHA-256 only.
		Assets: map[string]Asset{
			"linux/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_amd64.zip",
				SHA256:          "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
				BinaryInArchive: "nuclei",
			},
			"linux/arm64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_arm64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_linux_arm64.zip",
				SHA256:          "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
				BinaryInArchive: "nuclei",
			},
			"darwin/amd64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_macOS_amd64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_macOS_amd64.zip",
				SHA256:          "75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a",
				BinaryInArchive: "nuclei",
			},
			"darwin/arm64": {
				URL:             "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_macOS_arm64.zip",
				URLTemplate:     "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_macOS_arm64.zip",
				SHA256:          "7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0",
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

// cosignLookPath finds the cosign CLI; overridable in tests. A missing cosign is not an error,
// provenance verification degrades to the SHA-256 pin with a note.
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
	names := make([]string, 0, len(installable)+len(pythonInstallable)+len(nodeInstallable)+len(goInstallable))
	for name := range installable {
		names = append(names, name)
	}
	// The language-package methods too. A tool missing from here is one `tools install` provisions
	// and every caller believes it cannot, doctor stops offering it, and `tools list` reports it as
	// something the reader has to find themselves.
	for name := range pythonInstallable {
		names = append(names, name)
	}
	for name := range nodeInstallable {
		names = append(names, name)
	}
	for name := range goInstallable {
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
	// The shim is what ends up on PATH, so it is the file the attestation is about, the same rule
	// the binary path follows.
	sum, err := fileSHA256(path)
	if err != nil {
		return Installed{}, err
	}
	// LevelPinned when the embedded set applied: every artifact in the resolved tree matched a
	// digest recorded in this binary, which is the same claim a pinned release archive makes and
	// covers more, the dependencies as well as the tool.
	recordInstall(destDir, name, installRecord{
		Version: version, BinarySHA256: sum, Verified: level,
	})
	return Installed{Name: name, Version: version, Path: path}, nil
}

// installNodeTool provisions a tool that ships as an npm package, and reports it the way an
// installed binary is reported.
func installNodeTool(ctx context.Context, name, version, destDir string, spec NodeSpec) (Installed, error) {
	if version == "" {
		version = nodeVersions[name]
	}
	root := filepath.Dir(destDir)
	path, level, err := installNode(ctx, root, name, spec, version)
	if err != nil {
		return Installed{}, err
	}
	// The shim is what ends up on PATH, so it is the file the attestation is about, the same rule
	// the binary and Python paths follow.
	sum, err := fileSHA256(path)
	if err != nil {
		return Installed{}, err
	}
	recordInstall(destDir, name, installRecord{
		Version: version, BinarySHA256: sum, Verified: level,
	})
	return Installed{Name: name, Version: version, Path: path}, nil
}

// installGoTool provisions a tool built with the Go toolchain, and reports it the way an
// installed binary is reported.
func installGoTool(ctx context.Context, name, version, destDir string, spec GoSpec) (Installed, error) {
	if version == "" {
		version = goVersions[name]
	}
	root := filepath.Dir(destDir)
	path, level, err := installGo(ctx, root, name, spec, version)
	if err != nil {
		return Installed{}, err
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return Installed{}, err
	}
	// LevelPinned when the checksum database verified the module and everything it builds with,
	// which is the same claim a pinned release archive makes and covers more.
	recordInstall(destDir, name, installRecord{
		Version: version, BinarySHA256: sum, Verified: level,
	})
	return Installed{Name: name, Version: version, Path: path}, nil
}

// pythonVersions pins each Python-packaged tool.
var pythonVersions = map[string]string{"semgrep": semgrepVersion}

// ManagedVersion is the pinned version of a tool provisioned through one of the language-package
// paths, or "" for anything obtained as a release archive or not managed at all.
//
// One place to ask, because the callers that need it, the install plan, `tools list`, the
// up-to-date check, each named the paths individually, and a path added later joined none of
// them.
func ManagedVersion(name string) string {
	for _, v := range []string{pythonVersions[name], nodeVersions[name], goVersions[name]} {
		if v != "" {
			return v
		}
	}
	return ""
}

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
// has a different lifetime from its binary. Reinstalling one should not silently orphan the other
// somewhere a reader has to guess at.
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
// download is verified before anything is written, and the binary is placed atomically. Install
// provisions a pinned tool into destDir. A tool already present at exactly the pinned build is
// left alone unless force is set. See the install manifest below.
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
	if nodeSpec, ok := NodeTool(name); ok {
		return installNodeTool(ctx, name, version, destDir, nodeSpec)
	}
	if goSpec, ok := GoTool(name); ok {
		return installGoTool(ctx, name, version, destDir, goSpec)
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
	// The data tree, if this tool is more than a binary. After the binary so a failure here leaves
	// an installed tool that doctor will report as missing its data. Which is true, and better than
	// a rolled-back install that reports nothing at all.
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
		return false, "cosign not installed, skipped signature check", nil
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
// The record holds the *binary's* checksum, not just a version string. The pinned SHA-256 covers
// the upstream archive, so it can't be compared against an extracted binary. But we can compare
// against what we ourselves wrote. That way "already installed" can never quietly accept a binary
// that has been modified since: a mismatch reinstalls.

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
		// Refuse rather than sanitize. Joining a cleaned path would neutralize `..` and write the file
		// somewhere harmless, which is safe and quiet. And quiet is wrong here. An archive is untrusted
		// input even when its checksum matched: the pin proves it is the file upstream published, not
		// that the file is well-behaved, and a traversal attempt in a signed release is something
		// someone needs to hear about rather than have tidied away.
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
// It never refuses for want of evidence, a version somebody asked for is installed even when
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
		return "", fmt.Errorf("%s %s: %s is not listed with checksum %s in %s, the download does "+
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
