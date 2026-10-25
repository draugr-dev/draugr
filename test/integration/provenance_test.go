//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The provenance control is the one whose whole value is in what a real registry and a real
// verifier say. Its unit tests script cosign's exit codes and notation's messages, which proves
// the classification and proves nothing about whether those are the codes and messages the tools
// produce. These run the real binaries against real artifacts.
//
// cgr.dev/chainguard/static is public, Sigstore-signed by a workflow whose identity is stable, and
// small. docker.io/library/alpine is public and carries no signature at all, which is the other
// half of what the control has to tell apart.
const (
	signedImage   = "cgr.dev/chainguard/static:latest"
	unsignedImage = "docker.io/library/alpine:3.19"
	// The identity that image actually carries, read back from cosign rather than assumed.
	signedIdentity = `^https://github\.com/chainguard-images/images/\.github/workflows/release\.yaml@refs/heads/main$`
	sigstoreIssuer = "https://token.actions.githubusercontent.com"
)

// findings reads the rule IDs a scan wrote into its SARIF, which is the artifact a consumer sees.
func findings(t *testing.T, dir string) []string {
	t.Helper()
	// #nosec G304 -- dir is t.TempDir(), which this test passed to the scan as its output.
	raw, err := os.ReadFile(filepath.Join(dir, "results.sarif"))
	if err != nil {
		t.Fatalf("expected a SARIF report: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			out = append(out, r.RuleID+" "+r.Message.Text)
		}
	}
	return out
}

// runScan writes a descriptor, scans it, and returns the findings plus whether the gate passed.
func runScan(t *testing.T, saga string) ([]string, bool) {
	t.Helper()
	out, passed := scanProvenance(t, saga)
	return findings(t, out), passed
}

// scanProvenance is runScan returning the output directory instead of the findings, for a test
// that reads more of the run than what it found.
func scanProvenance(t *testing.T, saga string) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "provenance.saga.yaml")
	if err := os.WriteFile(path, []byte(saga), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	// #nosec G204 -- the binary under test, from $DRAUGR_BIN or LookPath; the arguments are the
	// descriptor and output directory this test just created.
	cmd := exec.Command(draugrBin(t), "scan", path, "--output", out, "--log-level", "warn")
	combined, err := cmd.CombinedOutput()
	t.Logf("draugr scan exit=%v\n%s", err, combined)
	return out, err == nil
}

// descriptor renders a one-image descriptor with the given provenance block.
func descriptor(image, controlBlock string) string {
	return `project: provenance-integration
release: {version: "1.0.0"}
config:
  controls:
    provenance:
      enabled: true
` + controlBlock + `
components:
  - name: app
    exposure: public
    criticality: critical
    images:
      - image: ` + image + `
`
}

// A signature from the identity the descriptor expects is not a finding. This is the only test
// that proves cosign's success path end to end: every scripted one asserts what Draugr does with
// exit code zero, not that a real verification produces it.
func TestProvenanceVerifiesARealSignature(t *testing.T) {
	requireTool(t, "cosign", "the point of this test is a real cosign verifying a real signature")

	got, passed := runScan(t, descriptor(signedImage, `      signers:
        - name: chainguard
          images: ["cgr.dev/*"]
          keyless:
            issuer: `+sigstoreIssuer+`
            identityRegexp: `+signedIdentity+`
`))
	if len(got) != 0 {
		t.Errorf("a signature from the expected identity should produce no finding, got %v", got)
	}
	if !passed {
		t.Error("the gate should pass when every image verifies")
	}
}

// The finding the control exists for. Expecting an identity the artifact does not carry has to
// report a mismatch rather than an absence, and has to name who did sign: a reader comparing what
// they meant against what is there needs the second half.
func TestProvenanceReportsARealIdentityMismatch(t *testing.T) {
	requireTool(t, "cosign", "the point of this test is cosign refusing a real signature")

	got, passed := runScan(t, descriptor(signedImage, `      signers:
        - name: our-ci
          images: ["cgr.dev/*"]
          github:
            repository: acme/ci-workflows
            workflow: .github/workflows/build.yml
            ref: refs/heads/main
`))
	if len(got) != 1 || !strings.HasPrefix(got[0], "provenance-unexpected-identity") {
		t.Fatalf("findings = %v, want one provenance-unexpected-identity", got)
	}
	if !strings.Contains(got[0], "chainguard-images/images") {
		t.Errorf("the finding should name who did sign: %q", got[0])
	}
	if passed {
		t.Error("an image signed by an unexpected workload must fail the gate")
	}
}

// An absence, distinguished from a mismatch. The risk this guards is cosign's exit code 10 being
// read as something else, which would turn an unsigned image into a pass or an error.
func TestProvenanceReportsARealAbsentSignature(t *testing.T) {
	requireTool(t, "cosign", "the point of this test is cosign reporting a real absence")

	got, passed := runScan(t, descriptor(unsignedImage, `      signers:
        - name: our-ci
          images: ["docker.io/*"]
          keyless:
            issuer: `+sigstoreIssuer+`
            identity: https://github.com/acme/ci/.github/workflows/b.yml@refs/heads/main
`))
	if len(got) != 1 || !strings.HasPrefix(got[0], "provenance-unsigned") {
		t.Fatalf("findings = %v, want one provenance-unsigned", got)
	}
	if passed {
		t.Error("an image that should be signed and is not must fail the gate")
	}
}

// Discovery, which is how somebody finds the identity to declare. It must not fail, and it must
// report what it found rather than nothing.
func TestProvenanceDiscoveryReportsWhatItFound(t *testing.T) {
	requireTool(t, "cosign", "the point of this test is reading back a real signing identity")

	dir := t.TempDir()
	path := filepath.Join(dir, "discover.saga.yaml")
	if err := os.WriteFile(path, []byte(descriptor(signedImage, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	// #nosec G204 -- as above.
	cmd := exec.Command(draugrBin(t), "scan", path, "--output", out, "--log-level", "warn")
	combined, err := cmd.CombinedOutput()
	t.Logf("draugr scan exit=%v\n%s", err, combined)
	if err != nil {
		t.Fatalf("a descriptor with no signers must not fail: %v", err)
	}
	if got := findings(t, out); len(got) != 0 {
		t.Errorf("observing is not a finding, got %v", got)
	}
	// The terminal gets the count. The block this row lands in gives a control three lines, and an
	// inventory is as long as the inventory, so a run over fifty images would have reported less
	// than a run over two.
	if !strings.Contains(string(combined), "1 observed") {
		t.Errorf("the run should count what it observed:\n%s", combined)
	}
	if strings.Contains(string(combined), "chainguard-images/images") {
		t.Errorf("the identity belongs in the machine formats, not on a terminal row:\n%s", combined)
	}
	// And the identity itself, whole, where somebody copies it from.
	sarif, readErr := os.ReadFile(filepath.Join(out, "results.sarif")) // #nosec G304 -- t.TempDir()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(sarif), "chainguard-images/images") {
		t.Error("the run should record the identity it observed, in full")
	}
	if !strings.Contains(string(sarif), sigstoreIssuer) {
		t.Error("an identity without its issuer does not describe a check, so both are recorded")
	}
}

// notation's verdict arrives as a message rather than an exit code, so the strings the scanner
// matches on are the ones most likely to drift. This runs the real binary against a real registry
// with a trust policy Draugr generated, which is the part no unit test can prove.
func TestProvenanceNotationAgainstARealRegistry(t *testing.T) {
	requireTool(t, "notation", "the point of this test is a real notation reading a real registry")

	// A trust store holding a certificate nothing was signed with. The image carries no Notary
	// Project signature at all, so what is in it never has to match; what is being exercised is
	// that Draugr's generated policy is accepted and that notation's answer is read correctly.
	_, roots, subject := notationTestCert(t, "acme-release-signing")

	got, passed := runScan(t, descriptor(unsignedImage, `      signers:
        - name: acme-pki
          images: ["docker.io/*"]
          x509:
            trustStore: `+roots+`
            subject: "`+subject+`"
`))
	// The message notation gives for an absent signature is what the scanner matches on. A rule
	// of "provenance-unsigned" here means the real string still contains what it looks for; an
	// error instead would mean the wording moved, which is the safe direction and still a
	// failure worth seeing.
	if len(got) != 1 || !strings.HasPrefix(got[0], "provenance-unsigned") {
		t.Fatalf("findings = %v, want one provenance-unsigned from notation", got)
	}
	if passed {
		t.Error("an image that should carry a Notary Project signature and does not must fail the gate")
	}
}

// The success path, which nothing else runs against the real binary: an image carrying a Notary
// Project signature from the certificate the descriptor names verifies, and the same signature
// checked against a subject it does not carry is refused. The refusal is what gives the pass its
// meaning, since a scanner that passed every image would pass the first half on its own.
//
// No public image carries a signature from a certificate this test can trust, so it signs one of
// its own, in a registry the job provides.
func TestProvenanceNotationVerifiesARealSignature(t *testing.T) {
	requireTool(t, "notation", "the point of this test is a real notation verifying a real signature")
	registry := requireRegistry(t, "the signature has to be pushed somewhere this test can write")

	// Named by tag and pinned by digest, under a host with a port. The reference Draugr builds
	// from those, and the scope it writes into the trust policy, both have to drop the tag and keep
	// the port, and a registry on localhost always has a port.
	repo := registry + "/draugr-integration/app"
	digest := pushImage(t, registry, "draugr-integration/app", "1.0.0")
	config, cert, subject := notationTestCert(t, "draugr-integration")
	notationAs(t, config, "sign", repo+"@"+digest)

	signedBy := func(subject string) string {
		return `project: provenance-integration
release: {version: "1.0.0"}
config:
  controls:
    provenance:
      enabled: true
      signers:
        - name: release-signing
          images: ["` + registry + `/*"]
          x509:
            trustStore: ` + cert + `
            subject: "` + subject + `"
components:
  - name: app
    exposure: public
    criticality: critical
    images:
      - image: ` + repo + `:1.0.0
        digest: ` + digest + `
`
	}

	t.Run("declared subject", func(t *testing.T) {
		out, passed := scanProvenance(t, signedBy(subject))
		if got := findings(t, out); len(got) != 0 {
			t.Errorf("a signature from the declared certificate should produce no finding, got %v", got)
		}
		if !passed {
			t.Error("the gate should pass when every image verifies")
		}
		requireControlRan(t, out, "provenance", "notation")
		// A scan that planned no job would pass the checks above as well, so the run's own account
		// of what it measured is read too.
		account, ok := verifierAccount(t, out)["notation"]
		if !ok {
			t.Fatal("the run carries no account from notation, so nothing says the image was verified")
		}
		if coverage := account["coverage"]; !strings.HasPrefix(coverage, "1 of 1 image checked") ||
			strings.Contains(coverage, "unsigned") {
			t.Errorf("coverage = %q, want the one image checked against its signer", coverage)
		}
		if pinning := account["pinning"]; !strings.Contains(pinning, "by digest") {
			t.Errorf("pinning = %q, want the image verified by the digest the descriptor declares", pinning)
		}
	})

	t.Run("another subject", func(t *testing.T) {
		got, passed := runScan(t, signedBy("C=US, ST=WA, O=Notary, CN=somebody-else"))
		// The message notation gives for a subject it does not trust is what the scanner matches on,
		// so this is the other string that a release of notation can move.
		if len(got) != 1 || !strings.HasPrefix(got[0], "provenance-unexpected-identity") {
			t.Fatalf("findings = %v, want one provenance-unexpected-identity from notation", got)
		}
		if passed {
			t.Error("an image signed by a certificate the descriptor does not name must fail the gate")
		}
	})
}

// notationTestCert has notation generate a self-signed certificate and key into a configuration
// directory of the test's own, and returns that directory, the certificate's path and its subject
// in the form a descriptor declares it.
//
// The directory belongs to the signer alone. Draugr writes a configuration of its own for every
// verification, so a scan sees this certificate only through the trust store the descriptor names,
// which is the part under test.
func notationTestCert(t *testing.T, name string) (config, cert, subject string) {
	t.Helper()
	config = filepath.Join(t.TempDir(), "notation")
	notationAs(t, config, "cert", "generate-test", "--default", name)

	raw, err := os.ReadFile(filepath.Join(config, "signingkeys.json")) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("notation wrote no signing key configuration: %v", err)
	}
	var keys struct {
		Keys []struct {
			Name     string `json:"name"`
			CertPath string `json:"certPath"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("parse signingkeys.json: %v", err)
	}
	for _, k := range keys.Keys {
		if k.Name == name {
			cert = k.CertPath
		}
	}
	if cert == "" {
		t.Fatalf("signingkeys.json names no certificate for %s:\n%s", name, raw)
	}
	if !filepath.IsAbs(cert) {
		cert = filepath.Join(config, cert)
	}
	encoded, err := os.ReadFile(cert) // #nosec G304 -- a path notation wrote under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatalf("%s holds no PEM certificate", cert)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", cert, err)
	}
	return config, cert, parsed.Subject.String()
}

// notationAs runs notation against a configuration directory of the test's own.
func notationAs(t *testing.T, config string, args ...string) {
	t.Helper()
	// #nosec G204 -- notation with argument lists this file wrote, configured under t.TempDir().
	cmd := exec.Command("notation", args...)
	cmd.Env = append(os.Environ(), "NOTATION_CONFIG="+config)
	out, err := cmd.CombinedOutput()
	t.Logf("notation %v exit=%v\n%s", args, err, out)
	if err != nil {
		t.Fatalf("notation %v: %v", args, err)
	}
}

// verifierAccount reads what the provenance control said about its own run, by verifier, from the
// SARIF property bag: what each was measured against, as opposed to what it found.
func verifierAccount(t *testing.T, dir string) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "results.sarif")) // #nosec G304 -- t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Properties struct {
				Provenance []struct {
					Tool   string            `json:"tool"`
					Fields map[string]string `json:"fields"`
				} `json:"draugr/provenance"`
			} `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	for _, run := range doc.Runs {
		for _, p := range run.Properties.Provenance {
			out[p.Tool] = p.Fields
		}
	}
	return out
}

// ociManifest is the media type of the manifest pushImage writes.
const ociManifest = "application/vnd.oci.image.manifest.v1+json"

// pushImage puts a minimal image into the registry under a tag and returns its digest.
//
// Built here rather than copied from a public registry, so what gets signed depends on nothing
// outside the job. It has one empty layer, because the image specification discourages a manifest
// with none and a registry may refuse one.
func pushImage(t *testing.T, registry, repo, tag string) string {
	t.Helper()
	layer := make([]byte, 1024) // an empty tar archive is two zero blocks
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["` +
		digestOf(layer) + `"]}}`)
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     ociManifest,
		"config": map[string]any{
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest":    pushBlob(t, registry, repo, config),
			"size":      len(config),
		},
		"layers": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.layer.v1.tar",
			"digest":    pushBlob(t, registry, repo, layer),
			"size":      len(layer),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	registryPut(t, "http://"+registry+"/v2/"+repo+"/manifests/"+tag, ociManifest, manifest)
	return digestOf(manifest)
}

// pushBlob uploads one blob, monolithically, and returns its digest.
func pushBlob(t *testing.T, registry, repo string, body []byte) string {
	t.Helper()
	// #nosec G107 -- a registry on localhost that the job started for this test.
	resp, err := http.Post("http://"+registry+"/v2/"+repo+"/blobs/uploads/", "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("start a blob upload: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start a blob upload: %s", resp.Status)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("the registry gave no upload location: %v", err)
	}
	digest := digestOf(body)
	query := loc.Query()
	query.Set("digest", digest)
	loc.RawQuery = query.Encode()
	registryPut(t, loc.String(), "application/octet-stream", body)
	return digest
}

// registryPut sends one PUT to the registry and fails the test unless it created something.
func registryPut(t *testing.T, url, contentType string, body []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT %s: %s\n%s", url, resp.Status, msg)
	}
}

// digestOf is the content address a registry gives bytes.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// attestedImage carries a GitHub artifact attestation pushed to the registry as an OCI referrer,
// which is what `actions/attest` with `push-to-registry: true` produces and therefore the shape
// most images with provenance have.
//
// cosign answers about an attestation with a sentence rather than an exit code, so the codes this
// scanner reads say nothing here. Scripted tests prove the sentence is parsed; only a real one
// proves it is the sentence cosign writes.
const attestedImage = "ghcr.io/github/artifact-attestations-helm-charts/policy-controller:v0.10.0-github5"

func TestProvenanceReadsARealGitHubAttestation(t *testing.T) {
	requireTool(t, "cosign", "the point of this test is cosign refusing a real attestation")

	got, passed := runScan(t, descriptor(attestedImage, `      signers:
        - name: our-ci
          images: ["ghcr.io/github/*"]
          github:
            repository: acme/ci-workflows
            workflow: .github/workflows/build.yml
            ref: refs/heads/main
`))
	// Before this was classified, cosign's exit 1 read as "could not answer" and the critical
	// finding was reported as an error instead.
	if len(got) != 1 || !strings.HasPrefix(got[0], "provenance-unexpected-identity") {
		t.Fatalf("findings = %v, want one provenance-unexpected-identity", got)
	}
	if !strings.Contains(got[0], "artifact-attestations-helm-charts") {
		t.Errorf("the finding should name the workflow that did sign: %q", got[0])
	}
	if passed {
		t.Error("an attestation from an unexpected workflow must fail the gate")
	}
}

// And discovery on the same image, which is how somebody finds the identity to declare. An
// attestation keeps its identity in the certificate rather than in the payload, so this is the
// path that would otherwise report nothing at all.
func TestProvenanceDiscoversARealAttestationIdentity(t *testing.T) {
	requireTool(t, "cosign", "the point of this test is reading back a real attestation's identity")

	dir := t.TempDir()
	path := filepath.Join(dir, "discover.saga.yaml")
	if err := os.WriteFile(path, []byte(descriptor(attestedImage, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	// #nosec G204 -- as above.
	cmd := exec.Command(draugrBin(t), "scan", path, "--output", out, "--log-level", "warn")
	combined, err := cmd.CombinedOutput()
	t.Logf("draugr scan exit=%v\n%s", err, combined)
	if err != nil {
		t.Fatalf("a descriptor with no signers must not fail: %v", err)
	}
	sarif, readErr := os.ReadFile(filepath.Join(out, "results.sarif")) // #nosec G304 -- t.TempDir()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(sarif), "artifact-attestations-helm-charts/.github/workflows/release.yml") {
		t.Error("the run should record the identity the attestation carries, in full")
	}
}
