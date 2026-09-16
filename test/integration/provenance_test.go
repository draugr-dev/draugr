//go:build integration

package integration

import (
	"encoding/json"
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
	return findings(t, out), err == nil
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
	// The identity belongs in the control's account of the run, which is what somebody copies.
	if !strings.Contains(string(combined), "chainguard-images/images") {
		t.Errorf("the run should report the identity it observed:\n%s", combined)
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
	dir := t.TempDir()
	roots := filepath.Join(dir, "roots.pem")
	// #nosec G204 -- openssl with literal arguments and paths this test created.
	gen := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", filepath.Join(dir, "key.pem"), "-out", roots,
		"-days", "1", "-nodes", "-subj", "/C=US/ST=WA/O=Acme/CN=Acme Release Signing")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("openssl is needed to build a trust store for this test: %v\n%s", err, out)
	}

	got, passed := runScan(t, descriptor(unsignedImage, `      signers:
        - name: acme-pki
          images: ["docker.io/*"]
          x509:
            trustStore: `+roots+`
            subject: "C=US, ST=WA, O=Acme, CN=Acme Release Signing"
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
