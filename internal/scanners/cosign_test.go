package scanners

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// signedJSON is the shape cosign writes to stdout, trimmed to the two fields this scanner reads.
// Taken from a real `cosign verify -o json` run against a signed public image.
const signedJSON = `[{"critical":{"type":"cosign container image signature","identity":{"docker-reference":"cgr.dev/chainguard/static"}},` +
	`"optional":{"Issuer":"https://token.actions.githubusercontent.com",` +
	`"Subject":"https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"}}]`

// stubCosign replaces the exec with a scripted answer per invocation, and records the argv.
func stubCosign(t *testing.T, answers ...func(argv []string) ([]byte, []byte, int, error)) (*cosignVerifier, *[][]string) {
	t.Helper()
	s, _ := NewCosign().(*cosignVerifier)
	var calls [][]string
	i := 0
	s.run = func(_ context.Context, argv []string) ([]byte, []byte, int, error) {
		calls = append(calls, argv)
		if i >= len(answers) {
			t.Fatalf("cosign called %d times, only %d answers scripted: %v", i+1, len(answers), argv)
		}
		a := answers[i]
		i++
		return a(argv)
	}
	return s, &calls
}

func ok(out string) func([]string) ([]byte, []byte, int, error) {
	return func([]string) ([]byte, []byte, int, error) { return []byte(out), nil, 0, nil }
}

func exits(code int) func([]string) ([]byte, []byte, int, error) {
	return func([]string) ([]byte, []byte, int, error) {
		return nil, nil, code, errors.New("cosign said no")
	}
}

// said is cosign exiting 1 with a sentence, which is how it answers about an attestation.
func said(stderr string) func([]string) ([]byte, []byte, int, error) {
	return func([]string) ([]byte, []byte, int, error) {
		return nil, []byte(stderr), 1, errors.New("exit status 1")
	}
}

// exitsSaying is cosign exiting with a code and a sentence on stderr.
func exitsSaying(code int, stderr string) func([]string) ([]byte, []byte, int, error) {
	return func([]string) ([]byte, []byte, int, error) {
		return nil, []byte(stderr), code, errors.New("cosign said no")
	}
}

// What cosign 3.1 prints when the signature it finds carries no certificate or does not verify,
// each read from a real run. The first is a key signature with a transparency-log entry, in the
// legacy format; the second a key signature with none, in the bundle format, as an organization
// signing offline makes; the third a bundle whose log entry names a different certificate.
const (
	keySignedLogged   = "Error: no matching signatures: x509: unsupported public key type: <nil>"
	keySignedUnlogged = "Error: no matching attestations: failed to verify log inclusion: " +
		"not enough verified log entries from transparency log: 0 < 1"
	signatureDoesNotVerify = "Error: no matching attestations: failed to verify log inclusion: " +
		"transparency log certificate does not match"
)

func scan(t *testing.T, s *cosignVerifier, cfg plugin.Config) sarif.Report {
	t.Helper()
	rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "ghcr.io/acme/p:1.0"}, cfg)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return rep
}

// expecting builds the job config the control writes for an image it has an expectation for.
func expecting() plugin.Config {
	return plugin.Config{
		"signer": "our-ci", "issuer": "https://token.actions.githubusercontent.com",
		"identity":  "https://github.com/acme/ci/.github/workflows/b.yml@refs/tags/v3",
		"unmatched": "observe",
	}
}

// A verified signature is not a finding. The control's value is in what it refuses.
func TestCosignVerifiedProducesNoFinding(t *testing.T) {
	s, calls := stubCosign(t, ok(signedJSON))
	rep := scan(t, s, expecting())
	if len(rep.Results) != 0 {
		t.Errorf("a verified image should produce no finding, got %v", rep.Results)
	}
	argv := strings.Join((*calls)[0], " ")
	for _, want := range []string{"--certificate-identity", "--certificate-oidc-issuer", "--output json"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q: %s", want, argv)
		}
	}
	if strings.Contains(argv, "--certificate-identity-regexp") {
		t.Error("an exact identity must not be passed as a pattern")
	}
}

// Draugr never asks cosign to accept any signature on the path that decides a verdict. A pattern
// matching anything is how this mechanism is bypassed in the wild.
func TestCosignNeverVerifiesWithAPermissivePattern(t *testing.T) {
	s, calls := stubCosign(t, ok(signedJSON))
	scan(t, s, expecting())
	if strings.Contains(strings.Join((*calls)[0], " "), ".*") {
		t.Errorf("the verifying call used a permissive pattern: %v", (*calls)[0])
	}
}

// The transparency log is what establishes that the certificate was valid when it signed, rather
// than valid now, and a ten-minute certificate is the whole design.
func TestCosignNeverSkipsTheTransparencyLog(t *testing.T) {
	s, calls := stubCosign(t, ok(signedJSON))
	scan(t, s, expecting())
	if strings.Contains(strings.Join((*calls)[0], " "), "insecure-ignore-tlog") {
		t.Error("cosign was told to skip the transparency log")
	}
}

func TestCosignClassifiesEveryOutcome(t *testing.T) {
	cases := []struct {
		name     string
		cfg      plugin.Config
		answers  []func([]string) ([]byte, []byte, int, error)
		wantRule string
		wantErr  string
	}{
		{"signed by somebody else", expecting(),
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNoMatch), ok(signedJSON)},
			"provenance-unexpected-identity", ""},
		{"no certificate on the signature", expecting(),
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNoCertificate), ok(signedJSON)},
			"provenance-unexpected-identity", ""},
		{"expected and unsigned", expecting(),
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNoSignature)},
			"provenance-unsigned", ""},
		{"expected and the reference does not exist", expecting(),
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNonExistent)},
			"provenance-unsigned", ""},
		// The row that matters most. cosign returns 1 for a registry it could not reach, and
		// reading that as unsigned would turn a network failure into a clean bill of health.
		{"cosign could not answer", expecting(),
			[]func([]string) ([]byte, []byte, int, error){exits(1)},
			"", "verifying"},
		{"uncovered and unsigned, observed", plugin.Config{"unmatched": "observe"},
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNoSignature)},
			"", ""},
		{"uncovered and unsigned, warned", plugin.Config{"unmatched": "warn"},
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNoSignature)},
			"provenance-not-covered", ""},
		{"uncovered and unsigned, failed", plugin.Config{"unmatched": "fail"},
			[]func([]string) ([]byte, []byte, int, error){exits(cosignExitNoSignature)},
			"provenance-not-covered", ""},
		{"uncovered and signed", plugin.Config{"unmatched": "observe"},
			[]func([]string) ([]byte, []byte, int, error){ok(signedJSON)},
			"", ""},
		// A signature from an identity nobody declared is not coverage. Requiring coverage and
		// accepting any signature would pass an image signed by whoever pushed it.
		{"uncovered and signed, warned", plugin.Config{"unmatched": "warn"},
			[]func([]string) ([]byte, []byte, int, error){ok(signedJSON)},
			"provenance-not-covered", ""},
		{"uncovered and signed, failed", plugin.Config{"unmatched": "fail"},
			[]func([]string) ([]byte, []byte, int, error){ok(signedJSON)},
			"provenance-not-covered", ""},
		{"uncovered and cosign could not answer", plugin.Config{"unmatched": "observe"},
			[]func([]string) ([]byte, []byte, int, error){exits(1)},
			"", "reading the signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := stubCosign(t, c.answers...)
			rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "ghcr.io/acme/p:1.0"}, c.cfg)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.wantRule == "" {
				if len(rep.Results) != 0 {
					t.Errorf("want no finding, got %v", rep.Results)
				}
				return
			}
			if len(rep.Results) != 1 || rep.Results[0].RuleID != c.wantRule {
				t.Fatalf("results = %v, want one %s", rep.Results, c.wantRule)
			}
		})
	}
}

// An unexpected identity is the attack this control exists to catch, so it outranks an absence.
func TestCosignRanksAnUnexpectedIdentityAboveAnAbsence(t *testing.T) {
	mismatch, _ := stubCosign(t, exits(cosignExitNoMatch), ok(signedJSON))
	absent, _ := stubCosign(t, exits(cosignExitNoSignature))
	a := scan(t, mismatch, expecting()).Results[0]
	b := scan(t, absent, expecting()).Results[0]
	if a.Score <= b.Score {
		t.Errorf("an unexpected signer scored %v and an absence %v", a.Score, b.Score)
	}
	// The identity found leads the message: the console gives it 96 characters and a Fulcio
	// identity runs to about 95, so whatever comes first is what a reader gets.
	if !strings.Contains(a.Message, "chainguard-images/images") {
		t.Errorf("the message should name who did sign: %q", a.Message)
	}
}

// unmatched: fail with no signers declared, over two images: one signed by an identity nobody
// declared and one carrying nothing. Both are gaps in coverage and both fail, the signed one naming
// who signed it so a reader can declare that signer or refuse it. The identity is still recorded
// for the account of the run, because it is the value a signer for the image would declare.
func TestCosignRequiredCoverageFailsASignedImageNoSignerCovers(t *testing.T) {
	cfg := plugin.Config{"unmatched": "fail"}
	signed, _ := stubCosign(t, ok(signedJSON))
	unsigned, _ := stubCosign(t, exits(cosignExitNoSignature))

	reports := map[string]sarif.Report{}
	for ref, s := range map[string]*cosignVerifier{
		"cgr.dev/chainguard/static:latest": signed,
		"docker.io/library/alpine:3.19":    unsigned,
	} {
		rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: ref}, cfg)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		reports[ref] = rep
	}

	for ref, rep := range reports {
		if len(rep.Results) != 1 || rep.Results[0].RuleID != "provenance-not-covered" ||
			rep.Results[0].Level != sarif.LevelError {
			t.Errorf("%s: results = %v, want one provenance-not-covered at error", ref, rep.Results)
		}
	}
	got := reports["cgr.dev/chainguard/static:latest"]
	if msg := got.Results[0].Message; !strings.Contains(msg, "chainguard-images/images") {
		t.Errorf("the finding should name who signed the image: %q", msg)
	}
	if desc := got.Provenance[0].Describe(); !strings.Contains(desc, "https://github.com/chainguard-images/images") {
		t.Errorf("account = %q, want the identity found recorded in full", desc)
	}
	if msg := reports["docker.io/library/alpine:3.19"].Results[0].Message; !strings.Contains(msg, "no signature") {
		t.Errorf("an unsigned image should say it carries nothing: %q", msg)
	}
}

// Who signed comes from a second read rather than from parsing what the failure printed.
func TestCosignReadsBackTheIdentityOnlyAfterAFailure(t *testing.T) {
	s, calls := stubCosign(t, exits(cosignExitNoMatch), ok(signedJSON))
	scan(t, s, expecting())
	if len(*calls) != 2 {
		t.Fatalf("want a strict call then a read-back, got %d calls", len(*calls))
	}
	if !strings.Contains(strings.Join((*calls)[1], " "), "--certificate-identity-regexp .*") {
		t.Errorf("the read-back should accept any identity: %v", (*calls)[1])
	}
}

// The account of the run carries what the finding cannot: the identity, in full, and how the
// image was named.
func TestCosignRecordsWhatItObserved(t *testing.T) {
	s, _ := stubCosign(t, ok(signedJSON))
	rep := scan(t, s, plugin.Config{"unmatched": "observe"})
	if len(rep.Provenance) != 1 {
		t.Fatalf("want an account of the job, got %v", rep.Provenance)
	}
	got := rep.Provenance[0].Describe()
	for _, want := range []string{"no signer declared", "pinned: tag", "chainguard-images/images"} {
		if !strings.Contains(got, want) {
			t.Errorf("account = %q, want it to contain %q", got, want)
		}
	}
}

// A digest is what makes the check reproducible, so it is preferred and the tag is replaced
// rather than appended to.
func TestCosignPrefersTheDigest(t *testing.T) {
	cases := []struct {
		name, ref, digest, want string
		wantPinned              bool
	}{
		{"a tag and a digest", "ghcr.io/acme/p:1.0", "sha256:abc", "ghcr.io/acme/p@sha256:abc", true},
		{"a digest already in the reference", "ghcr.io/acme/p@sha256:old", "sha256:abc", "ghcr.io/acme/p@sha256:abc", true},
		{"a registry port and a tag", "reg.example.com:5000/acme/p:1.0", "sha256:abc", "reg.example.com:5000/acme/p@sha256:abc", true},
		{"a tag alone", "ghcr.io/acme/p:1.0", "", "ghcr.io/acme/p:1.0", false},
		{"a digest in the reference alone", "ghcr.io/acme/p@sha256:abc", "", "ghcr.io/acme/p@sha256:abc", true},
		{"a tag and a digest in the reference alone", "ghcr.io/acme/p:1.0@sha256:abc", "", "ghcr.io/acme/p:1.0@sha256:abc", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, pinned := cosignRef(plugin.ImageTarget{Ref: c.ref, Digest: c.digest})
			if got != c.want || pinned != c.wantPinned {
				t.Errorf("cosignRef = (%q, %v), want (%q, %v)", got, pinned, c.want, c.wantPinned)
			}
		})
	}
}

func TestCosignPassesTheTrustRoot(t *testing.T) {
	s, calls := stubCosign(t, ok(signedJSON))
	cfg := expecting()
	cfg["trustRoot"] = "/etc/draugr/root.json"
	scan(t, s, cfg)
	if !strings.Contains(strings.Join((*calls)[0], " "), "--trusted-root /etc/draugr/root.json") {
		t.Errorf("the cached root should reach cosign: %v", (*calls)[0])
	}
}

func TestCosignRefusesANonImageTarget(t *testing.T) {
	s, _ := stubCosign(t)
	_, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "https://example.com/x.git"}, nil)
	if err == nil || !strings.Contains(err.Error(), "image target") {
		t.Errorf("err = %v", err)
	}
}

// The trust root is one file. Without a warm, a component with fourteen images opens fourteen
// concurrent requests for it.
func TestCosignWarmsTheTrustRootOnce(t *testing.T) {
	s, calls := stubCosign(t, ok(""))
	if err := s.Prewarm(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0][1] != "initialize" {
		t.Errorf("warm ran %v", *calls)
	}
}

func TestCosignInfoDeclaresWhatItNeedsAndSends(t *testing.T) {
	info := NewCosign().Info()
	if info.Binary != "cosign" {
		t.Errorf("binary = %q", info.Binary)
	}
	if len(info.Data) == 0 {
		t.Error("the Sigstore trust root is fetched, so it must be declared for an egress allowlist")
	}
	var discloses bool
	for _, e := range info.Effects {
		if e.Kind == plugin.EffectDisclosure {
			discloses = true
		}
	}
	if !discloses {
		t.Error("digests reach the registry and the transparency log, which is a disclosure")
	}
}

// A warm that cannot reach the trust root is reported rather than swallowed, and the run goes on:
// the first job that needs the root fetches it and fails there, naming the image it was checking.
func TestCosignWarmReportsAFailure(t *testing.T) {
	s, _ := stubCosign(t, exits(1))
	if err := s.Prewarm(context.Background()); err == nil {
		t.Error("a warm that could not reach the trust root reported success")
	}
}

// An identity cosign did not report is still a fact worth carrying: an image that holds something
// is a different answer from one that holds nothing, and reporting neither would let the images
// most likely to carry provenance vanish from the account.
func TestCosignSaysWhenTheIdentityCouldNotBeRead(t *testing.T) {
	if got := describeObserved(signature{}); !strings.Contains(got, "could not be read") {
		t.Errorf("describeObserved = %q", got)
	}
	got := observedIdentity("ghcr.io/acme/p", "", "")
	if !strings.HasPrefix(got, "ghcr.io/acme/p\t") || !strings.Contains(got, "identity not reported") {
		t.Errorf("observedIdentity = %q, want the image recorded with the gap named", got)
	}
}

// The path that matters most, because it is what GitHub Actions produces. cosign reads a GitHub
// artifact attestation out of the registry as an OCI referrer and then answers about it with a
// sentence rather than an exit code: exit 1, and the identity it found written into the message.
// Read only as a code, that is "cosign could not answer", and the critical finding is lost.
func TestCosignReadsAnAttestationIdentityFailure(t *testing.T) {
	const refusal = `Error: no matching attestations: failed to verify certificate identity: ` +
		`no matching CertificateIdentity found, last error: expected SAN value ` +
		`"https://github.com/acme/nope/.github/workflows/x.yml@refs/heads/main", got ` +
		`"https://github.com/github/artifact-attestations-helm-charts/.github/workflows/release.yml@refs/tags/v1"`

	s, _ := stubCosign(t, said(refusal))
	rep := scan(t, s, expecting())
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "provenance-unexpected-identity" {
		t.Fatalf("results = %v, want one provenance-unexpected-identity", rep.Results)
	}
	// The identity comes out of the same message, so this path needs no second read.
	if !strings.Contains(rep.Results[0].Message, "artifact-attestations-helm-charts") {
		t.Errorf("the finding should name who did sign: %q", rep.Results[0].Message)
	}
}

// Every other reason cosign exits 1 stays an error. A registry it could not reach must not be
// read as an artifact signed by somebody unexpected.
func TestCosignKeepsOtherExitOneFailuresAnError(t *testing.T) {
	s, _ := stubCosign(t, said("Error: GET https://ghcr.io/token: DENIED: requested access to the resource is denied"))
	if _, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "ghcr.io/acme/p:1.0"}, expecting()); err == nil {
		t.Error("a registry that refused access was read as a finding")
	}
}

// A cosign that could not be started has said nothing about the image. Its code has to be one no
// outcome claims, or a missing binary reads as a pass or as an unsigned image depending on the
// number it happened to carry. Driven through the real exec, at a path where nothing exists, on
// both the verifying path and the observing one.
func TestCosignThatCouldNotStartIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "cosign")
	_, _, code, err := runCosign(context.Background(), []string{missing, "verify"})
	if code != -1 || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("code = %d, err = %v, want -1 and the reason cosign did not start", code, err)
	}

	s, _ := NewCosign().(*cosignVerifier)
	s.run = func(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
		return runCosign(ctx, append([]string{missing}, argv[1:]...))
	}
	for name, cfg := range map[string]plugin.Config{
		"a declared signer":          expecting(),
		"no signer, unmatched fails": {"unmatched": "fail"},
	} {
		rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "ghcr.io/acme/p:1.0"}, cfg)
		if err == nil {
			t.Errorf("%s: a cosign that never ran produced a verdict: %v", name, rep.Results)
		}
	}
}

// An attestation's identity is not in the payload cosign prints, so discovery asks for it. Without
// this the images most likely to carry provenance are the ones the account says nothing about.
func TestCosignDiscoversAnAttestationIdentity(t *testing.T) {
	const attestationPayload = `[{"critical":{"type":"https://slsa.dev/provenance/v1"},"optional":{}}]`
	const refusal = `Error: no matching attestations: failed to verify certificate identity: ` +
		`expected SAN value "x", got "https://github.com/acme/payments/.github/workflows/release.yml@refs/heads/main"`

	s, calls := stubCosign(t, ok(attestationPayload), said(refusal))
	rep := scan(t, s, plugin.Config{"unmatched": "observe"})
	if len(rep.Results) != 0 {
		t.Errorf("observing is not a finding, got %v", rep.Results)
	}
	if got := rep.Provenance[0].Describe(); !strings.Contains(got, "acme/payments/.github/workflows/release.yml") {
		t.Errorf("account = %q, want the identity the attestation carries", got)
	}
	if len(*calls) != 2 {
		t.Fatalf("want a permissive read then a probe, got %d calls", len(*calls))
	}
	// The probe names an identity nothing can carry, which is what makes cosign say what it found.
	if !strings.Contains(strings.Join((*calls)[1], " "), impossibleIdentity) {
		t.Errorf("the probe should ask for an impossible identity: %v", (*calls)[1])
	}
}

// A bare signature still reports its identity in the payload, so it takes one call and not two.
func TestCosignDoesNotProbeABareSignature(t *testing.T) {
	s, calls := stubCosign(t, ok(signedJSON))
	if _, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "ghcr.io/acme/p:1.0"},
		plugin.Config{"unmatched": "observe"}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Errorf("a signature carries its own identity, so one read is enough: %d calls", len(*calls))
	}
}

// TestWhoSignedIsTheReadDiscoveryAndVerificationShare.
//
// The surveyor that proposes signers and the control that checks them have to ask the registry the
// same question. Asked separately they diverge on the case that decides whether discovery is worth
// running: a GitHub artifact attestation answers a plain read with an empty identity, so the naive
// version reports nothing for exactly the images most likely to carry provenance.
func TestWhoSignedIsTheReadDiscoveryAndVerificationShare(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		answers []func([]string) ([]byte, []byte, int, error)
		want    Signature
	}{
		{
			name:    "a plain signature carries its identity in the payload",
			answers: []func([]string) ([]byte, []byte, int, error){ok(`[{"critical":{"type":"cosign container image signature"},"optional":{"Subject":"https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3","Issuer":"https://token.actions.githubusercontent.com"}}]`)},
			want: Signature{
				Identity: "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3",
				Issuer:   "https://token.actions.githubusercontent.com",
				Signed:   true,
			},
		},
		{
			// An attestation's identity is in the certificate, not the payload, so the first read
			// succeeds with nothing in it and a second read has to ask.
			name: "an attestation needs the second read",
			answers: []func([]string) ([]byte, []byte, int, error){
				ok(`[{"critical":{"type":"https://slsa.dev/provenance/v1"},"optional":{}}]`),
				said(`no matching attestations: failed to verify certificate identity: got "https://github.com/acme/build/.github/workflows/attest.yml@refs/heads/main"`),
			},
			want: Signature{
				Identity: "https://github.com/acme/build/.github/workflows/attest.yml@refs/heads/main",
				Issuer:   githubOIDCIssuer,
				Signed:   true,
			},
		},
		{
			// Most of what a project runs is published by somebody else. Not an error, and not a
			// signer: proposing one for an image nobody signed would be proposing a policy that
			// can only fail.
			name:    "nothing signed it",
			answers: []func([]string) ([]byte, []byte, int, error){exits(cosignExitNoSignature)},
			want:    Signature{},
		},
		{
			name:    "the image is not there",
			answers: []func([]string) ([]byte, []byte, int, error){exits(cosignExitNonExistent)},
			want:    Signature{},
		},
		// A signature with no Fulcio certificate has no identity to read, and is still a
		// signature. Read as an error, one image signed with a key stops the control for every
		// other image in the run.
		{
			name:    "a key signature with a log entry",
			answers: []func([]string) ([]byte, []byte, int, error){exitsSaying(cosignExitNoMatch, keySignedLogged)},
			want:    Signature{Signed: true},
		},
		{
			name:    "a key signature with no log entry",
			answers: []func([]string) ([]byte, []byte, int, error){said(keySignedUnlogged)},
			want:    Signature{Signed: true},
		},
		{
			name:    "a signature with no certificate",
			answers: []func([]string) ([]byte, []byte, int, error){exits(cosignExitNoCertificate)},
			want:    Signature{Signed: true},
		},
		{
			name:    "a signature that does not verify",
			answers: []func([]string) ([]byte, []byte, int, error){said(signatureDoesNotVerify)},
			want:    Signature{Signed: true},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, _ := stubCosign(t, c.answers...)
			got, err := s.whoSigned(context.Background(), "ghcr.io/acme/p:1.0", expectation{})
			if err != nil {
				t.Fatalf("whoSigned: %v", err)
			}
			if got != c.want {
				t.Errorf("whoSigned = %+v,\n          want %+v", got, c.want)
			}
		})
	}
}

// A registry that did not answer is not an image nobody signed. Read as one, discovery would
// propose no signer for an image that has one, and verification would report a clean inventory
// for a registry it could not reach.
func TestWhoSignedRefusesToCallAnUnreadableAnswerUnsigned(t *testing.T) {
	t.Parallel()
	s, _ := stubCosign(t, exits(1))
	if _, err := s.whoSigned(context.Background(), "ghcr.io/acme/p:1.0", expectation{}); err == nil {
		t.Error("an unreadable answer was reported as a definite absence of signature")
	}
	// Nor as a signature: a registry that refused access has said nothing about what it holds.
	s, _ = stubCosign(t, said("Error: GET https://ghcr.io/token: DENIED: requested access to the resource is denied"))
	if got, err := s.whoSigned(context.Background(), "ghcr.io/acme/p:1.0", expectation{}); err == nil {
		t.Errorf("a registry that refused access was read as %+v", got)
	}
	// And a verified answer this could not parse is not an image with no identity on it.
	s, _ = stubCosign(t, ok("not what cosign prints"))
	if got, err := s.whoSigned(context.Background(), "ghcr.io/acme/p:1.0", expectation{}); err == nil {
		t.Errorf("an unparsed answer was read as %+v", got)
	}
}

// Discovery over two images, one signed with a key and one through Sigstore keyless. The key
// signature is observed as a signature whose identity could not be read, rather than stopping the
// control, and the other image is read as it would be on its own. Under unmatched: observe neither
// is a finding.
func TestCosignObservesAKeySignatureAndCarriesOn(t *testing.T) {
	cfg := plugin.Config{"unmatched": "observe"}
	for ref, answer := range map[string]func([]string) ([]byte, []byte, int, error){
		"registry.example.com/acme/offline@sha256:aaaa": said(keySignedUnlogged),
		"cgr.dev/chainguard/static:latest":              ok(signedJSON),
	} {
		s, _ := stubCosign(t, answer)
		rep, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: ref}, cfg)
		if err != nil {
			t.Fatalf("%s: a signed image stopped the control: %v", ref, err)
		}
		if len(rep.Results) != 0 {
			t.Errorf("%s: observing is not a finding, got %v", ref, rep.Results)
		}
		desc := rep.Provenance[0].Describe()
		if strings.Contains(desc, "unsigned") {
			t.Errorf("%s: account = %q, a signed image was counted as unsigned", ref, desc)
		}
		if strings.HasPrefix(ref, "registry.example.com") && !strings.Contains(desc, "identity not reported") {
			t.Errorf("%s: account = %q, want the signature recorded with its identity unread", ref, desc)
		}
	}
}

// The descriptor's own Sigstore root reaches the read. Without it discovery reports nothing for
// exactly the organizations running their own Sigstore, whose signers are the least guessable.
func TestWhoSignedCarriesTheTrustRoot(t *testing.T) {
	t.Parallel()
	s, calls := stubCosign(t, ok(`[{"critical":{"type":"cosign container image signature"},"optional":{"Subject":"s","Issuer":"i"}}]`))
	if _, err := s.whoSigned(context.Background(), "ghcr.io/acme/p:1.0", expectation{TrustRoot: "/etc/roots.json"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains((*calls)[0], "--trusted-root") || !slices.Contains((*calls)[0], "/etc/roots.json") {
		t.Errorf("the trust root did not reach cosign: %v", (*calls)[0])
	}
}
