package scanners

import (
	"context"
	"errors"
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
	got := observedNote("ghcr.io/acme/p", signature{})
	if !strings.HasPrefix(got, "ghcr.io/acme/p\t") || !strings.Contains(got, "identity not reported") {
		t.Errorf("observedNote = %q, want the image recorded with the gap named", got)
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
