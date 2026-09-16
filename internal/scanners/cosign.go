package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// cosignScannerName is the scanner's name in the registry and in a descriptor.
const cosignScannerName = "cosign"

// The exit codes cosign uses to say what went wrong, from its own `cmd/cosign/errors` package.
// Observed against cosign 3.1.3.
//
// Only zero is a pass. The three below are findings, and every other code is an error this
// control reports rather than a result: cosign returns 1 for anything it has no specific code
// for, which includes a registry it could not reach and a transparency log that did not answer.
// Reading 1 as "unsigned" would turn an unreachable registry into a clean bill of health.
// The values config.controls.provenance.unmatched takes, as the control resolves them. Spelled
// here rather than imported: internal/controllers already imports this package's siblings, and a
// scanner reaching back into a controller for three strings would be a cycle waiting to happen.
const (
	unmatchedWarn = "warn"
	unmatchedFail = "fail"
)

// What cosign says about an attestation, which is the form a GitHub artifact attestation takes.
// Observed against cosign 3.1.1.
//
// An attestation gets no exit code of its own: cosign exits 1 and explains. So the outcomes that
// mean something on that path are recognized by the sentence, and anything unrecognized stays an
// error. Wording that moves upstream turns a finding into an error rather than into a pass.
//
// The message carries the identity it found, which is why this path needs no second read.
const (
	cosignAttestationNoMatch = "no matching attestations"
	cosignIdentityFailed     = "failed to verify certificate identity"
	cosignFoundSAN           = `got "`
)

const (
	cosignExitNoSignature   = 10
	cosignExitNonExistent   = 11
	cosignExitNoMatch       = 12
	cosignExitNoCertificate = 13
)

// cosignConfigSchema is the JSON Schema for the job config this scanner receives.
//
// Every key in it is written by the control, not by a descriptor. They are declared because the
// engine holds a job's config to its scanner's schema, and they are refused under
// `controls.provenance.cosign` by the control's own validation, because a key that a descriptor
// can write and that has no effect is worse than one it cannot write at all.
//
// It matters more here than it would elsewhere. `identityRegexp: ".*"` accepts a signature from
// anybody, so a scanner block that could set it would be a way to turn the control green without
// touching the signer it appears to be governed by. Plan writes all six on every job, so whatever
// reached the block is overwritten before it is read.
const cosignConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "signer": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the name of the signer covering this image."
    },
    "issuer": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the OIDC issuer the signature must carry."
    },
    "identity": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the exact signing identity to require."
    },
    "identityRegexp": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the pattern the signing identity must match."
    },
    "unmatched": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: what an image no signer covers is worth."
    },
    "trustRoot": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: a Sigstore trusted-root file to verify against."
    }
  }
}`

// cosignVerifier checks that a container image carries a Sigstore signature from the identity the
// descriptor expects. It serves the "provenance" control.
//
// The strict check runs first and the verdict is cosign's, never a comparison of Draugr's. Reading
// back a signature with a permissive identity pattern and then matching the subject in Go would
// put the whole guarantee behind one string comparison, and a pattern loose enough to match
// anything is the documented way this mechanism gets bypassed. So Draugr decides *what* to expect,
// passes it to cosign, and believes the exit code.
//
// The permissive read happens only after a failure, to say who did sign. It never produces a pass.
type cosignVerifier struct {
	info plugin.ScannerInfo
	// run executes cosign and returns stdout, stderr and the process exit code. Injected so tests
	// need neither the binary nor a registry.
	//
	// stderr as well as the code, because cosign answers about a signature with an exit code and
	// about an attestation with a sentence. Reading only the code loses half the outcomes.
	run func(ctx context.Context, argv []string) (stdout, stderr []byte, code int, err error)
}

// NewCosign returns the Sigstore verification scanner.
func NewCosign() plugin.Scanner {
	return &cosignVerifier{
		info: plugin.ScannerInfo{
			Name:         cosignScannerName,
			Binary:       "cosign",
			Origin:       "sigstore",
			Controls:     []string{"provenance"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
			ConfigSchema: json.RawMessage(cosignConfigSchema),
			Data: []plugin.DataSource{{
				Name:  "Sigstore trust root",
				Hosts: []string{"tuf-repo-cdn.sigstore.dev"},
				Local: "--trusted-root <file>, set as config.controls.provenance.trustRoot",
			}},
			Effects: []plugin.Effect{{
				Kind: plugin.EffectDisclosure,
				Detail: "the digest of each image checked, to the registry holding it and, where a " +
					"signature carries no inclusion proof, to the Sigstore transparency log",
			}},
		},
		run: runCosign,
	}
}

// Info identifies the scanner.
func (s *cosignVerifier) Info() plugin.ScannerInfo { return s.info }

// Prewarm fetches the Sigstore trust root once, into the cache cosign keeps under ~/.sigstore.
//
// Without it every job fetches it, so a component with fourteen images opens fourteen concurrent
// requests for one file. A failure here is not fatal: the root is fetched again by the first job
// that needs it, and a run that cannot reach it fails there with a message about the image it was
// checking rather than about a warm nobody asked for.
func (s *cosignVerifier) Prewarm(ctx context.Context) error {
	if _, _, _, err := s.run(ctx, []string{"cosign", "initialize"}); err != nil {
		return fmt.Errorf("cosign: fetching the Sigstore trust root: %w", err)
	}
	return nil
}

// Scan verifies one image against the expectation the control resolved for it.
func (s *cosignVerifier) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("cosign: expected an image target, got %s", target.Kind())
	}
	ref, byDigest := cosignRef(img)
	if ref == "" {
		return sarif.Report{}, errors.New("cosign: the image has neither a reference nor a digest")
	}

	expect := expectationFrom(cfg)
	result, observed, err := s.check(ctx, ref, expect)
	if err != nil {
		return sarif.Report{}, err
	}
	report := sarif.Report{Tool: cosignScannerName}
	report.Provenance = []sarif.Provenance{{
		Tool:   cosignScannerName,
		Fields: cosignFields(expect, byDigest, img.Ref, observed),
	}}
	if result != nil {
		result.Location = sarif.Location{URI: img.Ref}
		report.Results = []sarif.Result{*result}
	}
	return report, nil
}

// expectation is what this image is supposed to carry, as the control resolved it. A zero value
// means nothing was declared, which is the discovery case.
type expectation struct {
	Signer   string
	Issuer   string
	Identity string
	Regexp   string
	// Unmatched is what an image no signer covers is worth, when nothing was declared.
	Unmatched string
	TrustRoot string
}

// declared reports whether the descriptor said who should have signed this.
func (e expectation) declared() bool { return e.Issuer != "" && (e.Identity != "" || e.Regexp != "") }

// expectationFrom reads the control's resolved expectation out of the job config.
func expectationFrom(cfg plugin.Config) expectation {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}
	return expectation{
		Signer:    str("signer"),
		Issuer:    str("issuer"),
		Identity:  str("identity"),
		Regexp:    str("identityRegexp"),
		Unmatched: str("unmatched"),
		TrustRoot: str("trustRoot"),
	}
}

// check runs the verification and turns its outcome into at most one finding, plus what was
// observed about the signature either way.
func (s *cosignVerifier) check(ctx context.Context, ref string, expect expectation) (*sarif.Result, string, error) {
	if !expect.declared() {
		return s.observe(ctx, ref, expect)
	}
	_, stderr, code, err := s.run(ctx, cosignArgs(ref, expect, false))
	// An attestation rather than a signature: cosign exits 1 and names the identity it found in
	// the same breath, so there is nothing to read back. This is the shape a GitHub artifact
	// attestation takes, which makes it the common path rather than the exotic one.
	if code == 1 && attestationIdentityFailed(string(stderr)) {
		return &sarif.Result{
			Tool:     cosignScannerName,
			RuleID:   "provenance-unexpected-identity",
			Level:    sarif.LevelError,
			Score:    9.0,
			HasScore: true,
			Message: fmt.Sprintf("Signed by %s, not %s.",
				withoutHost(sanFrom(string(stderr))), expect.Signer),
		}, "", nil
	}
	switch code {
	case 0:
		return nil, "", nil
	case cosignExitNoMatch, cosignExitNoCertificate:
		// Signed by somebody. Who, comes from a second read rather than from parsing what the
		// first one printed, and it leads the message: a Fulcio identity is around ninety-five
		// characters and the console gives a finding ninety-six, so whatever comes first is what
		// a reader gets. The whole of it travels in the report document.
		observed, _, _ := s.identityOf(ctx, ref, expect)
		return &sarif.Result{
			Tool:     cosignScannerName,
			RuleID:   "provenance-unexpected-identity",
			Level:    sarif.LevelError,
			Score:    9.0,
			HasScore: true,
			// What was found leads, what was expected closes. Both have to survive a console
			// message budget of ninety-six characters, and the identity is seventy of them.
			Message: fmt.Sprintf("Signed by %s, not %s.",
				describeObserved(observed), expect.Signer),
		}, "", nil
	case cosignExitNoSignature, cosignExitNonExistent:
		return &sarif.Result{
			Tool:     cosignScannerName,
			RuleID:   "provenance-unsigned",
			Level:    sarif.LevelError,
			Score:    7.0,
			HasScore: true,
			Message: fmt.Sprintf("Expected %s and found no signature in the registry. Nothing "+
				"connects this image to the build that produced it.", expect.Signer),
		}, "", nil
	}
	return nil, "", fmt.Errorf("cosign: verifying %s: %w", ref, err)
}

// observe reads back whoever signed the image, for a descriptor that has not said who should
// have. Never a pass and never a failure on its own: it reports what is there so somebody can
// decide, which is the step before a policy exists.
func (s *cosignVerifier) observe(ctx context.Context, ref string, expect expectation) (*sarif.Result, string, error) {
	sig, code, err := s.identityOf(ctx, ref, expect)
	switch code {
	case 0:
		// No finding. An image somebody else signed, that this descriptor has not claimed, is not
		// something to fix, and a note per image is how an inventory of fourteen becomes fourteen
		// rows nobody reads. It is recorded instead, where the control accounts for the run.
		if sig.Optional.Subject == "" && sig.Critical.Type != cosignSignatureType {
			// An attestation. Its identity is in the certificate and not in the payload, so it
			// has to be asked for separately; without this the images most likely to carry
			// provenance are the ones discovery says nothing about.
			subject, issuer := s.attestedBy(ctx, ref, expect)
			return nil, observedIdentity(ref, subject, issuer), nil
		}
		return nil, observedNote(ref, sig), nil
	case cosignExitNoSignature, cosignExitNonExistent:
		if expect.Unmatched != unmatchedWarn && expect.Unmatched != unmatchedFail {
			return nil, unsignedNote(ref), nil
		}
		level, score := sarif.LevelWarning, 4.0
		if expect.Unmatched == unmatchedFail {
			level, score = sarif.LevelError, 7.0
		}
		return &sarif.Result{
			Tool:     cosignScannerName,
			RuleID:   "provenance-not-covered",
			Level:    level,
			Score:    score,
			HasScore: true,
			Message:  "No signer covers this image and it carries no signature in the registry.",
		}, unsignedNote(ref), nil
	}
	return nil, "", fmt.Errorf("cosign: reading the signature on %s: %w", ref, err)
}

// The two shapes an observation takes, so the control can tell them apart when it aggregates.
const (
	unsignedMark = "\tunsigned"
)

// attestedBy asks cosign what an attestation is signed by, by refusing an identity it cannot
// carry and reading the one it names instead. Empty when the answer could not be read.
func (s *cosignVerifier) attestedBy(ctx context.Context, ref string, expect expectation) (subject, issuer string) {
	probe := expect
	probe.Identity, probe.Regexp = impossibleIdentity, ""
	probe.Issuer = githubOIDCIssuer
	_, stderr, _, _ := s.run(ctx, cosignArgs(ref, probe, false))
	return sanFrom(string(stderr)), githubOIDCIssuer
}

// githubOIDCIssuer is the issuer every GitHub Actions attestation carries, and the one the probe
// above has to name to get as far as the identity check.
const githubOIDCIssuer = "https://token.actions.githubusercontent.com"

// observedNote records who signed an image, for the control's account of the run.
func observedNote(ref string, sig signature) string {
	return observedIdentity(ref, sig.Optional.Subject, sig.Optional.Issuer)
}

// observedIdentity records one image and who signed it. An unreadable identity is still recorded,
// because an image that carries something is a different fact from one that carries nothing.
func observedIdentity(ref, subject, issuer string) string {
	if subject == "" {
		return ref + "\tsigned, identity not reported\t"
	}
	return ref + "\t" + subject + "\t" + issuer
}

// unsignedNote records that an image carries no signature at all.
func unsignedNote(ref string) string { return ref + unsignedMark }

// signature is the part of cosign's JSON this scanner reads.
type signature struct {
	Critical struct {
		// Type is "cosign container image signature" for a signature, and the predicate URI for
		// an attestation. Which decides whether the identity is in the payload at all.
		Type string `json:"type"`
	} `json:"critical"`
	Optional struct {
		Issuer  string `json:"Issuer"`
		Subject string `json:"Subject"`
	} `json:"optional"`
}

// cosignSignatureType is what cosign calls its own signature. Anything else in that field is a
// predicate URI, which means the artifact carries an attestation rather than a bare signature.
const cosignSignatureType = "cosign container image signature"

// impossibleIdentity is a value no Fulcio certificate can carry, used to ask cosign what an
// attestation *is* signed by.
//
// An attestation's identity is not in the payload cosign prints: a permissive read of one
// succeeds with an empty `optional` block, so discovery would report nothing about the images
// most likely to have provenance. Refusing a specific identity is the one channel cosign offers,
// and its refusal names what it found instead. A space cannot appear in a SAN URI, so nothing
// real collides with it, and a message that stops reporting the identity leaves discovery saying
// so rather than saying something wrong.
const impossibleIdentity = "draugr asked what this is signed by"

// identityOf reads back who signed, with an identity pattern that matches anything.
//
// The pattern is why this is a separate method with a name that says what it does. cosign refuses
// a keyless verification with no identity at all, so reading one back means asking for any, and a
// call that accepts any signature must never be mistaken for a call that checked one.
func (s *cosignVerifier) identityOf(ctx context.Context, ref string, expect expectation) (signature, int, error) {
	out, _, code, err := s.run(ctx, cosignArgs(ref, expect, true))
	if code != 0 {
		return signature{}, code, err
	}
	var sigs []signature
	if err := json.Unmarshal(out, &sigs); err != nil || len(sigs) == 0 {
		return signature{}, code, fmt.Errorf("cosign: reading the signature on %s: %w", ref, err)
	}
	return sigs[0], 0, nil
}

// attestationIdentityFailed reports whether cosign refused an attestation because the identity on
// it was not the expected one, as distinct from every other reason it exits 1.
func attestationIdentityFailed(said string) bool {
	return strings.Contains(said, cosignAttestationNoMatch) &&
		strings.Contains(said, cosignIdentityFailed)
}

// sanFrom pulls the identity cosign found out of the sentence it refused with. An empty result
// leaves the finding saying the identity could not be read, which is true and better than a guess.
func sanFrom(said string) string {
	_, rest, ok := strings.Cut(said, cosignFoundSAN)
	if !ok {
		return ""
	}
	got, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return ""
	}
	return got
}

// cosignArgs builds the command. `readBack` swaps the declared identity for a pattern that
// matches anything, which is how an unknown signer is read and never how one is verified.
func cosignArgs(ref string, expect expectation, readBack bool) []string {
	argv := []string{"cosign", "verify", "--output", "json"}
	switch {
	case readBack:
		argv = append(argv, "--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*")
	case expect.Identity != "":
		argv = append(argv, "--certificate-identity", expect.Identity,
			"--certificate-oidc-issuer", expect.Issuer)
	default:
		argv = append(argv, "--certificate-identity-regexp", expect.Regexp,
			"--certificate-oidc-issuer", expect.Issuer)
	}
	if expect.TrustRoot != "" {
		argv = append(argv, "--trusted-root", expect.TrustRoot)
	}
	// --insecure-ignore-tlog is never passed. Without the log there is nothing to say the
	// certificate was valid when it signed rather than valid now, and a short-lived certificate
	// is the whole design.
	return append(argv, ref)
}

// cosignRef prefers the digest, and reports which it used.
//
// A tag can be repointed after the check, so verifying one says less than verifying a digest. It
// still says a great deal more than not looking, and refusing would withhold the control from the
// descriptors most likely to carry an unexpected signer. What it cannot do is go unsaid, which is
// what the second result is for.
func cosignRef(img plugin.ImageTarget) (string, bool) {
	if img.Digest != "" {
		repo, _, _ := strings.Cut(img.Ref, "@")
		repo, _, _ = cutTag(repo)
		if repo == "" {
			return "", false
		}
		return repo + "@" + img.Digest, true
	}
	return img.Ref, false
}

// cutTag removes a trailing `:tag`, leaving a registry port alone.
func cutTag(ref string) (string, string, bool) {
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:], true
	}
	return ref, "", false
}

// cosignFields records what this job was measured against: who was expected, and whether the
// image was named in a way that pins it.
func cosignFields(expect expectation, byDigest bool, ref, observed string) []sarif.Field {
	who := "no signer declared"
	if expect.declared() {
		who = expect.Signer
	}
	pinned := "tag"
	if byDigest {
		pinned = "digest"
	}
	fields := []sarif.Field{{Key: "signer", Value: who}, {Key: "pinned", Value: pinned}}
	if observed != "" {
		fields = append(fields, sarif.Field{Key: "observed", Value: observed})
	}
	_ = ref
	return fields
}

// describeObserved names who actually signed, or says that could not be read.
//
// Without its scheme and host, because the console gives a finding's message ninety-six
// characters and a Fulcio identity spends the first nineteen on `https://github.com/` before it
// says anything that distinguishes one signer from another. What is left, the repository, the
// workflow and the ref, is the part a reader is trying to compare against what they expected, and
// it fits. The identity in full is in the control's account of the run and in the report document.
func describeObserved(sig signature) string {
	return withoutHost(sig.Optional.Subject)
}

// withoutHost drops a leading scheme and host from an identity URI, and leaves anything that is
// not one alone: an email address and a SPIFFE ID are both valid Fulcio subjects.
func withoutHost(subject string) string {
	if subject == "" {
		return "a workload whose identity could not be read"
	}
	rest, ok := strings.CutPrefix(subject, "https://")
	if !ok {
		return subject
	}
	_, path, ok := strings.Cut(rest, "/")
	if !ok {
		return subject
	}
	return path
}

// runCosign executes cosign and separates the exit code from a failure to run it at all.
func runCosign(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	out, err := toolexec.Run(ctx, "", argv)
	if err == nil {
		return out, nil, 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// exit.Stderr rather than the wrapped message: the message is one shortened line, and the
		// identity cosign found sits at the end of a long one.
		return out, exit.Stderr, exit.ExitCode(), err
	}
	// Not a failed verification: cosign could not be started. Code -1 falls through every case
	// that means something, so the caller reports it rather than reading it as a result.
	return out, nil, -1, err
}
