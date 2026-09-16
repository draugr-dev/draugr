package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// notationScannerName is the scanner's name in the registry and in a descriptor.
const notationScannerName = "notation"

// What notation says when verification fails, observed against notation 1.3.2.
//
// Matched on the message rather than the exit code, because notation exits 1 for everything: a
// missing signature, a wrong certificate and a registry it could not reach are one code. So the
// two outcomes that mean something are recognized by what it said, and everything else is an
// error this control reports rather than a result. A message that changes wording upstream turns
// a finding into an error, which is the direction a security control should fail in.
const (
	notationUnsigned = "no signature is associated with"
	notationMismatch = "does not match the X.509 trusted identities"
	notationNoPolicy = "has no applicable trust policy statement"
)

// notationConfigSchema is the JSON Schema for the job config this scanner receives. Every key is
// written by the control; see the cosign scanner for why they are declared and read-only.
const notationConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "signer": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the name of the signer covering this image."
    },
    "trustStore": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the PEM file of roots the certificate must chain to."
    },
    "subject": {
      "type": "string",
      "readOnly": true,
      "description": "Set by the control: the certificate subject the signature must carry."
    }
  }
}`

// notationVerifier checks that a container image carries a Notary Project signature from a
// certificate the descriptor trusts. It serves the "provenance" control.
//
// The X.509 half of that control. Sigstore identifies a signer by a short-lived certificate tied
// to a workload; this identifies one by a certificate chaining to roots somebody holds. Azure
// Pipelines signs this way with a key in Azure Key Vault, and so does any organization with its
// own authority.
//
// notation takes its trust policy and trust store from a configuration directory rather than from
// flags, so Draugr writes one per job from what the descriptor declared. Generated rather than
// asked for, because a policy file beside the descriptor would be a second place to state who may
// sign, and two places that must agree are one place that drifts.
type notationVerifier struct {
	info plugin.ScannerInfo
	// run executes notation with an environment, and returns its combined output. Injected so
	// tests need neither the binary nor a registry.
	run func(ctx context.Context, argv, env []string) ([]byte, error)
}

// NewNotation returns the Notary Project verification scanner.
func NewNotation() plugin.Scanner {
	return &notationVerifier{
		info: plugin.ScannerInfo{
			Name:         notationScannerName,
			Binary:       "notation",
			Origin:       "notaryproject",
			Controls:     []string{"provenance"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
			ConfigSchema: json.RawMessage(notationConfigSchema),
			Effects: []plugin.Effect{{
				Kind: plugin.EffectDisclosure,
				Detail: "the digest of each image checked, to the registry holding it. No " +
					"transparency log is involved: a Notary Project signature is verified against " +
					"certificates on this machine",
			}},
		},
		run: runNotation,
	}
}

// Info identifies the scanner.
func (s *notationVerifier) Info() plugin.ScannerInfo { return s.info }

// Scan verifies one image against the certificate the control resolved for it.
func (s *notationVerifier) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("notation: expected an image target, got %s", target.Kind())
	}
	str := func(key string) string { v, _ := cfg[key].(string); return v }
	signer, trustStore, subject := str("signer"), str("trustStore"), str("subject")
	if trustStore == "" || subject == "" {
		// The control only routes an image here when its signer declared both, so reaching this
		// means the two disagree. Refusing beats verifying against a policy built from nothing,
		// which would trust any certificate and report a pass.
		return sarif.Report{}, fmt.Errorf(
			"notation: %s has no trust store or subject to check against; this scanner runs only for an x509 signer", img.Ref)
	}
	ref, byDigest := cosignRef(img)
	if ref == "" {
		return sarif.Report{}, fmt.Errorf("notation: %s has neither a reference nor a digest", img.Ref)
	}

	dir, err := writeNotationConfig(ref, signer, trustStore, subject)
	if err != nil {
		return sarif.Report{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	report := sarif.Report{Tool: notationScannerName}
	report.Provenance = []sarif.Provenance{{
		Tool:   notationScannerName,
		Fields: cosignFields(expectation{Signer: signer, Identity: subject, Issuer: trustStore}, byDigest, img.Ref, ""),
	}}

	out, runErr := s.run(ctx, []string{"notation", "verify", ref}, []string{"NOTATION_CONFIG=" + dir})
	if runErr == nil {
		return report, nil
	}
	said := string(out) + " " + runErr.Error()
	switch {
	case strings.Contains(said, notationMismatch):
		report.Results = []sarif.Result{{
			Tool:     notationScannerName,
			RuleID:   "provenance-unexpected-identity",
			Level:    sarif.LevelError,
			Score:    9.0,
			HasScore: true,
			Location: sarif.Location{URI: img.Ref},
			Message: fmt.Sprintf("Signed by a certificate that is not %s. The artifact is signed, "+
				"by an identity this descriptor does not name.", signer),
		}}
		return report, nil
	case strings.Contains(said, notationUnsigned):
		report.Results = []sarif.Result{{
			Tool:     notationScannerName,
			RuleID:   "provenance-unsigned",
			Level:    sarif.LevelError,
			Score:    7.0,
			HasScore: true,
			Location: sarif.Location{URI: img.Ref},
			Message: fmt.Sprintf("Expected %s and found no signature in the registry. Nothing "+
				"connects this image to the build that produced it.", signer),
		}}
		return report, nil
	case strings.Contains(said, notationNoPolicy):
		// The policy is Draugr's own, written one line above and scoped to this image. Reaching
		// here means the scope did not match the reference it was built from, which is a fault in
		// this scanner rather than anything the descriptor said.
		return sarif.Report{}, fmt.Errorf(
			"notation: the trust policy Draugr wrote does not cover %s, so nothing was checked", ref)
	}
	return sarif.Report{}, fmt.Errorf("notation: verifying %s: %w", ref, runErr)
}

// writeNotationConfig builds the configuration directory notation reads: a trust policy scoped to
// this image, and a trust store holding the roots the descriptor named.
//
// Per job and removed afterwards. A shared directory would have concurrent scans writing one
// another's policy, and a policy left behind is a trust decision outliving the run that made it.
func writeNotationConfig(ref, signer, trustStore, subject string) (string, error) {
	roots, err := os.ReadFile(trustStore) // #nosec G304 -- a path the descriptor names, by design
	if err != nil {
		return "", fmt.Errorf("notation: reading the trust store for signer %q: %w", signer, err)
	}
	dir, err := os.MkdirTemp("", "draugr-notation-")
	if err != nil {
		return "", fmt.Errorf("notation: %w", err)
	}
	store := filepath.Join(dir, "truststore", "x509", "ca", notationStoreName(signer))
	if err := os.MkdirAll(store, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("notation: %w", err)
	}
	// #nosec G703 -- store is MkdirTemp plus notationStoreName, which maps everything outside
	// [A-Za-z0-9_-] to a dash, so no component of it comes through from the descriptor intact.
	if err := os.WriteFile(filepath.Join(store, "roots.crt"), roots, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("notation: %w", err)
	}
	policy := map[string]any{
		"version": "1.0",
		"trustPolicies": []any{map[string]any{
			"name": notationStoreName(signer),
			// Scoped to the repository this job is verifying and nothing else, so a policy written
			// for one image cannot decide another.
			"registryScopes":        []string{notationScope(ref)},
			"signatureVerification": map[string]any{"level": "strict"},
			"trustStores":           []string{"ca:" + notationStoreName(signer)},
			"trustedIdentities":     []string{"x509.subject: " + subject},
		}},
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("notation: %w", err)
	}
	// trustpolicy.json rather than trustpolicy.oci.json: 1.3.2 writes and reads the former, and
	// later versions still accept it.
	if err := os.WriteFile(filepath.Join(dir, "trustpolicy.json"), encoded, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("notation: %w", err)
	}
	return dir, nil
}

// notationScope is the repository part of a reference, which is what a trust policy is scoped by.
func notationScope(ref string) string {
	repo, _, _ := strings.Cut(ref, "@")
	repo, _, _ = cutTag(repo)
	return repo
}

// notationStoreName makes a signer's name safe as a directory and a policy name: notation reads
// the trust store from a path built out of it.
func notationStoreName(signer string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, signer)
	if safe == "" {
		return "signer"
	}
	return safe
}

// runNotation executes notation with the configuration directory this job wrote.
//
// Combined output, because notation writes what went wrong to stderr and the classification above
// reads it. There is no report on stdout to corrupt: the answer is the exit status and the
// sentence beside it.
func runNotation(ctx context.Context, argv, env []string) ([]byte, error) {
	return toolexec.RunCombinedWithEnv(ctx, "", argv, env)
}
