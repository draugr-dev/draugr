package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// trustStoreFile writes a stand-in for the roots a descriptor would name. Its contents are copied
// verbatim, so what they are does not matter to this scanner.
func trustStoreFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nnot a real one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubNotation replaces the exec with a scripted answer, and records the argv and environment.
func stubNotation(t *testing.T, out string, err error) (*notationVerifier, *[]string, *[]string) {
	t.Helper()
	s, _ := NewNotation().(*notationVerifier)
	var argv, env []string
	s.run = func(_ context.Context, a, e []string) ([]byte, error) {
		argv, env = a, e
		return []byte(out), err
	}
	return s, &argv, &env
}

func notationCfg(t *testing.T) plugin.Config {
	return plugin.Config{
		"signer": "acme-pki", "trustStore": trustStoreFile(t),
		"subject": "C=US, ST=WA, O=Acme, CN=Acme Release Signing",
	}
}

func notationScan(t *testing.T, s *notationVerifier, cfg plugin.Config) (sarif.Report, error) {
	t.Helper()
	return s.Scan(context.Background(), plugin.ImageTarget{
		Ref: "acme.azurecr.io/payments:1.0", Digest: "sha256:abc",
	}, cfg)
}

func TestNotationVerifiedProducesNoFinding(t *testing.T) {
	s, argv, env := stubNotation(t, "Successfully verified signature", nil)
	rep, err := notationScan(t, s, notationCfg(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Errorf("a verified image should produce no finding, got %v", rep.Results)
	}
	// By digest, because that is what makes the check reproducible.
	if got := strings.Join(*argv, " "); !strings.Contains(got, "acme.azurecr.io/payments@sha256:abc") {
		t.Errorf("argv = %v, want the digest", *argv)
	}
	if len(*env) != 1 || !strings.HasPrefix((*env)[0], "NOTATION_CONFIG=") {
		t.Errorf("env = %v, want the generated config directory", *env)
	}
}

// notation exits 1 for everything, so the message is what tells the outcomes apart. Each string
// below was taken from notation 1.3.2 rather than written from its documentation.
func TestNotationClassifiesWhatItWasTold(t *testing.T) {
	cases := []struct {
		name     string
		said     string
		wantRule string
		wantErr  string
	}{
		{"unsigned",
			`Error: signature verification failed: no signature is associated with "acme.azurecr.io/payments@sha256:abc", make sure the artifact was signed successfully`,
			"provenance-unsigned", ""},
		{"a certificate we do not trust",
			"Error: signature verification failed: signing certificate from the digital signature does not match the X.509 trusted identities [map[CN:Acme]] defined in the trust policy",
			"provenance-unexpected-identity", ""},
		// Draugr writes the policy itself, scoped to the image in front of it, so this says the
		// scope did not match the reference it was built from. That is a fault here, not a
		// finding about somebody's artifact.
		{"a scope that did not match",
			`Error: signature verification failed: artifact "acme.azurecr.io/payments@sha256:abc" has no applicable trust policy statement`,
			"", "does not cover"},
		// The row that matters. A registry nobody could reach must not read as unsigned.
		{"a registry it could not reach",
			"Error: unable to resolve the reference: dial tcp: lookup acme.azurecr.io: no such host",
			"", "verifying"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := stubNotation(t, c.said, errors.New("exit status 1"))
			rep, err := notationScan(t, s, notationCfg(t))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Results) != 1 || rep.Results[0].RuleID != c.wantRule {
				t.Fatalf("results = %v, want one %s", rep.Results, c.wantRule)
			}
		})
	}
}

// The policy is the whole check: its scope decides which image it governs, and its trusted
// identity decides who may have signed. A policy built wrong verifies something else, or anybody.
func TestNotationWritesAPolicyScopedToTheImage(t *testing.T) {
	roots := trustStoreFile(t)
	dir, err := writeNotationConfig("acme.azurecr.io/payments@sha256:abc", "acme pki", roots, "CN=Acme")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// #nosec G304 -- dir is the temporary directory this test just asked the scanner to write.
	raw, err := os.ReadFile(filepath.Join(dir, "trustpolicy.json"))
	if err != nil {
		t.Fatalf("notation 1.3.2 reads trustpolicy.json: %v", err)
	}
	var doc struct {
		TrustPolicies []struct {
			RegistryScopes        []string `json:"registryScopes"`
			TrustStores           []string `json:"trustStores"`
			TrustedIdentities     []string `json:"trustedIdentities"`
			SignatureVerification struct {
				Level string `json:"level"`
			} `json:"signatureVerification"`
		} `json:"trustPolicies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.TrustPolicies) != 1 {
		t.Fatalf("want one policy, got %d", len(doc.TrustPolicies))
	}
	p := doc.TrustPolicies[0]
	if len(p.RegistryScopes) != 1 || p.RegistryScopes[0] != "acme.azurecr.io/payments" {
		t.Errorf("scope = %v, want only the repository being verified", p.RegistryScopes)
	}
	if p.SignatureVerification.Level != "strict" {
		t.Errorf("level = %q, want strict", p.SignatureVerification.Level)
	}
	if len(p.TrustedIdentities) != 1 || p.TrustedIdentities[0] != "x509.subject: CN=Acme" {
		t.Errorf("trustedIdentities = %v; a wildcard here would accept any certificate from the authority", p.TrustedIdentities)
	}
	// The store name reaches a filesystem path, so it is made safe and the policy agrees with it.
	if len(p.TrustStores) != 1 || p.TrustStores[0] != "ca:acme-pki" {
		t.Errorf("trustStores = %v", p.TrustStores)
	}
	if _, err := os.Stat(filepath.Join(dir, "truststore", "x509", "ca", "acme-pki", "roots.crt")); err != nil {
		t.Errorf("the roots should be where the policy says they are: %v", err)
	}
}

// A trust decision must not outlive the run that made it, and two concurrent scans must not write
// each other's policy.
func TestNotationRemovesItsConfigAfterwards(t *testing.T) {
	s, _, env := stubNotation(t, "verified", nil)
	if _, err := notationScan(t, s, notationCfg(t)); err != nil {
		t.Fatal(err)
	}
	dir := strings.TrimPrefix((*env)[0], "NOTATION_CONFIG=")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the generated config directory should be gone, %s still exists", dir)
	}
}

// Reaching this scanner without both halves means the control and the scanner disagree. Verifying
// against a policy built from nothing would trust any certificate and report a pass.
func TestNotationRefusesAnIncompleteExpectation(t *testing.T) {
	for _, cfg := range []plugin.Config{
		{"signer": "acme-pki", "subject": "CN=Acme"},
		{"signer": "acme-pki", "trustStore": "roots.pem"},
		{},
	} {
		s, _, _ := stubNotation(t, "", nil)
		if _, err := notationScan(t, s, cfg); err == nil {
			t.Errorf("cfg %v was accepted and would have trusted anything", cfg)
		}
	}
}

func TestNotationReportsAnUnreadableTrustStore(t *testing.T) {
	s, _, _ := stubNotation(t, "", nil)
	_, err := notationScan(t, s, plugin.Config{
		"signer": "acme-pki", "trustStore": "/nonexistent/roots.pem", "subject": "CN=Acme",
	})
	if err == nil || !strings.Contains(err.Error(), "trust store") {
		t.Errorf("err = %v, want it to name the trust store", err)
	}
}

func TestNotationRefusesANonImageTarget(t *testing.T) {
	s, _, _ := stubNotation(t, "", nil)
	_, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: "https://example.com/x.git"}, notationCfg(t))
	if err == nil || !strings.Contains(err.Error(), "image target") {
		t.Errorf("err = %v", err)
	}
}

func TestNotationStoreNameIsSafeAsAPath(t *testing.T) {
	cases := map[string]string{
		"acme-pki": "acme-pki", "acme pki": "acme-pki", "../escape": "---escape", "": "signer",
	}
	for in, want := range cases {
		if got := notationStoreName(in); got != want {
			t.Errorf("notationStoreName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNotationInfoDeclaresWhatItSendsAndReads(t *testing.T) {
	info := NewNotation().Info()
	if info.Binary != "notation" {
		t.Errorf("binary = %q", info.Binary)
	}
	// Nothing: trust comes from certificates the descriptor names, not from a log or a database.
	if len(info.Data) != 0 {
		t.Errorf("data = %v, want none", info.Data)
	}
	var discloses bool
	for _, e := range info.Effects {
		if e.Kind == plugin.EffectDisclosure {
			discloses = true
		}
	}
	if !discloses {
		t.Error("digests reach the registry, which is a disclosure")
	}
}
