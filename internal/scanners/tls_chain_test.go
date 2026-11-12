package scanners

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// issue signs a certificate for subject with the issuer's key, or itself when issuer is nil.
func issue(t *testing.T, serial int64, subject string, dns []string, sigAlg x509.SignatureAlgorithm, isCA bool,
	issuer *x509.Certificate, issuerKey any) (*x509.Certificate, any) {
	t.Helper()
	key := rsaKey(t, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: subject},
		DNSNames:              dns,
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(90 * 24 * time.Hour),
		SignatureAlgorithm:    sigAlg,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	parent, signer := tmpl, any(key)
	if issuer != nil {
		parent, signer = issuer, issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// scanChain scans a host that accepts TLS 1.2 and 1.3 and presents chain, with verification stubbed
// to verifyErr.
func scanChain(t *testing.T, url string, chain []*x509.Certificate, verifyErr error) map[string]string {
	t.Helper()
	s := newTestScanner(probeFunc(tls.ConnectionState{PeerCertificates: chain}, tls.VersionTLS13))
	s.verify = func([]*x509.Certificate, time.Time) error { return verifyErr }
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: url}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.RuleID] += r.Message
	}
	return got
}

// Each property of a chain is a finding of its own kind, read from the chain whether or not it
// verifies: a reader fixing a SHA-1 intermediate needs to be told the intermediate, not that the
// chain is untrusted.
func TestAChainIsReadForWhatItIs(t *testing.T) {
	root, rootKey := issue(t, 1, "Test Root", nil, x509.SHA256WithRSA, true, nil, nil)
	sha1Inter, sha1InterKey := issue(t, 2, "SHA-1 Intermediate", nil, x509.SHA1WithRSA, true, root, rootKey)
	leaf, _ := issue(t, 3, "www.example.test", []string{"www.example.test"}, x509.SHA256WithRSA, false, sha1Inter, sha1InterKey)
	noSAN, _ := issue(t, 4, "www.example.test", nil, x509.SHA256WithRSA, false, root, rootKey)
	good, _ := issue(t, 5, "www.example.test", []string{"www.example.test"}, x509.SHA256WithRSA, false, root, rootKey)

	t.Run("a SHA-1 intermediate", func(t *testing.T) {
		got := scanChain(t, "https://www.example.test", []*x509.Certificate{leaf, sha1Inter, root}, nil)
		if !strings.Contains(got["tls-weak-cert-signature"], "Intermediate certificate 1 (SHA-1 Intermediate)") {
			t.Errorf("got %v, want the SHA-1 intermediate named", got)
		}
		if _, ok := got["tls-cert-chain-order"]; ok {
			t.Errorf("an ordered chain reported out of order: %v", got)
		}
	})
	t.Run("no SAN", func(t *testing.T) {
		got := scanChain(t, "https://www.example.test", []*x509.Certificate{noSAN}, nil)
		if _, ok := got["tls-cert-no-san"]; !ok {
			t.Errorf("got %v, want tls-cert-no-san", got)
		}
		if _, ok := got["tls-cert-hostname-mismatch"]; ok {
			t.Errorf("a missing SAN is reported once, as itself: %v", got)
		}
	})
	t.Run("out of order", func(t *testing.T) {
		got := scanChain(t, "https://www.example.test", []*x509.Certificate{leaf, root, sha1Inter}, nil)
		if !strings.Contains(got["tls-cert-chain-order"], "certificate 0 (www.example.test)") {
			t.Errorf("got %v, want the chain order reported at the leaf", got)
		}
	})
	t.Run("untrusted and for another host", func(t *testing.T) {
		got := scanChain(t, "https://api.example.test", []*x509.Certificate{good}, x509.UnknownAuthorityError{})
		_, untrusted := got["tls-cert-untrusted"]
		_, mismatch := got["tls-cert-hostname-mismatch"]
		if !untrusted || !mismatch {
			t.Errorf("got %v, want both, since each needs its own fix", got)
		}
	})
	t.Run("expired, once", func(t *testing.T) {
		expired := makeCert(t, testNow.Add(-time.Hour), x509.SHA256WithRSA, rsaKey(t, 2048))
		got := scanChain(t, "https://example.test", []*x509.Certificate{expired},
			x509.CertificateInvalidError{Cert: expired, Reason: x509.Expired})
		if len(got) != 1 || !strings.Contains(got["tls-cert-expired"], "expired on") {
			t.Errorf("got %v, want one tls-cert-expired with its date", got)
		}
	})
	t.Run("a sound chain", func(t *testing.T) {
		if got := scanChain(t, "https://www.example.test", []*x509.Certificate{good, root}, nil); len(got) != 0 {
			t.Errorf("got %v, want nothing", got)
		}
	})
}

// verifyChain verifies against the given time and offers the rest of the chain as intermediates.
func TestVerifyChain(t *testing.T) {
	root, rootKey := issue(t, 1, "Test Root", nil, x509.SHA256WithRSA, true, nil, nil)
	leaf, _ := issue(t, 2, "www.example.test", []string{"www.example.test"}, x509.SHA256WithRSA, false, root, rootKey)
	var unknown x509.UnknownAuthorityError
	if err := verifyChain([]*x509.Certificate{leaf, root}, testNow); !errors.As(err, &unknown) {
		t.Errorf("a chain to a root nobody trusts: %v, want UnknownAuthorityError", err)
	}
}

// End to end against a real server: a self-signed certificate that accepts TLS 1.0 to 1.2. The
// certificate is reported, and so are the protocols, which a verifying handshake never reached.
func TestARealServerWithAnUntrustedCertificateHasItsProtocolsTested(t *testing.T) {
	cert := selfSignedPair(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10, // #nosec G402 -- a server accepting TLS 1.0 is the case under test
		MaxVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	_, port, _ := strings.Cut(ln.Addr().String(), ":")
	s := NewTLSProbe().(draugrTLSScanner)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := s.Scan(ctx, plugin.HostTarget{URL: "https://localhost:" + port}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, want := range []string{"tls-cert-untrusted", "tls-deprecated-protocol", "tls-no-tls13"} {
		if !hasRule(rep, want) {
			t.Errorf("want %s, got %v", want, ruleIDs(rep))
		}
	}
	if hasRule(rep, "tls-cert-hostname-mismatch") {
		t.Errorf("the certificate names localhost: %v", ruleIDs(rep))
	}
}

// A chain to a trusted root whose leaf is signed with SHA-1 fails Go's verifier only because Go
// refuses the algorithm. The finding is the weak signature, by name, and not an untrusted chain,
// which would send the reader looking for a missing CA. A SHA-1 leaf from a root nobody trusts is
// still untrusted.
func TestARefusedAlgorithmIsTheSignatureFindingNotAnUntrustedChain(t *testing.T) {
	root, rootKey := issue(t, 1, "Test Root", nil, x509.SHA256WithRSA, true, nil, nil)
	leaf, _ := issue(t, 2, "www.example.test", []string{"www.example.test"}, x509.SHA1WithRSA, false, root, rootKey)
	trusted := x509.NewCertPool()
	trusted.AddCert(root)
	other, _ := issue(t, 3, "Other Root", nil, x509.SHA256WithRSA, true, nil, nil)
	elsewhere := x509.NewCertPool()
	elsewhere.AddCert(other)

	for name, tc := range map[string]struct {
		roots         *x509.CertPool
		wantUntrusted bool
	}{
		"trusted root": {trusted, false},
		"no root":      {elsewhere, true},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestScanner(probeFunc(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, tls.VersionTLS13))
			s.verify = func(c []*x509.Certificate, now time.Time) error { return verifyChainAgainst(c, now, tc.roots) }
			rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://www.example.test"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !hasRule(rep, "tls-weak-cert-signature") || hasRule(rep, "tls-cert-untrusted") != tc.wantUntrusted {
				t.Errorf("got %v, want the weak signature, and untrusted %v", ruleIDs(rep), tc.wantUntrusted)
			}
		})
	}
}

// A server that refuses the TLS 1.2+ handshake and accepts TLS 1.0, with an MD5- or SHA-1-signed
// leaf (SHA-1 here, since Go will not sign with MD5), may
// speak TLS 1.2 to a client that offers a signature scheme for that certificate. The refusal is
// told on the signature finding, and the server is not reported as stuck on old versions.
func TestARefusalAWeakLeafExplainsIsNotReportedAsOldVersionsOnly(t *testing.T) {
	weakLeaf := makeCert(t, testNow.Add(90*24*time.Hour), x509.SHA1WithRSA, rsaKey(t, 2048))
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{weakLeaf}}
	s := newTestScanner(func(_ context.Context, _, _ string, minVer, _ uint16) (tls.ConnectionState, error) {
		if minVer <= tls.VersionTLS11 {
			return state, nil
		}
		return tls.ConnectionState{}, refusal()
	})
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://md5.example.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(rep, "tls-modern-unsupported") || !hasRule(rep, "tls-deprecated-protocol") {
		t.Fatalf("got %v, want TLS 1.0 and 1.1 reported and no claim the server lacks TLS 1.2", ruleIDs(rep))
	}
	for _, r := range rep.Results {
		if r.RuleID == "tls-weak-cert-signature" && !strings.Contains(r.Message, "TLS 1.2 handshake with this server failed") {
			t.Errorf("the signature finding should say the refusal is likely its doing: %q", r.Message)
		}
	}
}
