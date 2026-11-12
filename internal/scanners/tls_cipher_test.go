package scanners

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// refusal is the error a handshake returns when the server answers with a handshake_failure alert.
func refusal() error {
	return &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}
}

// refusingProbe refuses every handshake with the server's alert.
func refusingProbe(context.Context, string, string, uint16, uint16) (tls.ConnectionState, error) {
	return tls.ConnectionState{}, refusal()
}

// A server that refuses the current cipher suites and accepts an old one is a finding naming the
// suite and what is wrong with it, with the certificate still checked, and the control fails
// rather than reporting a target it could not reach.
func TestAServerAcceptingOnlyALegacySuiteIsAFinding(t *testing.T) {
	cert := makeCert(t, testNow.Add(5*24*time.Hour), x509.SHA256WithRSA, rsaKey(t, 2048))
	for _, c := range []struct {
		suite uint16
		says  string
	}{
		{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "RC4 has practical attacks that recover plaintext, and RFC 7465 prohibits it. The server accepts no suite a current client offers, and negotiated TLS_ECDHE_RSA_WITH_RC4_128_SHA."},
		{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "Sweet32"},
		{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "no forward secrecy"},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "Lucky13"},
		{tls.TLS_RSA_WITH_AES_128_CBC_SHA, "no forward secrecy"},
	} {
		s := newTestScanner(refusingProbe)
		s.probeLegacySuites = func(context.Context, string, string) (tls.ConnectionState, error) {
			return tls.ConnectionState{CipherSuite: c.suite, PeerCertificates: []*x509.Certificate{cert}}, nil
		}
		rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://rc4.example.test"}, nil)
		if err != nil {
			t.Fatalf("%s: a server refusing the current suites is a finding, not an error: %v", tls.CipherSuiteName(c.suite), err)
		}
		if !hasRule(rep, "tls-legacy-cipher-only") || !hasRule(rep, "tls-cert-expiring") {
			t.Fatalf("%s: rules = %v, want the cipher finding and the certificate checked", tls.CipherSuiteName(c.suite), ruleIDs(rep))
		}
		for _, r := range rep.Results {
			if r.RuleID == "tls-legacy-cipher-only" && !strings.Contains(r.Message, c.says) {
				t.Errorf("message = %q, want %q", r.Message, c.says)
			}
		}
	}
}

// A server that refuses every suite Go implements accepts only suites outside them, which is a
// finding too. A server that resets the connection, or a legacy probe that fails for another reason,
// stays an error: neither says anything about ciphers.
func TestAServerRefusingEverySuiteIsAFindingAndAResetIsNot(t *testing.T) {
	s := newTestScanner(refusingProbe)
	s.probeLegacySuites = func(context.Context, string, string) (tls.ConnectionState, error) {
		return tls.ConnectionState{}, refusal()
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://dh480.example.test"}, nil)
	if err != nil || len(rep.Results) != 1 || rep.Results[0].RuleID != "tls-no-shared-cipher" {
		t.Fatalf("rep = %v, err = %v, want one tls-no-shared-cipher", ruleIDs(rep), err)
	}

	reset := newTestScanner(func(context.Context, string, string, uint16, uint16) (tls.ConnectionState, error) {
		return tls.ConnectionState{}, &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}
	})
	if _, err := reset.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil); err == nil {
		t.Error("a reset connection is an unreached target, not a finding")
	}

	s.probeLegacySuites = func(context.Context, string, string) (tls.ConnectionState, error) {
		return tls.ConnectionState{}, errors.New("i/o timeout")
	}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil); err == nil {
		t.Error("a legacy probe that timed out says nothing about ciphers and is an error")
	}

	s.probeLegacySuites = nil
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil); err == nil {
		t.Error("with no legacy probe a refusal stays an error")
	}
}

// refusedSuites reads the alert a real server sends when it shares no suite with the client, the
// shape a handshake against such a server returns, and nothing else.
func TestRefusedSuitesReadsARealServersAlert(t *testing.T) {
	cert := selfSignedPair(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}, // #nosec G402 -- a server offering only RC4 is the case under test
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = dialTLS(ctx, ln.Addr().String(), "localhost", tls.VersionTLS12, tls.VersionTLS13)
	if !refusedSuites(err) {
		t.Fatalf("default suites against an RC4-only server: %v, want the server's handshake_failure alert", err)
	}
	// Offered every suite Go implements, the client agrees RC4 with the server and completes the
	// handshake. The probe does not verify, so the self-signed certificate does not stop it, and the
	// chain comes back to be judged apart.
	state, err := dialTLSLegacySuites(ctx, ln.Addr().String(), "localhost")
	if err != nil || state.CipherSuite != tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA || len(state.PeerCertificates) != 1 {
		t.Fatalf("every suite against an RC4-only server: suite %s, %d certificates, %v; want RC4 and the certificate",
			tls.CipherSuiteName(state.CipherSuite), len(state.PeerCertificates), err)
	}
	if refusedSuites(errors.New("tls: handshake failure")) || refusedSuites(nil) {
		t.Error("only the server's alert is a refusal")
	}
}

// selfSignedPair is an RSA certificate and key for a test server, valid for localhost.
func selfSignedPair(t *testing.T) tls.Certificate {
	t.Helper()
	key := rsaKey(t, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A handshake can fail after the certificate has arrived, on a key Go refuses to use, say. What the
// server presented is then the finding, not a cipher problem and not a scan error.
func TestAHandshakeFailingAfterTheCertificateReportsTheCertificate(t *testing.T) {
	cert := makeCert(t, testNow.Add(90*24*time.Hour), x509.SHA256WithRSA, rsaKey(t, 1024))
	received := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	s := newTestScanner(func(_ context.Context, _, _ string, minVer, _ uint16) (tls.ConnectionState, error) {
		if minVer == tls.VersionTLS10 {
			return received, errors.New("crypto/rsa: 1024-bit keys are insecure")
		}
		return tls.ConnectionState{}, refusal()
	})
	s.probeLegacySuites = func(context.Context, string, string) (tls.ConnectionState, error) {
		return received, refusal()
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://rsa1024.example.test"}, nil)
	if err != nil || len(rep.Results) != 1 || rep.Results[0].RuleID != "tls-weak-key" {
		t.Fatalf("rep = %v, err = %v, want one tls-weak-key", ruleIDs(rep), err)
	}
}
