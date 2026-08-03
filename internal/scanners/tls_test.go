package scanners

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

var testNow = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)

// defaultThresholds is the zero-config expiry window (no Saga overrides).
func defaultThresholds() expiryThresholds { return thresholdsFrom(nil) }

// makeCert builds a self-signed certificate for tests. notAfter sets expiry; sigAlg and key
// control the signature/key strength checks.
func makeCert(t *testing.T, notAfter time.Time, sigAlg x509.SignatureAlgorithm, key any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "example.test"},
		NotBefore:          testNow.Add(-24 * time.Hour),
		NotAfter:           notAfter,
		SignatureAlgorithm: sigAlg,
	}
	var pub any
	var signer any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, signer = &k.PublicKey, k
	case *ecdsa.PrivateKey:
		pub, signer = &k.PublicKey, k
	default:
		t.Fatalf("unsupported key %T", key)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return k
}

// probeFunc builds a probe that succeeds for the listed max-versions and fails otherwise.
func probeFunc(state tls.ConnectionState, okVersions ...uint16) func(context.Context, string, string, uint16, uint16) (tls.ConnectionState, error) {
	return func(_ context.Context, _, _ string, _, maxVer uint16) (tls.ConnectionState, error) {
		for _, v := range okVersions {
			if v == maxVer {
				return state, nil
			}
		}
		return tls.ConnectionState{}, errors.New("protocol not supported")
	}
}

func newTestScanner(probe func(context.Context, string, string, uint16, uint16) (tls.ConnectionState, error)) draugrTLSScanner {
	s := NewTLSProbe().(draugrTLSScanner)
	s.probe = probe
	s.now = func() time.Time { return testNow }
	return s
}

// hasRule reports whether the report contains a finding with the given rule id.
func hasRule(rep sarif.Report, id string) bool {
	_, ok := ruleIDs(rep)[id]
	return ok
}

func TestTLSProbeInfo(t *testing.T) {
	info := NewTLSProbe().Info()
	if info.Name != "draugr-tls" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "tls" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetHost {
		t.Errorf("target kinds = %v", info.TargetKinds)
	}
}

func TestTLSProbeRejectsBadTarget(t *testing.T) {
	s := NewTLSProbe()
	if _, err := s.Scan(context.Background(), plugin.ImageTarget{Ref: "x"}, nil); err == nil {
		t.Error("want error for non-host target")
	}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{}, nil); err == nil {
		t.Error("want error for host with no url")
	}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "http://plain.test"}, nil); err == nil {
		t.Error("want error for plain http host")
	}
}

func TestTLSAddress(t *testing.T) {
	cases := []struct{ in, addr, sni string }{
		{"https://example.test", "example.test:443", "example.test"},
		{"https://example.test:8443/path", "example.test:8443", "example.test"},
		{"example.test", "example.test:443", "example.test"}, // bare host gets https
	}
	for _, c := range cases {
		addr, sni, err := tlsAddress(c.in)
		if err != nil || addr != c.addr || sni != c.sni {
			t.Errorf("tlsAddress(%q) = (%q,%q,%v), want (%q,%q,nil)", c.in, addr, sni, err, c.addr, c.sni)
		}
	}
	for _, bad := range []string{"http://example.test", "https://", "ht tp://x"} {
		if _, _, err := tlsAddress(bad); err == nil {
			t.Errorf("tlsAddress(%q) should error", bad)
		}
	}
}

func TestTLSProbeHealthyHost(t *testing.T) {
	cert := makeCert(t, testNow.Add(90*24*time.Hour), x509.SHA256WithRSA, rsaKey(t, 2048))
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	// Accepts TLS 1.3 (and 1.2 baseline); refuses 1.0/1.1.
	s := newTestScanner(probeFunc(state, tls.VersionTLS13))

	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.Results) != 0 {
		t.Errorf("healthy host should have no findings, got %v", ruleIDs(rep))
	}
}

func TestTLSProbeDeprecatedProtocols(t *testing.T) {
	cert := makeCert(t, testNow.Add(90*24*time.Hour), x509.SHA256WithRSA, rsaKey(t, 2048))
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	// Accepts everything including TLS 1.0/1.1, but not 1.3.
	s := newTestScanner(probeFunc(state, tls.VersionTLS13-1, tls.VersionTLS10, tls.VersionTLS11))

	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var deprecated int
	for _, r := range rep.Results {
		if r.RuleID == "tls-deprecated-protocol" {
			deprecated++
			if r.Level != sarif.LevelError {
				t.Errorf("deprecated protocol should be error level, got %v", r.Level)
			}
		}
	}
	if deprecated != 2 {
		t.Errorf("want TLS 1.0 and 1.1 findings, got %d (%v)", deprecated, ruleIDs(rep))
	}
	if !hasRule(rep, "tls-no-tls13") {
		t.Errorf("want a no-TLS1.3 note, got %v", ruleIDs(rep))
	}
}

// A server that refuses TLS 1.2+ but accepts a legacy version is the worst case — it must be a
// finding, not a scan error.
func TestTLSProbeOnlyLegacyProtocols(t *testing.T) {
	cert := makeCert(t, testNow.Add(90*24*time.Hour), x509.SHA256WithRSA, rsaKey(t, 2048))
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	s := newTestScanner(probeFunc(state, tls.VersionTLS11))

	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil)
	if err != nil {
		t.Fatalf("legacy-only host should report findings, not error: %v", err)
	}
	if !hasRule(rep, "tls-modern-unsupported") {
		t.Errorf("want tls-modern-unsupported, got %v", ruleIDs(rep))
	}
}

func TestTLSProbeUnreachableIsError(t *testing.T) {
	s := newTestScanner(probeFunc(tls.ConnectionState{})) // every version fails
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://example.test"}, nil); err == nil {
		t.Error("an unreachable host should be a scan error, not a silent pass")
	}
}

func TestCertificateFindingsExpiry(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		wantRule string
		wantLvl  sarif.Level
	}{
		{"expired", testNow.Add(-time.Hour), "tls-cert-expired", sarif.LevelError},
		{"expiring in 5d", testNow.Add(5 * 24 * time.Hour), "tls-cert-expiring", sarif.LevelError},
		{"expiring in 20d", testNow.Add(20 * 24 * time.Hour), "tls-cert-expiring", sarif.LevelWarning},
		{"healthy", testNow.Add(90 * 24 * time.Hour), "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := makeCert(t, c.notAfter, x509.SHA256WithRSA, rsaKey(t, 2048))
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			got := certificateFindings("https://example.test", state, testNow, defaultThresholds())
			if c.wantRule == "" {
				if len(got) != 0 {
					t.Fatalf("want no findings, got %d", len(got))
				}
				return
			}
			if len(got) != 1 || got[0].RuleID != c.wantRule || got[0].Level != c.wantLvl {
				t.Fatalf("got %+v, want rule %q level %q", got, c.wantRule, c.wantLvl)
			}
		})
	}
}

func TestCertificateFindingsWeakCrypto(t *testing.T) {
	notAfter := testNow.Add(90 * 24 * time.Hour)

	sha1Cert := makeCert(t, notAfter, x509.SHA1WithRSA, rsaKey(t, 2048))
	got := certificateFindings("https://example.test", tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{sha1Cert},
	}, testNow, defaultThresholds())
	if len(got) != 1 || got[0].RuleID != "tls-weak-cert-signature" {
		t.Errorf("SHA-1 signature should be flagged, got %+v", got)
	}

	weakRSA := makeCert(t, notAfter, x509.SHA256WithRSA, rsaKey(t, 1024))
	got = certificateFindings("https://example.test", tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{weakRSA},
	}, testNow, defaultThresholds())
	if len(got) != 1 || got[0].RuleID != "tls-weak-key" {
		t.Errorf("1024-bit RSA should be flagged, got %+v", got)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strongEC := makeCert(t, notAfter, x509.ECDSAWithSHA256, ecKey)
	if got := certificateFindings("https://example.test", tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{strongEC},
	}, testNow, defaultThresholds()); len(got) != 0 {
		t.Errorf("P-256 ECDSA is fine, got %+v", got)
	}

	// No peer certificates → nothing to inspect, no panic.
	if got := certificateFindings("https://example.test", tls.ConnectionState{}, testNow, defaultThresholds()); got != nil {
		t.Errorf("want nil for no certificates, got %+v", got)
	}
}

func TestCertHandshakeFinding(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantRule string
	}{
		{"hostname", x509.HostnameError{Host: "wrong.test"}, "tls-cert-hostname-mismatch"},
		{"untrusted", x509.UnknownAuthorityError{}, "tls-cert-untrusted"},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, "tls-cert-expired"},
		{"other invalid", x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForThisName}, "tls-cert-invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := certHandshakeFinding("https://example.test", c.err)
			if !ok || got.RuleID != c.wantRule {
				t.Fatalf("got (%q,%v), want rule %q", got.RuleID, ok, c.wantRule)
			}
			if got.Level != sarif.LevelError {
				t.Errorf("certificate problems should be error level, got %v", got.Level)
			}
		})
	}
	// A network error is not a certificate finding.
	if _, ok := certHandshakeFinding("https://example.test", errors.New("connection refused")); ok {
		t.Error("a network error should not become a certificate finding")
	}
}

// The scanner should surface a certificate problem found during the handshake as a finding.
func TestTLSProbeCertErrorBecomesFinding(t *testing.T) {
	s := newTestScanner(func(context.Context, string, string, uint16, uint16) (tls.ConnectionState, error) {
		return tls.ConnectionState{}, x509.UnknownAuthorityError{}
	})
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://self-signed.test"}, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "tls-cert-untrusted" {
		t.Fatalf("got %v, want a single tls-cert-untrusted finding", ruleIDs(rep))
	}
	if !strings.Contains(rep.Results[0].Message, "trusted") {
		t.Errorf("message should explain the problem: %q", rep.Results[0].Message)
	}
}

func TestExpiryThresholdsFromConfig(t *testing.T) {
	if got := thresholdsFrom(nil); got.errorDays != defaultExpiryErrorDays || got.warnDays != defaultExpiryWarnDays {
		t.Errorf("defaults = %+v", got)
	}
	// YAML decodes whole numbers as int; JSON yields float64. Both must work.
	if got := thresholdsFrom(plugin.Config{"expiryErrorDays": 3, "expiryWarnDays": 7}); got.errorDays != 3 || got.warnDays != 7 {
		t.Errorf("int config = %+v", got)
	}
	if got := thresholdsFrom(plugin.Config{"expiryErrorDays": float64(5)}); got.errorDays != 5 {
		t.Errorf("float config = %+v", got)
	}
	// A warn window below the error window would silently swallow the warning band.
	if got := thresholdsFrom(plugin.Config{"expiryErrorDays": 20, "expiryWarnDays": 5}); got.warnDays != 20 {
		t.Errorf("inverted windows should clamp, got %+v", got)
	}
	// A non-numeric value falls back rather than panicking (schema validation catches it first).
	if got := thresholdsFrom(plugin.Config{"expiryErrorDays": "soon"}); got.errorDays != defaultExpiryErrorDays {
		t.Errorf("bad type should fall back, got %+v", got)
	}
}

// Tightening the windows should silence a warning that the defaults would raise.
func TestTLSProbeHonorsConfiguredThresholds(t *testing.T) {
	cert := makeCert(t, testNow.Add(20*24*time.Hour), x509.SHA256WithRSA, rsaKey(t, 2048))
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	s := newTestScanner(probeFunc(state, tls.VersionTLS13))
	host := plugin.HostTarget{URL: "https://example.test"}

	// Default 30-day warn window: 20 days out is a warning.
	rep, err := s.Scan(context.Background(), host, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(rep, "tls-cert-expiring") {
		t.Fatalf("defaults should warn at 20 days, got %v", ruleIDs(rep))
	}

	// Tuned for automated renewal: warn at 10 days, so 20 days out is quiet.
	rep, err = s.Scan(context.Background(), host, plugin.Config{"expiryWarnDays": 10, "expiryErrorDays": 5})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(rep, "tls-cert-expiring") {
		t.Errorf("a 10-day warn window should not fire at 20 days, got %v", ruleIDs(rep))
	}
}

func TestTLSProbeConfigSchemaValid(t *testing.T) {
	schema := NewTLSProbe().Info().ConfigSchema
	if len(schema) == 0 {
		t.Fatal("draugr-tls should declare a config schema")
	}
	if err := plugin.ValidateConfig(schema, plugin.Config{"expiryWarnDays": 10}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := plugin.ValidateConfig(schema, plugin.Config{"expiryWarnDays": "ten"}); err == nil {
		t.Error("a non-integer window should be rejected")
	}
	if err := plugin.ValidateConfig(schema, plugin.Config{"typo": 1}); err == nil {
		t.Error("an unknown key should be rejected")
	}
}
