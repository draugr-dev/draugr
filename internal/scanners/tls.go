package scanners

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// tlsProbeScanner is a native (no external tool) scanner that inspects a host's TLS
// configuration: the certificate it presents and which protocol versions it accepts. It serves
// the "tls" control.
//
// Native rather than exec'ing testssl.sh: Draugr ships as a single binary, and testssl.sh is a
// bash script plus a data directory (so it doesn't fit the binary-based tool provisioning),
// needs bash/openssl on the runner, takes minutes per host, and is GPL-2.0 (exec-only, never
// bundleable). The checks below are the high-value ones that Go's crypto/tls can make in
// seconds. Depth that Go cannot reach — SSLv2/SSLv3, export/NULL ciphers, protocol-level vulns
// like ROBOT — is left to an opt-in testssl.sh scanner as a follow-up.
type tlsProbeScanner struct {
	info plugin.ScannerInfo
	// probe performs one handshake at a fixed protocol version, returning the negotiated
	// connection state. Injected so tests don't need a live endpoint.
	probe func(ctx context.Context, addr string, serverName string, minVer, maxVer uint16) (tls.ConnectionState, error)
	// now supplies the current time (certificate expiry math); injected for deterministic tests.
	now func() time.Time
}

// Default certificate-expiry windows, in days. A certificate inside errorDays is an error;
// inside warnDays, a warning. Both are tunable per Saga — an endpoint with automated renewal
// (Let's Encrypt, Cloudflare) legitimately sits inside a wide default window during normal
// rotation, and a gate should fire only when renewal has actually failed.
const (
	defaultExpiryErrorDays = 14
	defaultExpiryWarnDays  = 30
)

// tlsProbeConfigSchema is the JSON Schema for the probe's Saga config
// (controllers.tls.tls-probe). additionalProperties:false rejects mistyped keys.
const tlsProbeConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "expiryErrorDays": {
      "type": "integer",
      "description": "Report an error when the certificate expires within this many days. Defaults to 14."
    },
    "expiryWarnDays": {
      "type": "integer",
      "description": "Report a warning when the certificate expires within this many days. Defaults to 30. Lower it for endpoints with automated renewal so the gate only fires when renewal has failed."
    }
  }
}`

// expiryThresholds holds the resolved warn/error windows for certificate expiry.
type expiryThresholds struct{ errorDays, warnDays int }

// thresholdsFrom reads the expiry windows from the scanner config, falling back to the
// defaults. A warn window below the error window is raised to it, so the two never invert.
func thresholdsFrom(cfg plugin.Config) expiryThresholds {
	t := expiryThresholds{errorDays: defaultExpiryErrorDays, warnDays: defaultExpiryWarnDays}
	if v, ok := configInt(cfg, "expiryErrorDays"); ok {
		t.errorDays = v
	}
	if v, ok := configInt(cfg, "expiryWarnDays"); ok {
		t.warnDays = v
	}
	if t.warnDays < t.errorDays {
		t.warnDays = t.errorDays
	}
	return t
}

// configInt reads an integer option. YAML decodes whole numbers as int, but JSON (and some
// decoders) yield float64, so accept both.
func configInt(cfg plugin.Config, key string) (int, bool) {
	switch v := cfg[key].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// NewTLSProbe returns the native TLS configuration scanner.
func NewTLSProbe() plugin.Scanner {
	return tlsProbeScanner{
		info: plugin.ScannerInfo{
			Name:         "tls-probe",
			Origin:       plugin.OriginDraugr,
			Controls:     []string{"tls"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetHost},
			ConfigSchema: json.RawMessage(tlsProbeConfigSchema),
		},
		probe: dialTLS,
		now:   time.Now,
	}
}

// Info describes the scanner.
func (s tlsProbeScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion ties cached results to this binary (implements plugin.CacheVersioner).
//
// A native scanner has no external tool to ask, and the probe's expectations — protocol floor, expiry window, chain rules — are ours, so they change when Draugr does.
func (s tlsProbeScanner) CacheVersion(context.Context) string { return draugrCacheVersion() }

// Scan probes the host's TLS endpoint and reports certificate and protocol findings.
func (s tlsProbeScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("tls-probe: unsupported target %T (want host)", target)
	}
	if host.URL == "" {
		return sarif.Report{}, errors.New("tls-probe: host target has no url")
	}
	addr, serverName, err := tlsAddress(host.URL)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("tls-probe: %w", err)
	}

	var results []sarif.Result

	// Baseline handshake at modern versions: establishes that TLS works at all and gives us the
	// certificate chain to inspect.
	state, err := s.probe(ctx, addr, serverName, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		// A failure here can be a genuine finding (expired/untrusted certificate) rather than an
		// infrastructure error, so classify it instead of aborting the whole scan.
		if res, ok := certHandshakeFinding(host.URL, err); ok {
			return sarif.Report{Tool: s.info.Name, Results: []sarif.Result{res}}, nil
		}
		// The server may refuse TLS 1.2+ because it only speaks deprecated versions — the worst
		// case, and a finding rather than an error. Retry on the legacy range before giving up.
		legacyState, legacyErr := s.probe(ctx, addr, serverName, tls.VersionTLS10, tls.VersionTLS11)
		if legacyErr != nil {
			return sarif.Report{}, fmt.Errorf("tls-probe: connect %s: %w", addr, err)
		}
		results = append(results, sarif.Result{
			Tool:     s.info.Name,
			RuleID:   "tls-modern-unsupported",
			Level:    sarif.LevelError,
			Score:    8.5,
			HasScore: true,
			Message: "Server does not accept TLS 1.2 or newer — only deprecated versions. " +
				"Traffic is protected by protocols with known attacks; enable TLS 1.2+ urgently.",
			Location: sarif.Location{URI: host.URL},
		})
		state = legacyState
	}
	results = append(results, certificateFindings(host.URL, state, s.now(), thresholdsFrom(cfg))...)

	// Deprecated protocol versions: a successful handshake pinned to TLS 1.0/1.1 means the
	// server still accepts it.
	for _, v := range []struct {
		version uint16
		label   string
		score   float64
	}{
		{tls.VersionTLS10, "TLS 1.0", 7.0},
		{tls.VersionTLS11, "TLS 1.1", 6.5},
	} {
		if _, err := s.probe(ctx, addr, serverName, v.version, v.version); err == nil {
			results = append(results, sarif.Result{
				Tool:     s.info.Name,
				RuleID:   "tls-deprecated-protocol",
				Level:    sarif.LevelError,
				Score:    v.score,
				HasScore: true,
				Message: fmt.Sprintf(
					"%s is accepted. It is deprecated (RFC 8996) and vulnerable to known attacks — "+
						"disable it and require TLS 1.2 or newer.", v.label),
				Location: sarif.Location{URI: host.URL},
			})
		}
	}

	// TLS 1.3 support is a positive signal; note (not a failure) when it's absent.
	if _, err := s.probe(ctx, addr, serverName, tls.VersionTLS13, tls.VersionTLS13); err != nil {
		results = append(results, sarif.Result{
			Tool:     s.info.Name,
			RuleID:   "tls-no-tls13",
			Level:    sarif.LevelNote,
			Score:    2.0,
			HasScore: true,
			Message: "TLS 1.3 is not accepted. It is faster and removes legacy weaknesses — " +
				"enable it alongside TLS 1.2.",
			Location: sarif.Location{URI: host.URL},
		})
	}

	return sarif.Report{Tool: s.info.Name, Results: results}, nil
}

// certificateFindings inspects the negotiated peer certificate: expiry window, signature
// algorithm, and public-key strength.
func certificateFindings(uri string, state tls.ConnectionState, now time.Time, th expiryThresholds) []sarif.Result {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	var out []sarif.Result

	switch remaining := leaf.NotAfter.Sub(now); {
	case remaining <= 0:
		out = append(out, sarif.Result{
			Tool: "tls-probe", RuleID: "tls-cert-expired", Level: sarif.LevelError,
			Score: 9.0, HasScore: true,
			Message: fmt.Sprintf("Certificate expired on %s. Clients will refuse to connect — renew it now.",
				leaf.NotAfter.UTC().Format(time.DateOnly)),
			Location: sarif.Location{URI: uri},
		})
	case remaining < time.Duration(th.errorDays)*24*time.Hour:
		out = append(out, sarif.Result{
			Tool: "tls-probe", RuleID: "tls-cert-expiring", Level: sarif.LevelError,
			Score: 7.0, HasScore: true,
			Message: fmt.Sprintf("Certificate expires in %d day(s), on %s. Renew it before it lapses.",
				int(remaining.Hours()/24), leaf.NotAfter.UTC().Format(time.DateOnly)),
			Location: sarif.Location{URI: uri},
		})
	case remaining < time.Duration(th.warnDays)*24*time.Hour:
		out = append(out, sarif.Result{
			Tool: "tls-probe", RuleID: "tls-cert-expiring", Level: sarif.LevelWarning,
			Score: 4.0, HasScore: true,
			Message: fmt.Sprintf("Certificate expires in %d day(s), on %s. Schedule the renewal.",
				int(remaining.Hours()/24), leaf.NotAfter.UTC().Format(time.DateOnly)),
			Location: sarif.Location{URI: uri},
		})
	}

	if weakSignature(leaf.SignatureAlgorithm) {
		out = append(out, sarif.Result{
			Tool: "tls-probe", RuleID: "tls-weak-cert-signature", Level: sarif.LevelError,
			Score: 7.5, HasScore: true,
			Message: fmt.Sprintf("Certificate is signed with %s, which is collision-prone and no longer "+
				"trusted. Reissue it with an SHA-256 (or stronger) signature.", leaf.SignatureAlgorithm),
			Location: sarif.Location{URI: uri},
		})
	}

	if rule, msg, score, ok := weakKey(leaf); ok {
		out = append(out, sarif.Result{
			Tool: "tls-probe", RuleID: rule, Level: sarif.LevelError,
			Score: score, HasScore: true,
			Message:  msg,
			Location: sarif.Location{URI: uri},
		})
	}
	return out
}

// weakSignature reports whether a certificate signature algorithm relies on a broken hash.
func weakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// weakKey reports whether the certificate's public key is below current strength guidance.
func weakKey(cert *x509.Certificate) (rule, message string, score float64, weak bool) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < 2048 {
			return "tls-weak-key", fmt.Sprintf(
				"Certificate uses a %d-bit RSA key. Keys under 2048 bits are considered breakable — "+
					"reissue with at least 2048 bits.", bits), 7.0, true
		}
	case *ecdsa.PublicKey:
		if bits := pub.Curve.Params().BitSize; bits < 256 {
			return "tls-weak-key", fmt.Sprintf(
				"Certificate uses a %d-bit ECDSA key. Use a P-256 curve or stronger.", bits), 7.0, true
		}
	}
	return "", "", 0, false
}

// certHandshakeFinding turns a handshake failure that is really a certificate problem
// (untrusted issuer, hostname mismatch, expired) into a finding. Other errors — DNS, refused
// connections, timeouts — are left as scan errors, since they say nothing about TLS posture.
func certHandshakeFinding(uri string, err error) (sarif.Result, bool) {
	base := sarif.Result{
		Tool: "tls-probe", Level: sarif.LevelError, HasScore: true,
		Location: sarif.Location{URI: uri},
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalid x509.CertificateInvalidError

	switch {
	case errors.As(err, &hostnameErr):
		base.RuleID = "tls-cert-hostname-mismatch"
		base.Score = 8.0
		base.Message = fmt.Sprintf("Certificate is not valid for this hostname: %v. "+
			"Clients will reject it — reissue the certificate covering this name.", hostnameErr)
	case errors.As(err, &unknownAuthority):
		base.RuleID = "tls-cert-untrusted"
		base.Score = 8.0
		base.Message = "Certificate is not signed by a trusted authority (self-signed or an " +
			"incomplete chain). Serve the full chain from a trusted CA."
	case errors.As(err, &invalid):
		// An expired certificate surfaces here (the handshake fails before we can inspect the
		// chain), so name it specifically rather than reporting a generic invalid-cert error.
		if invalid.Reason == x509.Expired {
			base.RuleID = "tls-cert-expired"
			base.Score = 9.0
			base.Message = "Certificate has expired (or is not yet valid). Clients will refuse to " +
				"connect — renew it now."
			break
		}
		base.RuleID = "tls-cert-invalid"
		base.Score = 8.0
		base.Message = fmt.Sprintf("Certificate is not valid: %v.", invalid)
	default:
		return sarif.Result{}, false
	}
	return base, true
}

// tlsAddress derives the dial address and SNI server name from a host URL. A URL without a
// port defaults to 443; a bare host (no scheme) is accepted too.
func tlsAddress(raw string) (addr, serverName string, err error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("parse host url %q: %w", raw, err)
	}
	if u.Scheme == "http" {
		return "", "", fmt.Errorf("host %q is plain http — nothing to probe (serve it over https)", raw)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return "", "", fmt.Errorf("host url %q has no hostname", raw)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(hostname, port), hostname, nil
}

// dialTLS performs a handshake constrained to [minVer,maxVer] and returns the connection state.
// Verification is left on: a certificate error is a finding, and the caller classifies it.
func dialTLS(ctx context.Context, addr, serverName string, minVer, maxVer uint16) (tls.ConnectionState, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{ //nolint:gosec // MinVersion is set per probe: we must attempt old versions to detect them
			ServerName: serverName,
			MinVersion: minVer,
			MaxVersion: maxVer,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, fmt.Errorf("unexpected connection type %T", conn)
	}
	return tlsConn.ConnectionState(), nil
}
