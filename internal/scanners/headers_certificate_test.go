package scanners

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// expiredCertificate is the error a fetch over an expired certificate returns, wrapped the way the
// HTTP client wraps it.
var expiredCertificate = &url.Error{Op: "Get", URL: "https://expired.example.com/", Err: x509.CertificateInvalidError{Reason: x509.Expired}}

// certificateScanner fails its verified fetch with err and answers its unverified one, counting the
// unverified fetches.
func certificateScanner(err error, unverified *int) draugrHeadersScanner {
	return draugrHeadersScanner{
		info:  NewHTTPHeaders().Info(),
		fetch: func(context.Context, string, bool) (response, error) { return response{}, err },
		fetchUnverified: func(context.Context, string, bool) (response, error) {
			*unverified++
			return response{header: http.Header{"X-Content-Type-Options": {"nosniff"}}, statusCode: http.StatusOK}, nil
		},
	}
}

// Where the run reports the certificate, a host whose certificate fails verification still gets its
// headers read, and the control does not end in an error about the same fact. Two hosts, so a
// decision made once for the scanner rather than per target would show.
func TestHeadersReadPastACertificateTheRunReports(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		expiredCertificate,
		&url.Error{Op: "Get", URL: "https://self-signed.example.com/", Err: x509.UnknownAuthorityError{}},
		&url.Error{Op: "Get", URL: "https://wrong.host.example.com/", Err: x509.HostnameError{Host: "wrong.host.example.com"}},
	} {
		var unverified int
		s := certificateScanner(err, &unverified)
		for _, u := range []string{"https://expired.example.com/", "https://self-signed.example.com/"} {
			rep, scanErr := s.Scan(context.Background(), plugin.HostTarget{URL: u, Type: "api", CertificateReported: true}, nil)
			if scanErr != nil {
				t.Fatalf("%v: Scan(%s) = %v, want the headers read past the certificate", err, u, scanErr)
			}
			if got := ruleIDs(rep); len(got) == 0 {
				t.Errorf("%v: Scan(%s) found nothing, want the headers judged", err, u)
			}
		}
		if unverified != 2 {
			t.Errorf("%v: %d unverified fetches, want one per host", err, unverified)
		}
	}
}

// Everywhere else a certificate that fails verification stays an error: where nothing in the run
// reports it, where the target carries auth, and where the failure is not the certificate's.
func TestHeadersKeepVerifyingOtherwise(t *testing.T) {
	t.Parallel()
	auth := &plugin.HostAuth{Kind: "bearer", TokenEnv: "API_TOKEN"}
	for _, c := range []struct {
		name   string
		target plugin.HostTarget
		err    error
	}{
		{"no tls job on the host", plugin.HostTarget{URL: "https://expired.example.com/"}, expiredCertificate},
		{"auth", plugin.HostTarget{URL: "https://expired.example.com/", Auth: auth, CertificateReported: true}, expiredCertificate},
		// The client sends a user and password written in the URL as a header, so such a host keeps the
		// error rather than handing them to a server that failed the check.
		{"a credential in the URL", plugin.HostTarget{URL: (&url.URL{Scheme: "https", User: url.UserPassword("scanner", "x"),
			Host: "expired.example.com", Path: "/"}).String(), CertificateReported: true}, expiredCertificate},
		{"a refused handshake", plugin.HostTarget{URL: "https://rc4.example.com/", CertificateReported: true},
			errors.New("remote error: tls: handshake failure")},
	} {
		var unverified int
		_, err := certificateScanner(c.err, &unverified).Scan(context.Background(), c.target, nil)
		if err == nil || !strings.Contains(err.Error(), "draugr-headers: fetch") {
			t.Errorf("%s: Scan error = %v, want the fetch's", c.name, err)
		}
		if unverified != 0 {
			t.Errorf("%s: fetched without verifying", c.name)
		}
	}
	// A scanner given no unverified fetch never reads past a certificate.
	s := draugrHeadersScanner{info: NewHTTPHeaders().Info(),
		fetch: func(context.Context, string, bool) (response, error) { return response{}, expiredCertificate }}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://expired.example.com/", CertificateReported: true}, nil); err == nil {
		t.Error("a scanner without an unverified fetch read past the certificate")
	}
}

// One endpoint however its URL is written, and another on a different scheme, host or port.
func TestEndpointOf(t *testing.T) {
	t.Parallel()
	same := []string{"https://example.com/a", "https://EXAMPLE.com:443/b", "HTTPS://example.com"}
	for _, s := range same {
		u, _ := url.Parse(s)
		if got := endpointOf(u); got != "https://example.com:443" {
			t.Errorf("endpointOf(%s) = %s, want https://example.com:443", s, got)
		}
	}
	for _, s := range []string{"http://example.com/", "https://example.com:8443/", "https://www.example.com/"} {
		u, _ := url.Parse(s)
		if got := endpointOf(u); got == "https://example.com:443" {
			t.Errorf("endpointOf(%s) = %s, the declared endpoint", s, got)
		}
	}
	if u, _ := url.Parse("http://example.com/"); endpointOf(u) != "http://example.com:80" {
		t.Errorf("endpointOf(http://example.com/) = %s, want port 80", endpointOf(u))
	}
}

// Through a real client: the verified fetch refuses a certificate the system does not trust, and the
// unverified one reads the declared host while still verifying a host a redirect sends it to.
func TestUnverifiedFetchSkipsOnlyTheDeclaredHost(t *testing.T) {
	t.Parallel()
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer elsewhere.Close()
	// The same server reached by another name, which its test certificate does not cover and nothing
	// in the run would report.
	other := strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)

	declared := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			http.Redirect(w, r, other+"/", http.StatusFound)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><head></head></html>")
	}))
	defer declared.Close()

	_, err := httpFetchHeaders(context.Background(), declared.URL, false)
	if !certificateRejected(err) {
		t.Fatalf("verified fetch of a self-signed host = %v, want a certificate rejection", err)
	}

	resp, err := httpFetchHeadersUnverified(context.Background(), declared.URL, true)
	if err != nil {
		t.Fatalf("unverified fetch of the declared host: %v", err)
	}
	if resp.header.Get("Strict-Transport-Security") == "" || len(resp.body) == 0 {
		t.Errorf("unverified fetch read headers %v and %d bytes, want the host's response", resp.header, len(resp.body))
	}

	if _, err := httpFetchHeadersUnverified(context.Background(), declared.URL+"/away", false); !certificateRejected(err) {
		t.Errorf("a redirect to another host was read past its certificate: err = %v", err)
	}
	if _, err := httpFetchHeadersUnverified(context.Background(), "://bad-url", false); err == nil {
		t.Error("an unparsable URL fetched")
	}
}

// The unverified fetch goes straight to the host, as the tls control dials it: through a proxy that
// inspects TLS, the certificate it read past would be the proxy's, which no finding reports.
func TestTheUnverifiedFetchUsesNoProxy(t *testing.T) {
	t.Parallel()
	tr := unverifiedTransport()
	if tr.Proxy != nil {
		t.Error("the unverified transport takes a proxy from the environment")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS config = %+v, want unverified at TLS 1.2 or later", tr.TLSClientConfig)
	}
}
