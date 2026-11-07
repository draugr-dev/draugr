package scanners

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// An endpoint that did not answer ends the scan in an error naming it and the cause, and Nuclei
// never runs against it. One that answered beside it, in the same component, is scanned.
func TestNucleiRefusesAnEndpointThatDidNotAnswer(t *testing.T) {
	const gone, live = "http://allanlambe.com", "https://shop.example"
	cause := errors.New("dial tcp: lookup allanlambe.com: no such host")
	var ran []string
	s := nucleiScanner{
		info: NewNuclei().Info(),
		run: func(_ context.Context, argv []string) ([]byte, error) {
			ran = append(ran, argv[2])
			return []byte(`{"template-id":"t","matched-at":"https://shop.example/a","info":{"name":"T","severity":"high"}}`), nil
		},
		reach: func(_ context.Context, url, _ string) error {
			if url == gone {
				return cause
			}
			return nil
		},
	}
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: gone}, nil)
	if err == nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), gone+" did not answer, so nothing was scanned") {
		t.Errorf("err = %v, want the endpoint and the cause", err)
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: live}, nil)
	if err != nil || len(rep.Results) != 1 {
		t.Errorf("the endpoint that answered: %d results, err %v", len(rep.Results), err)
	}
	if len(ran) != 1 || ran[0] != live {
		t.Errorf("nuclei ran against %v, want only %s", ran, live)
	}
}

// The scanner Draugr registers checks the endpoint.
func TestNewNucleiChecksTheEndpoint(t *testing.T) {
	if NewNuclei().(nucleiScanner).reach == nil {
		t.Error("NewNuclei does not check the endpoint answers")
	}
}

// Any answer counts, whatever its status, a redirect is not followed, and an unverified certificate
// is accepted; a port nothing listens on and an address that cannot be requested do not.
func TestNucleiReach(t *testing.T) {
	answers := func(status int) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		t.Cleanup(srv.Close)
		return srv
	}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsSrv.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	_ = ln.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, closed, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	for name, url := range map[string]string{
		"a 500":                     answers(http.StatusInternalServerError).URL,
		"a 404":                     answers(http.StatusNotFound).URL,
		"a redirect to nothing":     redirect.URL,
		"a self-signed certificate": tlsSrv.URL,
	} {
		if err := nucleiReach(context.Background(), url, ""); err != nil {
			t.Errorf("%s: %v, want it to count as an answer", name, err)
		}
	}
	for name, url := range map[string]string{
		"a closed port": closed,
		"no scheme":     "::not a url",
	} {
		if err := nucleiReach(context.Background(), url, ""); err == nil {
			t.Errorf("%s: counted as an answer", name)
		}
	}
}

// The probe carries the scan's credential, so an authenticated scan sends no anonymous request.
func TestNucleiReachSendsTheHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }))
	t.Cleanup(srv.Close)
	if err := nucleiReach(context.Background(), srv.URL, "Authorization: Bearer aaaa"); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer aaaa" {
		t.Errorf("Authorization = %q", got)
	}
}

// A credential that cannot be resolved stops the scan before the probe, so nothing is sent.
func TestNucleiSendsNothingWithoutItsCredential(t *testing.T) {
	t.Setenv("DRAUGR_TOKEN_ENVS", "DRAUGR_TEST_ABSENT")
	t.Setenv("DRAUGR_TEST_ABSENT", "")
	probed := false
	s := nucleiScanner{
		info:  NewNuclei().Info(),
		run:   func(context.Context, []string) ([]byte, error) { t.Error("nuclei ran"); return nil, nil },
		reach: func(context.Context, string, string) error { probed = true; return nil },
	}
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://shop.example",
		Auth: &plugin.HostAuth{Kind: "bearer", TokenEnv: "DRAUGR_TEST_ABSENT"}}, nil) // #nosec G101 -- the name of an environment variable, which is the point: no credential is expressible here
	if err == nil || probed {
		t.Errorf("err %v, probed %v: want an error and no request", err, probed)
	}
}
