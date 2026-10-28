package publish

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// logins is a login.Store in memory, counting its reads.
type logins struct {
	held  map[string]login.Login
	err   error
	reads int
}

func (s *logins) Get(origin string) (login.Login, error) {
	s.reads++
	if s.err != nil {
		return login.Login{}, s.err
	}
	l, ok := s.held[origin]
	if !ok {
		return login.Login{}, login.ErrNotLoggedIn
	}
	return l, nil
}

func (s *logins) Set(origin string, l login.Login) error { s.held[origin] = l; return nil }

func (s *logins) Delete(origin string) error { delete(s.held, origin); return nil }

var loginNow = time.Date(2026, 10, 27, 18, 12, 0, 0, time.UTC)

// anaAt is a live login for server.
func anaAt(server string) *logins {
	origin, _ := login.Origin(server)
	return &logins{held: map[string]login.Login{origin: { // #nosec G101 -- a placeholder token for a test store
		Server: server, Token: "drgl_login", Email: "ana@acme.com", Organization: "acme",
		Expires: loginNow.Add(12 * time.Hour),
	}}}
}

func noAPIEnv(t *testing.T) {
	t.Helper()
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiTokenEnv, "")
	t.Setenv(apiOriginsEnv, "")
}

func TestThePolicyCheckUsesALoginWhereNoTokenIsSet(t *testing.T) {
	noAPIEnv(t)
	t.Run("the descriptor's url, with a login for its origin", func(t *testing.T) {
		store := anaAt("https://draugr.example")
		dest, skip, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api", URL: "https://draugr.example/"}, store, loginNow)
		if err != nil || skip != "" || dest.Endpoint != "https://draugr.example" || dest.Token != "drgl_login" ||
			dest.Login == nil || dest.Login.Email != "ana@acme.com" {
			t.Errorf("dest = %+v, %q, %v", dest, skip, err)
		}
	})
	t.Run("the environment's server", func(t *testing.T) {
		t.Setenv(apiURLEnv, "https://draugr.example")
		dest, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api"}, anaAt("https://draugr.example"), loginNow)
		if err != nil || dest.Token != "drgl_login" {
			t.Errorf("dest = %+v, %v", dest, err)
		}
	})
	t.Run("a url with no login for its origin asks nothing", func(t *testing.T) {
		// The login is for another server, and its token goes only to the server that issued it.
		store := anaAt("https://draugr.example")
		dest, skip, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api", URL: "https://attacker.example"}, store, loginNow)
		if err != nil || dest.Token != "" || !strings.Contains(skip, "no login for https://attacker.example") ||
			!strings.Contains(skip, "draugr login https://attacker.example") {
			t.Errorf("dest = %+v, %q, %v", dest, skip, err)
		}
	})
	t.Run("nothing named at all", func(t *testing.T) {
		_, skip, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api"}, anaAt("https://draugr.example"), loginNow)
		if err != nil || skip != "no $DRAUGR_API_URL or $DRAUGR_API_TOKEN" {
			t.Errorf("%q, %v", skip, err)
		}
	})
	t.Run("an expired login", func(t *testing.T) {
		store := anaAt("https://draugr.example")
		_, skip, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api", URL: "https://draugr.example"}, store, loginNow.Add(13*time.Hour))
		if err != nil || !strings.Contains(skip, "expired at 2026-10-28 06:12 UTC") || !strings.Contains(skip, "draugr login https://draugr.example") {
			t.Errorf("%q, %v", skip, err)
		}
	})
	t.Run("an endpoint with neither a token nor a login", func(t *testing.T) {
		t.Setenv(apiURLEnv, "https://draugr.example")
		_, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api"}, &logins{}, loginNow)
		if err == nil || !strings.Contains(err.Error(), "$DRAUGR_API_TOKEN is not set, and there is no login") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a keychain that cannot be read", func(t *testing.T) {
		broken := &logins{err: &login.KeychainError{Err: errors.New("no secret service")}}
		_, skip, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api", URL: "https://draugr.example"}, broken, loginNow)
		if err != nil || !strings.Contains(skip, "could not be read") || !strings.Contains(skip, "no secret service") {
			t.Errorf("a local run is not failed by a missing keychain: %q, %v", skip, err)
		}
		t.Setenv(apiURLEnv, "https://draugr.example")
		if _, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api"}, broken, loginNow); !errors.Is(err, login.ErrNoKeychain) {
			t.Errorf("an endpoint with no token says why no login was found: %v", err)
		}
	})
	t.Run("a login for a server reached without TLS", func(t *testing.T) {
		store := anaAt("http://draugr.example")
		_, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api", URL: "http://draugr.example"}, store, loginNow)
		if err == nil || !strings.Contains(err.Error(), "not https") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the project's configuration names the server", func(t *testing.T) {
		dest, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api", ProjectURL: "https://draugr.example"},
			anaAt("https://draugr.example"), loginNow)
		if err != nil || dest.Token != "drgl_login" {
			t.Errorf("dest = %+v, %v", dest, err)
		}
	})
}

// The pipeline's token is the pipeline's credential, and a login on the same machine never
// replaces it.
func TestTheCheckPrefersATokenFromTheEnvironment(t *testing.T) {
	noAPIEnv(t)
	t.Setenv(apiURLEnv, "https://draugr.example")
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	store := anaAt("https://draugr.example")
	dest, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api"}, store, loginNow)
	if err != nil || dest.Token != "drgr_ci_test" || dest.Login != nil || store.reads != 0 {
		t.Errorf("dest = %+v, %v, %d keychain reads", dest, err, store.reads)
	}
	if dest, _, err := ResolvePolicyAPI(saga.PublisherConfig{Kind: "draugr-api"}, nil, loginNow); err != nil || dest.Token != "drgr_ci_test" {
		t.Errorf("no store is ResolveAPI: %+v, %v", dest, err)
	}
}

// A login is check-only. With one held for the server the descriptor names, the publisher still
// sends nothing: it skips where no token is set, and refuses an endpoint without one, as it would
// with no login at all.
func TestThePublisherNeverUsesALogin(t *testing.T) {
	noAPIEnv(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	store := anaAt(srv.URL)
	cfg := saga.PublisherConfig{Kind: "draugr-api", URL: srv.URL}

	// The same descriptor and machine, where the policy check would use the login.
	if dest, _, err := ResolvePolicyAPI(cfg, store, loginNow); err != nil || dest.Token != "drgl_login" {
		t.Fatalf("the check's resolution: %+v, %v", dest, err)
	}

	pub, err := For(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, skipped := pub.(skipPublisher); !skipped {
		t.Fatalf("the publisher resolved a destination from a login: %T", pub)
	}
	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Errorf("a skipped publisher failed: %v", err)
	}

	t.Setenv(apiURLEnv, srv.URL)
	if _, err := For(cfg); err == nil || !strings.Contains(err.Error(), "$DRAUGR_API_TOKEN") {
		t.Errorf("an endpoint with a login and no token: %v", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the publisher sent %d requests", n)
	}
}

func TestARefusedLoginSaysToLogInAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"expired or revoked":     {http.StatusUnauthorized, `{"error":"invalid_token"}`, "has expired or was revoked; run `draugr login https://draugr.example`"},
		"no check scope":         {http.StatusForbidden, `{"error":"insufficient_scope"}`, "does not carry the check scope"},
		"no role in the project": {http.StatusForbidden, `{"error":"forbidden","detail":"not a member"}`, `holds no role in project "payments"`},
		"an unknown project":     {http.StatusNotFound, `{"error":"not_found"}`, `has no project "payments" that the login for`},
		"another refusal":        {http.StatusTooManyRequests, `{"error":"rate_limited","detail":"slow down"}`, "rate_limited: slow down"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			l := login.Login{Server: "https://draugr.example", Token: "drgl_login"} // #nosec G101 -- a placeholder the test server never checks
			_, err := PolicyClient{client: http.DefaultClient}.Check(context.Background(),
				APIDestination{Endpoint: srv.URL, Token: l.Token, Login: &l, Project: "payments"}, "project: payments\n")
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "drgl_login") ||
				errors.Is(err, ErrNoPolicyCheck) {
				t.Errorf("err = %v", err)
			}
		})
	}
	// A pipeline's token answered 401 is the server's word, not a login to renew.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","detail":"unknown token"}`))
	}))
	defer srv.Close()
	_, err := PolicyClient{client: http.DefaultClient}.Check(context.Background(),
		APIDestination{Endpoint: srv.URL, Token: "drgr_ci_test"}, "project: payments\n") // #nosec G101 -- a placeholder the test server never checks
	if err == nil || strings.Contains(err.Error(), "draugr login") || !strings.Contains(err.Error(), "unknown token") {
		t.Errorf("err = %v", err)
	}
}

// planeStub answers the two policy-check routes the way the server does: the ingest route takes
// only an ingest token and judges that token's own project, and a person's check token is accepted
// only on the route naming a project, by any role in it.
func planeStub(t *testing.T, got *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		*got = append(*got, r.Method+" "+r.URL.EscapedPath()+" "+auth)
		answer := func() {
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "project": "payments", "policyVersion": 3, "outcome": "pass", "passed": true})
		}
		switch {
		case r.URL.Path == "/v1/ingest/policy/check" && auth == "Bearer drgr_ci_test":
			answer()
		case r.URL.Path == "/v1/ingest/policy/check":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"token_invalid"}`)
		case r.URL.Path == "/v1/projects/payments/policy/check" && (auth == "Bearer drgl_login" || auth == "Bearer drgr_api_person"):
			answer()
		case strings.HasPrefix(r.URL.Path, "/v1/projects/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not_found"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A login's token is a person's check token, which the server refuses on the ingest route, so the
// check it makes names the descriptor's project. The pipeline's ingest token keeps the ingest route.
func TestALoginChecksThroughTheProjectRoute(t *testing.T) {
	var got []string
	srv := planeStub(t, &got)
	l := login.Login{Server: srv.URL, Token: "drgl_login"} // #nosec G101 -- a placeholder the test server checks
	out, err := PolicyClient{client: http.DefaultClient}.Check(context.Background(),
		APIDestination{Endpoint: srv.URL, Token: l.Token, Login: &l, Project: "payments"}, "project: payments\n")
	if err != nil || out.PolicyVersion != 3 {
		t.Fatalf("outcome %+v, err %v, requests %v", out, err, got)
	}
	if len(got) != 1 || got[0] != "POST /v1/projects/payments/policy/check Bearer drgl_login" {
		t.Errorf("requests = %v", got)
	}

	got = nil
	// #nosec G101 -- a placeholder the test server checks, not a credential.
	if _, err := (PolicyClient{client: http.DefaultClient}).Check(context.Background(),
		APIDestination{Endpoint: srv.URL, Token: "drgr_ci_test", Project: "payments"}, "project: payments\n"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "POST /v1/ingest/policy/check Bearer drgr_ci_test" {
		t.Errorf("the pipeline's token left the ingest route: %v", got)
	}

	got = nil
	_, err = PolicyClient{client: http.DefaultClient}.Check(context.Background(),
		APIDestination{Endpoint: srv.URL, Token: l.Token, Login: &l, Project: "pay ments/x"}, "")
	if len(got) != 1 || !strings.HasPrefix(got[0], "POST /v1/projects/pay%20ments%2Fx/policy/check ") {
		t.Errorf("the project was not escaped into one path segment: %v", got)
	}
	if err == nil || errors.Is(err, ErrNoPolicyCheck) || !strings.Contains(err.Error(), `has no project "pay ments/x"`) {
		t.Errorf("an unknown project read as a server with no policy: %v", err)
	}
}

// A descriptor with no project gives a login's check nothing to name, so nothing is sent.
func TestALoginCheckNeedsTheDescriptorsProject(t *testing.T) {
	var got []string
	srv := planeStub(t, &got)
	l := login.Login{Server: srv.URL, Token: "drgl_login"} // #nosec G101 -- a placeholder the test server checks
	_, err := PolicyClient{client: http.DefaultClient}.Check(context.Background(),
		APIDestination{Endpoint: srv.URL, Token: l.Token, Login: &l}, "")
	if err == nil || !strings.Contains(err.Error(), "add `project:` to the descriptor") || len(got) != 0 {
		t.Errorf("err = %v, requests %v", err, got)
	}
}

// A person's API token set in the environment is a person's token like a login's, and the server
// accepts it only on the route naming a project. Its prefix says so; any other token is a pipeline's.
func TestAPersonalTokenInTheEnvironmentChecksThroughTheProjectRoute(t *testing.T) {
	var got []string
	srv := planeStub(t, &got)
	// #nosec G101 -- a placeholder the test server checks, not a credential.
	dest := APIDestination{Endpoint: srv.URL, Token: "drgr_api_person", Project: "payments"}
	if _, err := (PolicyClient{client: http.DefaultClient}).Check(context.Background(), dest, "project: payments\n"); err != nil {
		t.Fatalf("err %v, requests %v", err, got)
	}
	if len(got) != 1 || got[0] != "POST /v1/projects/payments/policy/check Bearer drgr_api_person" {
		t.Errorf("requests = %v", got)
	}
	dest.Project = "billing"
	_, err := PolicyClient{client: http.DefaultClient}.Check(context.Background(), dest, "")
	if err == nil || errors.Is(err, ErrNoPolicyCheck) ||
		!strings.Contains(err.Error(), `has no project "billing" that the token in the environment can reach`) ||
		strings.Contains(err.Error(), "draugr login") {
		t.Errorf("err = %v", err)
	}
	dest.Project = ""
	if _, err := (PolicyClient{client: http.DefaultClient}).Check(context.Background(), dest, ""); err == nil ||
		!strings.Contains(err.Error(), "add `project:`") {
		t.Errorf("err = %v", err)
	}
}
