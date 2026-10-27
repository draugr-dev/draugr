package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// loginServer answers the device routes for https://draugr.example, with a token poll answered by
// outcome: "approved", "denied" or "expired".
type loginServer struct {
	mu      sync.Mutex
	outcome string
	revoked []string
	polls   int
}

func (s *loginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "application/json")
	answer := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch r.URL.Path {
	case "/v1/device/code":
		answer(http.StatusOK, map[string]any{
			"device_code": "dev-123", "user_code": "ABCD-EFGH",
			"verification_uri":          "https://console.example/device",
			"verification_uri_complete": "https://console.example/device/h1",
			"expires_in":                900, "interval": 5,
		})
	case "/v1/device/token":
		s.polls++
		switch {
		case s.polls == 1:
			answer(http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
		case s.outcome == "denied":
			answer(http.StatusBadRequest, map[string]string{"error": "access_denied"})
		case s.outcome == "expired":
			answer(http.StatusBadRequest, map[string]string{"error": "expired_token"})
		case s.outcome == "broken":
			answer(http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "already used"})
		default:
			answer(http.StatusOK, map[string]any{
				"access_token": "drgl_secret", "token_type": "Bearer", "expires_in": 43200,
				"email": "ana@acme.com", "organization": "acme",
			})
		}
	case "/v1/device/revoke":
		s.revoked = append(s.revoked, r.PostForm.Get("token"))
		if s.outcome == "revoke-fails" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

// reroute sends every request to srv, whatever host it names, so a client addressed to
// https://draugr.example reaches the test server.
type reroute struct{ to *url.URL }

func (rr reroute) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host = rr.to.Scheme, rr.to.Host
	return http.DefaultTransport.RoundTrip(out)
}

// loginAt stands the device routes up behind https://draugr.example, on a clock fixed at
// 2026-10-27 18:12 UTC that each poll's wait advances.
func loginAt(t *testing.T, outcome string) *loginServer {
	t.Helper()
	s := &loginServer{outcome: outcome}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	to, _ := url.Parse(srv.URL)
	prev := loginClient
	loginClient = func(server string) (login.Client, error) {
		c, err := login.NewClient(server, login.Device{Name: "build-01.corp.example", Version: "1.2.3"})
		if err != nil {
			return c, err
		}
		now := time.Date(2026, 10, 27, 18, 11, 50, 0, time.UTC)
		c.HTTP = &http.Client{Transport: reroute{to}}
		c.Now = func() time.Time { return now }
		c.Sleep = func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }
		return c, nil
	}
	t.Cleanup(func() { loginClient = prev })
	return s
}

// loginOutput is what `draugr login https://draugr.example` prints, approved. The reference quotes
// it, and TestTheReferenceQuotesTheLoginOutput holds the two together.
const loginOutput = `LOGIN  https://draugr.example
  code     ABCD-EFGH
  open     https://console.example/device
  expires  15m

approved · ana@acme.com · acme · until 06:12 UTC (12h)
`

func TestLoginApproved(t *testing.T) {
	loginAt(t, "approved")
	store := &memoryLogins{}
	useLogins(t, store)
	var out bytes.Buffer
	if err := runLogin(context.Background(), &out, "https://draugr.example"); err != nil {
		t.Fatal(err)
	}
	if out.String() != loginOutput {
		t.Errorf("printed:\n%s\nwant:\n%s", out.String(), loginOutput)
	}
	l, err := store.Get("https://draugr.example")
	if err != nil || l.Token != "drgl_secret" || l.Email != "ana@acme.com" || l.Server != "https://draugr.example" {
		t.Errorf("stored %s, %v", l, err)
	}
	if strings.Contains(out.String(), "drgl_secret") {
		t.Error("the token was printed")
	}
}

func TestLoginNotApproved(t *testing.T) {
	for outcome, want := range map[string]string{
		"denied":  "denied · ABCD-EFGH · nothing stored",
		"expired": "expired · ABCD-EFGH · not approved within 15m · run `draugr login https://draugr.example` again",
		"broken":  "draugr login https://draugr.example: device token: invalid_grant: already used",
	} {
		t.Run(outcome, func(t *testing.T) {
			loginAt(t, outcome)
			store := &memoryLogins{}
			useLogins(t, store)
			var out bytes.Buffer
			err := runLogin(context.Background(), &out, "https://draugr.example")
			if err == nil || err.Error() != want {
				t.Errorf("err = %v, want %q", err, want)
			}
			if len(store.held) != 0 {
				t.Errorf("stored %v", store.held)
			}
		})
	}
}

// Where the keychain will not keep the token, nothing holds it, so it is revoked rather than left
// live until it expires.
func TestALoginTheKeychainWillNotKeepIsRevoked(t *testing.T) {
	s := loginAt(t, "approved")
	useLogins(t, &memoryLogins{setErr: &login.KeychainError{Err: errors.New("no secret service")}})
	var out bytes.Buffer
	err := runLogin(context.Background(), &out, "https://draugr.example")
	if !errors.Is(err, login.ErrNoKeychain) || !strings.Contains(err.Error(), "not stored · token revoked") {
		t.Errorf("err = %v", err)
	}
	if len(s.revoked) != 1 || s.revoked[0] != "drgl_secret" {
		t.Errorf("revoked %v", s.revoked)
	}
	if strings.Contains(out.String(), "approved") {
		t.Errorf("printed approved:\n%s", out.String())
	}

	s.outcome = "revoke-fails"
	s.polls = 0
	err = runLogin(context.Background(), &out, "https://draugr.example")
	if !errors.Is(err, login.ErrNoKeychain) || !strings.Contains(err.Error(), "revoke") {
		t.Errorf("a failed revocation is said too: %v", err)
	}
}

func TestLoginOffline(t *testing.T) {
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
	var out bytes.Buffer
	err := runLogin(context.Background(), &out, "https://draugr.example")
	var refused *netpolicy.RefusedError
	if !errors.As(err, &refused) {
		t.Errorf("err = %v", err)
	}
}

func TestLoginRefusesPlainHTTP(t *testing.T) {
	err := runLogin(context.Background(), &bytes.Buffer{}, "http://draugr.example")
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("err = %v", err)
	}
}

func TestLogout(t *testing.T) {
	ana := login.Login{Server: "https://draugr.example", Token: "drgl_secret", Email: "ana@acme.com",
		Organization: "acme", Expires: time.Date(2026, 10, 28, 6, 12, 0, 0, time.UTC)}
	held := func() *memoryLogins {
		return &memoryLogins{held: map[string]login.Login{"https://draugr.example": ana}}
	}

	t.Run("revoked and removed", func(t *testing.T) {
		s := loginAt(t, "")
		store := held()
		useLogins(t, store)
		var out bytes.Buffer
		if err := runLogout(context.Background(), &out, "https://draugr.example/"); err != nil {
			t.Fatal(err)
		}
		if got, want := out.String(), "logged out · https://draugr.example · ana@acme.com · acme · token revoked\n"; got != want {
			t.Errorf("printed %q, want %q", got, want)
		}
		if len(s.revoked) != 1 || s.revoked[0] != "drgl_secret" || len(store.held) != 0 {
			t.Errorf("revoked %v, held %v", s.revoked, store.held)
		}
	})
	t.Run("not logged in", func(t *testing.T) {
		s := loginAt(t, "")
		useLogins(t, &memoryLogins{})
		var out bytes.Buffer
		if err := runLogout(context.Background(), &out, "https://draugr.example"); err != nil {
			t.Fatal(err)
		}
		if out.String() != "not logged in · https://draugr.example\n" || len(s.revoked) != 0 {
			t.Errorf("printed %q, revoked %v", out.String(), s.revoked)
		}
	})
	t.Run("the server cannot be told", func(t *testing.T) {
		loginAt(t, "revoke-fails")
		store := held()
		useLogins(t, store)
		err := runLogout(context.Background(), &bytes.Buffer{}, "https://draugr.example")
		if err == nil || !strings.Contains(err.Error(),
			"not revoked · https://draugr.example · removed from the keychain · valid until 06:12 UTC") {
			t.Errorf("err = %v", err)
		}
		if len(store.held) != 0 {
			t.Error("the login stays in the keychain")
		}
	})
	t.Run("offline", func(t *testing.T) {
		s := loginAt(t, "")
		netpolicy.SetOffline(true)
		t.Cleanup(func() { netpolicy.SetOffline(false) })
		store := held()
		useLogins(t, store)
		err := runLogout(context.Background(), &bytes.Buffer{}, "https://draugr.example")
		if err == nil || !strings.Contains(err.Error(), "not revoked") || len(s.revoked) != 0 || len(store.held) != 0 {
			t.Errorf("err = %v, revoked %v", err, s.revoked)
		}
	})
	t.Run("a keychain that cannot be read", func(t *testing.T) {
		useLogins(t, &memoryLogins{getErr: &login.KeychainError{Err: errors.New("no secret service")}})
		if err := runLogout(context.Background(), &bytes.Buffer{}, "https://draugr.example"); !errors.Is(err, login.ErrNoKeychain) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestServerArg(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "")
	if _, err := serverArg(nil); err == nil || !strings.Contains(err.Error(), "$DRAUGR_API_URL") {
		t.Errorf("err = %v", err)
	}
	if _, err := serverArg([]string{"draugr.example"}); err == nil {
		t.Error("an address with no scheme")
	}
	t.Setenv("DRAUGR_API_URL", "https://env.example/")
	if s, err := serverArg(nil); err != nil || s != "https://env.example" {
		t.Errorf("%q, %v", s, err)
	}
	if s, err := serverArg([]string{"https://draugr.example"}); err != nil || s != "https://draugr.example" {
		t.Errorf("%q, %v", s, err)
	}
}

func TestLoginCommandsAreWired(t *testing.T) {
	loginAt(t, "approved")
	store := &memoryLogins{}
	useLogins(t, store)
	t.Setenv("DRAUGR_API_URL", "")
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"login", "https://draugr.example"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.held) != 1 {
		t.Errorf("held %v", store.held)
	}
	root = newRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"logout", "https://draugr.example"})
	if err := root.ExecuteContext(context.Background()); err != nil || len(store.held) != 0 {
		t.Errorf("logout: %v, held %v", err, store.held)
	}
	for _, args := range [][]string{{"login"}, {"logout"}} {
		root = newRootCommand()
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		if err := root.ExecuteContext(context.Background()); err == nil {
			t.Errorf("%v with no server and no $DRAUGR_API_URL", args)
		}
	}
}

// doctorLoginOutput is doctor's POLICY heading and the line naming whose login asked. The reference
// quotes it.
const doctorLoginOutput = `POLICY  payments · version 7 · https://draugr.example
  login  ana@acme.com · acme · until 06:12 UTC
`

// A person checking a descriptor on their own machine, with no token in the environment, is asked
// for with their login, and doctor says whose it was.
func TestDoctorUsesTheLoginWhereNoTokenIsSet(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "")
	t.Setenv("DRAUGR_API_TOKEN", "")
	useLogins(t, &memoryLogins{held: map[string]login.Login{"https://draugr.example": {
		Server: "https://draugr.example", Token: "drgl_secret", Email: "ana@acme.com", Organization: "acme",
		Expires: time.Now().UTC().Truncate(24 * time.Hour).Add(48*time.Hour + 6*time.Hour + 12*time.Minute),
	}}})
	var sent []string
	prev := policyChecker
	policyChecker = func(_ context.Context, dest publish.APIDestination, _ string) (skald.PolicyOutcome, error) {
		sent = append(sent, dest.Token)
		return skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "none"}, nil
	}
	t.Cleanup(func() { policyChecker = prev })
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, publishingSaga),
		doctorRun{requirePolicy: true}, fakeDetect("trivy", "git"), nil); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0] != "drgl_secret" {
		t.Errorf("sent %v", sent)
	}
	if !strings.Contains(out.String(), doctorLoginOutput) {
		t.Errorf("doctor does not say whose login asked:\n%s", out.String())
	}
}

// The pipeline's token wins over a login on the same machine, and the keychain is not read.
func TestThePreflightPrefersTheCIToken(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	store := &memoryLogins{held: map[string]login.Login{"https://draugr.example": {
		Server: "https://draugr.example", Token: "drgl_secret", Expires: time.Now().Add(time.Hour),
	}}}
	useLogins(t, store)
	var sent []string
	prev := policyChecker
	policyChecker = func(_ context.Context, dest publish.APIDestination, _ string) (skald.PolicyOutcome, error) {
		sent = append(sent, dest.Token)
		return skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "none"}, nil
	}
	t.Cleanup(func() { policyChecker = prev })
	m, err := saga.Load([]byte(publishingSaga))
	if err != nil {
		t.Fatal(err)
	}
	p, used, err := checkOrgPolicyAs(context.Background(), m, "project: payments", "")
	if err != nil || !p.Checked || len(used) != 0 || len(sent) != 1 || sent[0] != "drgr_ci_test" || store.reads != 0 {
		t.Errorf("checked %+v, logins %v, sent %v, %d keychain reads, %v", p, used, sent, store.reads, err)
	}
}

// A CI job has its own token and no person's keychain, so it never reads one.
func TestAPipelineNeverReadsTheKeychain(t *testing.T) {
	prev := inPipeline
	inPipeline = func() bool { return true }
	t.Cleanup(func() { inPipeline = prev })
	if policyLogins() != nil {
		t.Error("a pipeline read the keychain")
	}
	inPipeline = func() bool { return false }
	if policyLogins() == nil {
		t.Error("a person's machine reads the keychain")
	}
}

// What the reference shows `draugr login` and doctor printing is what the tests above produce.
func TestTheReferenceQuotesTheLoginOutput(t *testing.T) {
	doc, err := os.ReadFile("../../docs/reference/cli.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"$ draugr login https://draugr.example\n" + loginOutput,
		doctorLoginOutput,
		"denied · ABCD-EFGH · nothing stored",
		"expired · ABCD-EFGH · not approved within 15m · run `draugr login https://draugr.example` again",
		"logged out · https://draugr.example · ana@acme.com · acme · token revoked",
	} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("docs/reference/cli.md does not quote:\n%s", want)
		}
	}
}
