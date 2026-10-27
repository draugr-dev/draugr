package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// deviceServer answers the device routes the way the server's contract says, polling through the
// answers it is given in order.
type deviceServer struct {
	t     *testing.T
	mu    sync.Mutex
	polls []func(http.ResponseWriter)
	seen  []*http.Request
	forms []map[string]string
}

func (d *deviceServer) handler(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		d.t.Error(err)
	}
	form := map[string]string{}
	for k := range r.PostForm {
		form[k] = r.PostForm.Get(k)
	}
	d.seen = append(d.seen, r)
	d.forms = append(d.forms, form)
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/v1/device/code":
		if form["client_id"] != ClientID {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "")
			return
		}
		writeJSON(w, map[string]any{
			"device_code": "dev-123", "user_code": "ABCD-EFGH",
			"verification_uri":          "https://console.example/#/device",
			"verification_uri_complete": "https://console.example/#/device/h1",
			"expires_in":                900, "interval": 5,
		})
	case "/v1/device/token":
		if len(d.polls) == 0 {
			d.t.Error("polled after the last answer")
			oauthError(w, http.StatusBadRequest, "expired_token", "")
			return
		}
		next := d.polls[0]
		d.polls = d.polls[1:]
		next(w)
	case "/v1/device/revoke":
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func pending(w http.ResponseWriter) {
	oauthError(w, http.StatusBadRequest, "authorization_pending", "")
}
func slowDown(w http.ResponseWriter) { oauthError(w, http.StatusBadRequest, "slow_down", "") }

func approved(w http.ResponseWriter) {
	writeJSON(w, map[string]any{
		"access_token": "drgl_secret", "token_type": "Bearer", "expires_in": 43200,
		"scope": "check", "email": "ana@acme.com", "organization": "acme",
	})
}

// testClient is a client for srv whose sleeps are recorded rather than waited, on a fixed clock that
// each sleep advances.
func testClient(t *testing.T, srv *httptest.Server) (Client, *[]time.Duration) {
	t.Helper()
	c, err := NewClient(srv.URL+"/", Device{Name: "build-01.corp.example", Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 27, 18, 12, 0, 0, time.UTC)
	var slept []time.Duration
	c.Now = func() time.Time { return now }
	c.Sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		now = now.Add(d)
		return nil
	}
	return c, &slept
}

func startDevice(t *testing.T, polls ...func(http.ResponseWriter)) (*deviceServer, Client, *[]time.Duration) {
	t.Helper()
	d := &deviceServer{t: t, polls: polls}
	srv := httptest.NewServer(http.HandlerFunc(d.handler))
	t.Cleanup(srv.Close)
	c, slept := testClient(t, srv)
	return d, c, slept
}

func TestAuthorizeSendsTheContractsFields(t *testing.T) {
	d, c, _ := startDevice(t)
	a, err := c.Authorize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.UserCode != "ABCD-EFGH" || a.DeviceCode != "dev-123" || a.Lifetime() != 15*time.Minute ||
		a.VerificationURIComplete != "https://console.example/#/device/h1" {
		t.Errorf("authorization = %+v", a)
	}
	f := d.forms[0]
	want := map[string]string{
		"client_id": "draugr-cli", "scope": "check", "device_name": "build-01.corp.example",
		"client_version": "1.2.3", "client_os": runtime.GOOS + "/" + runtime.GOARCH,
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %q, want %q", k, f[k], v)
		}
	}
	r := d.seen[0]
	if got := r.Header.Get("User-Agent"); got != "draugr/1.2.3 ("+runtime.GOOS+"/"+runtime.GOARCH+")" {
		t.Errorf("User-Agent = %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got)
	}
	if r.Method != http.MethodPost {
		t.Errorf("method = %s", r.Method)
	}
}

func TestAuthorizeRefusedClient(t *testing.T) {
	// A server that does not know the client answers 401.
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
	}))
	defer h.Close()
	c, _ := testClient(t, h)
	if _, err := c.Authorize(context.Background()); !errors.Is(err, ErrInvalidClient) {
		t.Errorf("err = %v, want invalid_client", err)
	}
}

func TestAuthorizeIncompleteAnswer(t *testing.T) {
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"device_code": "x"})
	}))
	defer h.Close()
	c, _ := testClient(t, h)
	if _, err := c.Authorize(context.Background()); err == nil || !strings.Contains(err.Error(), "no device code") {
		t.Errorf("err = %v", err)
	}
}

func TestWait(t *testing.T) {
	auth := Authorization{DeviceCode: "dev-123", UserCode: "ABCD-EFGH", ExpiresIn: 900, Interval: 5}

	t.Run("pending, then approved", func(t *testing.T) {
		d, c, slept := startDevice(t, pending, pending, approved)
		l, err := c.Wait(context.Background(), auth)
		if err != nil {
			t.Fatal(err)
		}
		if l.Token != "drgl_secret" || l.Email != "ana@acme.com" || l.Organization != "acme" || l.Server != c.Server {
			t.Errorf("login = %s", l)
		}
		// Three polls, each 5s after the last, and 12h from the clock at the approval.
		if want := time.Date(2026, 10, 28, 6, 12, 15, 0, time.UTC); !l.Expires.Equal(want) {
			t.Errorf("expires %s, want %s", l.Expires, want)
		}
		if len(*slept) != 3 || (*slept)[0] != 5*time.Second || (*slept)[2] != 5*time.Second {
			t.Errorf("slept %v", *slept)
		}
		f := d.forms[0]
		if f["grant_type"] != "urn:ietf:params:oauth:grant-type:device_code" || f["device_code"] != "dev-123" ||
			f["client_id"] != ClientID {
			t.Errorf("poll form = %v", f)
		}
	})
	t.Run("slow_down adds five seconds each time", func(t *testing.T) {
		_, c, slept := startDevice(t, slowDown, slowDown, pending, approved)
		if _, err := c.Wait(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		want := []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second, 15 * time.Second}
		if len(*slept) != len(want) {
			t.Fatalf("slept %v, want %v", *slept, want)
		}
		for i := range want {
			if (*slept)[i] != want[i] {
				t.Errorf("slept %v, want %v", *slept, want)
			}
		}
	})
	t.Run("no interval waits five seconds", func(t *testing.T) {
		_, c, slept := startDevice(t, approved)
		if _, err := c.Wait(context.Background(), Authorization{DeviceCode: "d"}); err != nil {
			t.Fatal(err)
		}
		if (*slept)[0] != 5*time.Second {
			t.Errorf("slept %v", *slept)
		}
	})
	t.Run("denied", func(t *testing.T) {
		_, c, _ := startDevice(t, pending, func(w http.ResponseWriter) {
			oauthError(w, http.StatusBadRequest, "access_denied", "")
		})
		if _, err := c.Wait(context.Background(), auth); !errors.Is(err, ErrDenied) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) {
			oauthError(w, http.StatusBadRequest, "expired_token", "")
		})
		if _, err := c.Wait(context.Background(), auth); !errors.Is(err, ErrExpired) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a server that never expires the code", func(t *testing.T) {
		polls := make([]func(http.ResponseWriter), 3)
		for i := range polls {
			polls[i] = pending
		}
		_, c, _ := startDevice(t, polls...)
		if _, err := c.Wait(context.Background(), Authorization{DeviceCode: "d", ExpiresIn: 12, Interval: 5}); !errors.Is(err, ErrExpired) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("invalid_grant stops with the server's description", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "the device code was already used")
		})
		_, err := c.Wait(context.Background(), auth)
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != "invalid_grant" || !strings.Contains(err.Error(), "already used") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("unsupported_grant_type", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) {
			oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		})
		if _, err := c.Wait(context.Background(), auth); err == nil || !strings.Contains(err.Error(), "unsupported_grant_type") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("invalid_client", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) {
			oauthError(w, http.StatusUnauthorized, "invalid_client", "")
		})
		if _, err := c.Wait(context.Background(), auth); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a status with no OAuth body", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) })
		if _, err := c.Wait(context.Background(), auth); err == nil || !strings.Contains(err.Error(), "502") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no token in the answer", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) { writeJSON(w, map[string]any{"token_type": "Bearer"}) })
		if _, err := c.Wait(context.Background(), auth); err == nil || !strings.Contains(err.Error(), "no access token") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a token that is not a bearer token", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) {
			writeJSON(w, map[string]any{"access_token": "x", "token_type": "mac"})
		})
		if _, err := c.Wait(context.Background(), auth); err == nil || !strings.Contains(err.Error(), "bearer") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("an answer that is not JSON", func(t *testing.T) {
		_, c, _ := startDevice(t, func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) })
		if _, err := c.Wait(context.Background(), auth); err == nil || !strings.Contains(err.Error(), "unreadable") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("canceled while waiting", func(t *testing.T) {
		_, c, _ := startDevice(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.Sleep = nil
		if _, err := c.Wait(ctx, auth); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestRevoke(t *testing.T) {
	d, c, _ := startDevice(t)
	if err := c.Revoke(context.Background(), "drgl_secret"); err != nil {
		t.Fatal(err)
	}
	if f := d.forms[0]; f["token"] != "drgl_secret" || f["token_type_hint"] != "access_token" || d.seen[0].URL.Path != "/v1/device/revoke" {
		t.Errorf("revoke sent %v to %s", f, d.seen[0].URL.Path)
	}

	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer h.Close()
	c.Server = h.URL
	if err := c.Revoke(context.Background(), "drgl_secret"); err == nil || !strings.Contains(err.Error(), "revoke") {
		t.Errorf("err = %v", err)
	}
}

// Each body carries a device code or a token, so a redirect is answered rather than followed.
func TestNoRedirectIsFollowed(t *testing.T) {
	followed := false
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer elsewhere.Close()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect) // #nosec G710 -- a test server redirecting to another test server
	}))
	defer h.Close()
	c, _ := testClient(t, h)
	if err := c.Revoke(context.Background(), "drgl_secret"); err == nil || followed {
		t.Errorf("err = %v, followed = %v", err, followed)
	}
}

func TestNewClientRefusesPlainHTTPElsewhere(t *testing.T) {
	if _, err := NewClient("http://draugr.example", Device{}); err == nil {
		t.Error("a token must not come back over plain http from another machine")
	}
	if _, err := NewClient("ftp://draugr.example", Device{}); err == nil {
		t.Error("not an http address")
	}
	c, err := NewClient(" https://draugr.example/ ", Device{})
	if err != nil || c.Server != "https://draugr.example" {
		t.Errorf("client = %+v, %v", c, err)
	}
}

func TestOAuthErrorText(t *testing.T) {
	cases := map[string]*OAuthError{
		"502 Bad Gateway":     {Status: "502 Bad Gateway"},
		"invalid_grant":       {Code: "invalid_grant"},
		"invalid_grant: used": {Code: "invalid_grant", Description: "used"},
	}
	for want, e := range cases {
		if e.Error() != want {
			t.Errorf("%#v = %q, want %q", e, e.Error(), want)
		}
	}
}
