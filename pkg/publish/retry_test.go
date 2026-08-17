package publish

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recordingSleeper stands in for time.Sleep so a backoff can be asserted without waiting it out.
type recordingSleeper struct{ waits []time.Duration }

func (r *recordingSleeper) sleep(d time.Duration) { r.waits = append(r.waits, d) }

// stubTransport returns queued outcomes in order, and counts what it was asked for.
type stubTransport struct {
	codes   []int
	err     error
	calls   atomic.Int32
	bodies  []string
	methods []string
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n := int(s.calls.Add(1))
	s.methods = append(s.methods, req.Method)
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		s.bodies = append(s.bodies, string(b))
	}
	if s.err != nil {
		return nil, s.err
	}
	code := s.codes[len(s.codes)-1]
	if n-1 < len(s.codes) {
		code = s.codes[n-1]
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
		Request:    req,
	}, nil
}

func newTestClient(t *testing.T, st *stubTransport, sl *recordingSleeper) *http.Client {
	t.Helper()
	return &http.Client{Transport: &retryTransport{base: st, attempts: retryAttempts, sleep: sl.sleep}}
}

// The failure this exists for: a forge answering 503 for a moment turned a clean gate into a red
// check, because the comment was attempted exactly once.
func TestARefusedRequestIsSentAgain(t *testing.T) {
	for _, code := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		st := &stubTransport{codes: []int{code, http.StatusCreated}}
		sl := &recordingSleeper{}
		req, err := http.NewRequestWithContext(context.Background(),
			http.MethodPost, "https://example.test/comments", bytes.NewReader([]byte(`{"body":"x"}`)))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := newTestClient(t, st, sl).Do(req)
		if err != nil {
			t.Fatalf("%d: %v", code, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("%d: final status = %d, want 201", code, resp.StatusCode)
		}
		if got := st.calls.Load(); got != 2 {
			t.Errorf("%d: sent %d times, want 2", code, got)
		}
	}
}

// The body has to survive the rewind, or the retry posts an empty comment and the failure is
// silent — a comment appears, so nothing looks wrong, and it says nothing.
func TestARetriedPostSendsTheSameBody(t *testing.T) {
	st := &stubTransport{codes: []int{http.StatusServiceUnavailable, http.StatusCreated}}
	sl := &recordingSleeper{}
	body := `{"body":"the report"}`
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, "https://example.test/comments", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newTestClient(t, st, sl).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(st.bodies) != 2 {
		t.Fatalf("bodies seen = %d, want 2", len(st.bodies))
	}
	for i, b := range st.bodies {
		if b != body {
			t.Errorf("attempt %d sent %q, want %q", i+1, b, body)
		}
	}
}

// A status that means the server did the work, or refused on the merits, is the answer. Retrying
// a 404 or a 401 changes nothing and delays the message that would have explained it.
func TestAStatusThatIsAnAnswerIsNotRetried(t *testing.T) {
	for _, code := range []int{
		http.StatusOK, http.StatusCreated, http.StatusUnauthorized,
		http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity,
	} {
		st := &stubTransport{codes: []int{code}}
		sl := &recordingSleeper{}
		req, _ := http.NewRequestWithContext(context.Background(),
			http.MethodPost, "https://example.test/c", bytes.NewReader([]byte("{}")))
		resp, err := newTestClient(t, st, sl).Do(req)
		if err != nil {
			t.Fatalf("%d: %v", code, err)
		}
		_ = resp.Body.Close()
		if got := st.calls.Load(); got != 1 {
			t.Errorf("%d: sent %d times, want 1", code, got)
		}
	}
}

// The one that decides between one comment and two.
//
// A POST that never came back may still have created the comment — the forge could have lost the
// reply, not the request. Sending it again would post a second copy of a comment whose whole
// purpose is to be the single current verdict, so a write that vanished is reported rather than
// repeated. A GET has no such cost and is retried.
func TestAWriteThatVanishedIsNotRepeated(t *testing.T) {
	netErr := errors.New("connection reset by peer")

	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut} {
		st := &stubTransport{err: netErr}
		sl := &recordingSleeper{}
		req, _ := http.NewRequestWithContext(context.Background(),
			method, "https://example.test/c", bytes.NewReader([]byte("{}")))
		resp, err := newTestClient(t, st, sl).Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s: expected the transport error to surface", method)
		}
		if got := st.calls.Load(); got != 1 {
			t.Errorf("%s: sent %d times, want 1 — a lost write must not be repeated", method, got)
		}
	}

	st := &stubTransport{err: netErr}
	sl := &recordingSleeper{}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/c", nil)
	getResp, err := newTestClient(t, st, sl).Do(req)
	if err == nil {
		_ = getResp.Body.Close()
		t.Fatal("expected the transport error to surface")
	}
	if got := st.calls.Load(); got != retryAttempts {
		t.Errorf("GET sent %d times, want %d — reading is safe to repeat", got, retryAttempts)
	}
}

// Giving up is part of the contract: the run has to be told, and told quickly.
func TestItGivesUpAndReportsTheLastAnswer(t *testing.T) {
	st := &stubTransport{codes: []int{http.StatusServiceUnavailable}}
	sl := &recordingSleeper{}
	req, _ := http.NewRequestWithContext(context.Background(),
		http.MethodPost, "https://example.test/c", bytes.NewReader([]byte("{}")))
	resp, err := newTestClient(t, st, sl).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want the 503 to survive as the outcome", resp.StatusCode)
	}
	if got := st.calls.Load(); got != retryAttempts {
		t.Errorf("sent %d times, want %d", got, retryAttempts)
	}
	if len(sl.waits) != retryAttempts-1 {
		t.Errorf("slept %d times, want %d", len(sl.waits), retryAttempts-1)
	}
}

// The server is the only party that knows how long it wants; when it says so, that wins.
func TestRetryAfterIsHonoredAndCapped(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   time.Duration
		ok     bool
	}{
		{"seconds", "2", 2 * time.Second, true},
		{"capped", "600", retryMaxDelay, true},
		{"zero", "0", 0, true},
		{"negative is not an answer", "-5", 0, false},
		{"nonsense is not an answer", "soon", 0, false},
		{"absent", "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := retryAfter(c.header)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			capped := min(got, retryMaxDelay)
			if capped != c.want {
				t.Errorf("delay = %v, want %v", capped, c.want)
			}
		})
	}
	// An HTTP date is the other form the spec allows, and a forge does use it.
	if d, ok := retryAfter(time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)); !ok || d <= 0 {
		t.Errorf("an HTTP-date Retry-After should parse to a positive delay, got %v ok=%v", d, ok)
	}
}

// A canceled run stops, rather than sitting out a backoff nobody is waiting for any more.
func TestACanceledContextStopsTheRetries(t *testing.T) {
	st := &stubTransport{codes: []int{http.StatusServiceUnavailable}}
	sl := &recordingSleeper{}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/c", nil)
	cancel()
	cancelResp, err := newTestClient(t, st, sl).Do(req)
	if err == nil {
		_ = cancelResp.Body.Close()
		t.Fatal("expected the cancellation to surface")
	}
	if got := st.calls.Load(); got > 1 {
		t.Errorf("sent %d times after cancellation, want at most 1", got)
	}
}

// The backoff grows and stays inside the cap, so a retry never becomes the reason a run is slow.
func TestTheBackoffGrowsWithinTheCap(t *testing.T) {
	tr := &retryTransport{attempts: retryAttempts, sleep: func(time.Duration) {}}
	var prev time.Duration
	for attempt := 1; attempt <= 6; attempt++ {
		d := tr.backoff(attempt, nil)
		if d <= 0 {
			t.Fatalf("attempt %d: delay %v, want positive", attempt, d)
		}
		// The cap plus its jitter allowance.
		if d > retryMaxDelay+retryMaxDelay/4 {
			t.Errorf("attempt %d: delay %v exceeds the cap %v", attempt, d, retryMaxDelay)
		}
		if attempt > 1 && attempt <= 4 && d < prev {
			t.Errorf("attempt %d: delay %v is shorter than the previous %v", attempt, d, prev)
		}
		prev = d
	}
}

// End to end against a real server, so the wiring is proved rather than the stub.
func TestTheRetryingClientRecoversAgainstARealServer(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "the report") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := newRetryingClient(&http.Client{Timeout: 10 * time.Second})
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, srv.URL, bytes.NewReader([]byte(`{"body":"the report"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201 after the retry", resp.StatusCode)
	}
	if hits.Load() != 2 {
		t.Errorf("server saw %d requests, want 2", hits.Load())
	}
}

// The caller's own settings have to survive being wrapped, or a timeout somebody set is quietly
// dropped and the retry loop is the thing that hangs.
func TestWrappingKeepsTheCallersSettings(t *testing.T) {
	orig := &http.Client{Timeout: 7 * time.Second}
	got := newRetryingClient(orig)
	if got.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want it preserved", got.Timeout)
	}
	if got == orig {
		t.Error("the caller's client was modified in place rather than copied")
	}
	if _, ok := got.Transport.(*retryTransport); !ok {
		t.Errorf("transport = %T, want the retrying one", got.Transport)
	}
	if nilClient := newRetryingClient(nil); nilClient == nil {
		t.Error("a nil client should still produce a usable one")
	}
}
