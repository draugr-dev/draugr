package publish

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeClock is a clock that moves only when the transport sleeps, so paced waits can be asserted
// as durations without waiting them out.
type fakeClock struct {
	at    time.Time
	waits []time.Duration
}

func (c *fakeClock) now() time.Time { return c.at }
func (c *fakeClock) sleep(d time.Duration) {
	c.waits = append(c.waits, d)
	c.at = c.at.Add(d)
}

// answer is one queued response: a status and the headers it carries.
type answer struct {
	code   int
	header map[string]string
}

// answerStub returns queued answers in order and records when each request arrived.
type answerStub struct {
	clock   *fakeClock
	answers []answer
	sent    []time.Time
	methods []string
}

func (s *answerStub) RoundTrip(req *http.Request) (*http.Response, error) {
	n := len(s.sent)
	s.sent = append(s.sent, s.clock.at)
	s.methods = append(s.methods, req.Method)
	a := s.answers[min(n, len(s.answers)-1)]
	h := http.Header{}
	for k, v := range a.header {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: a.code, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func pacedClient(stub *answerStub) *http.Client {
	return &http.Client{Transport: &retryTransport{
		base: stub, attempts: retryAttempts, sleep: stub.clock.sleep,
		pace: &pacing{maxWait: issueMaxWait, budget: issueWaitBudget, writeGap: issueWriteGap, now: stub.clock.now},
	}}
}

// send makes one request and reports its status, 0 when it failed.
func send(t *testing.T, c *http.Client, method string) (int, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, "https://forge.test/issues", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func newClock() *fakeClock { return &fakeClock{at: time.Unix(1_800_000_000, 0)} }

// GitHub's secondary limit answers 403. With its headers it is a limit to wait out; without them it
// is a permission error, and retrying one only delays the message that names the permission.
func TestAForbiddenIsRetriedOnlyWhenItIsARateLimit(t *testing.T) {
	clock := newClock()
	reset := strconv.FormatInt(clock.at.Add(20*time.Second).Unix(), 10)
	cases := []struct {
		name    string
		first   answer
		sends   int
		waitFor time.Duration
	}{
		{"retry-after", answer{403, map[string]string{"Retry-After": "7"}}, 2, 7 * time.Second},
		{"remaining zero", answer{403, map[string]string{"X-Ratelimit-Remaining": "0", "X-Ratelimit-Reset": reset}}, 2, 20 * time.Second},
		{"permission", answer{403, nil}, 1, 0},
		{"remaining zero, no reset", answer{403, map[string]string{"X-Ratelimit-Remaining": "0"}}, 1, 0},
		{"remaining left", answer{403, map[string]string{"X-Ratelimit-Remaining": "12", "X-Ratelimit-Reset": reset}}, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClock()
			stub := &answerStub{clock: c, answers: []answer{tc.first, {201, nil}}}
			status, err := send(t, pacedClient(stub), http.MethodPost)
			if err != nil {
				t.Fatal(err)
			}
			if len(stub.sent) != tc.sends {
				t.Fatalf("sent %d times, want %d", len(stub.sent), tc.sends)
			}
			if tc.sends == 1 && status != http.StatusForbidden {
				t.Errorf("status = %d, want the 403 reported as it came", status)
			}
			if tc.sends == 2 {
				if got := stub.sent[1].Sub(stub.sent[0]); got != tc.waitFor {
					t.Errorf("waited %s before retrying, want %s", got, tc.waitFor)
				}
			}
		})
	}
}

// An ordinary client keeps treating every 403 as final, whatever headers it carries.
func TestAnUnpacedClientDoesNotRetryAForbidden(t *testing.T) {
	st := &stubTransport{codes: []int{403, 201}}
	sl := &recordingSleeper{}
	resp, err := newTestClient(t, st, sl).Get("https://forge.test/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if st.calls.Load() != 1 {
		t.Errorf("sent %d times, want 1", st.calls.Load())
	}
}

// GitLab's application limits answer 429 with no Retry-After, and the documented wait is a minute.
func TestATooManyRequestsNamingNoWaitWaitsAMinute(t *testing.T) {
	c := newClock()
	stub := &answerStub{clock: c, answers: []answer{{429, nil}, {201, nil}}}
	if _, err := send(t, pacedClient(stub), http.MethodPost); err != nil {
		t.Fatal(err)
	}
	if len(stub.sent) != 2 || stub.sent[1].Sub(stub.sent[0]) != rateLimitDefaultWait {
		t.Errorf("sends at %v, want two a minute apart", stub.sent)
	}
}

// Azure sends Retry-After on a 200 while it is delaying requests, so the next request waits even
// though nothing failed.
func TestRetryAfterOnASuccessDelaysTheNextRequest(t *testing.T) {
	c := newClock()
	stub := &answerStub{clock: c, answers: []answer{{200, map[string]string{"Retry-After": "5"}}, {200, nil}}}
	client := pacedClient(stub)
	for range 2 {
		if _, err := send(t, client, http.MethodGet); err != nil {
			t.Fatal(err)
		}
	}
	if got := stub.sent[1].Sub(stub.sent[0]); got != 5*time.Second {
		t.Errorf("second request sent %s after the first, want 5s", got)
	}
}

// GitHub asks for writes at least a second apart. Reads are not spaced.
func TestWritesAreSpacedAndReadsAreNot(t *testing.T) {
	c := newClock()
	stub := &answerStub{clock: c, answers: []answer{{200, nil}}}
	client := pacedClient(stub)
	for _, m := range []string{http.MethodPost, http.MethodGet, http.MethodPatch, http.MethodGet} {
		if _, err := send(t, client, m); err != nil {
			t.Fatal(err)
		}
	}
	if got := stub.sent[1].Sub(stub.sent[0]); got != 0 {
		t.Errorf("a read waited %s after a write, want no wait", got)
	}
	if got := stub.sent[2].Sub(stub.sent[0]); got != issueWriteGap {
		t.Errorf("writes %s apart, want %s", got, issueWriteGap)
	}
	if got := stub.sent[3].Sub(stub.sent[2]); got != 0 {
		t.Errorf("a read waited %s, want no wait", got)
	}
}

// A limit that asks for longer than the cap is still in force when a capped wait ends, so the
// answer is reported at once rather than after a minute spent learning nothing.
func TestAWaitPastTheCapIsReportedNotWaited(t *testing.T) {
	c := newClock()
	stub := &answerStub{clock: c, answers: []answer{{429, map[string]string{"Retry-After": "600"}}, {201, nil}}}
	status, err := send(t, pacedClient(stub), http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusTooManyRequests || len(stub.sent) != 1 {
		t.Errorf("status %d after %d sends, want the 429 after one", status, len(stub.sent))
	}
}

// Across a run, waiting stops at the budget. The retry that would exceed it is not made, and a
// request whose turn is past the budget fails naming the limit.
func TestWaitingStopsAtTheBudget(t *testing.T) {
	c := newClock()
	limited := answer{429, map[string]string{"Retry-After": "50"}}
	stub := &answerStub{clock: c, answers: []answer{limited}}
	client := pacedClient(stub)

	var sends int
	var lastErr error
	for range 4 {
		before := len(stub.sent)
		_, lastErr = send(t, client, http.MethodGet)
		sends += len(stub.sent) - before
		if lastErr != nil {
			break
		}
	}
	var total time.Duration
	for _, w := range c.waits {
		total += w
	}
	if total > issueWaitBudget {
		t.Errorf("waited %s in total, over the %s budget", total, issueWaitBudget)
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "3m0s") {
		t.Errorf("err = %v, want one naming the budget", lastErr)
	}
	if sends == 0 {
		t.Error("nothing was sent")
	}
}

// A canceled context during a paced wait stops the request.
func TestACanceledContextStopsAPacedWait(t *testing.T) {
	c := newClock()
	stub := &answerStub{clock: c, answers: []answer{{200, nil}}}
	ctx, cancel := context.WithCancel(context.Background())
	client := &http.Client{Transport: &retryTransport{
		base: stub, attempts: retryAttempts,
		sleep: func(d time.Duration) { c.sleep(d); cancel() },
		pace:  &pacing{maxWait: issueMaxWait, budget: issueWaitBudget, writeGap: issueWriteGap, now: c.now},
	}}
	for i := range 2 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://forge.test/x", strings.NewReader("{}"))
		resp, err := client.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if i == 1 && err == nil {
			t.Error("the second write was sent after its context was canceled")
		}
	}
	if len(stub.sent) != 1 {
		t.Errorf("sent %d, want 1", len(stub.sent))
	}
}

func TestTheIssueClientIsPaced(t *testing.T) {
	c := newIssueClient(&http.Client{Timeout: time.Second})
	rt, ok := c.Transport.(*retryTransport)
	if !ok || rt.pace == nil {
		t.Fatalf("transport = %T, want a paced retryTransport", c.Transport)
	}
	if rt.pace.maxWait != issueMaxWait || rt.pace.budget != issueWaitBudget || rt.pace.writeGap != issueWriteGap {
		t.Errorf("pacing = %+v", rt.pace)
	}
	if c.Timeout != time.Second {
		t.Errorf("timeout = %s, the caller's setting was lost", c.Timeout)
	}
}
