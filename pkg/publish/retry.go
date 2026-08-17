package publish

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// retryAttempts is how many times a request is sent in total, first try included. Three is chosen
// against what it is for: a forge returning 503 is usually shedding load for seconds, not minutes,
// and a scan holding a CI runner open is not the place to wait one out. Two retries covers the
// blip and gives up long before anybody would rather have been told.
const retryAttempts = 3

// retryBaseDelay is the first backoff, doubled each attempt and jittered. Small, because the
// requests being retried are a handful of comment reads and one write — there is no herd here to
// protect, only a moment to let pass.
const retryBaseDelay = 500 * time.Millisecond

// retryMaxDelay caps a Retry-After the server asks for. A forge under maintenance can name a
// delay in minutes; honoring that literally would hold a runner open for a comment. Past the cap
// the run reports that delivery failed, which is a truthful outcome reached quickly.
const retryMaxDelay = 8 * time.Second

// retryableStatus reports whether a status means "not processed, ask again".
//
// Every one of these is the server declining before it did the work: 429 is a rate limit, and the
// 502/503/504 family is a proxy or a backend that never reached the handler. That is what makes a
// retry safe on a POST as well as a GET — the request was refused, not applied, so sending it
// again cannot produce a second comment.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryTransport re-sends a request that a forge refused, rather than reporting a delivery failure
// the first time a proxy has a bad second.
//
// Wrapped around a client rather than written at each call site: the publishers make several
// requests each — list the comments, follow a page, then post or patch — and a retry that covers
// only the last of them still fails the run on the first.
//
// What it will not retry is a transport error with no response, on anything but a GET. A request
// that never came back is a request whose fate is unknown: the forge may have created the comment
// and lost the reply. Retrying that risks posting twice, and two comments on a pull request is a
// worse outcome than one honest failure — the sticky comment exists so a reader sees one current
// verdict, not a history of attempts.
type retryTransport struct {
	base     http.RoundTripper
	attempts int
	// sleep is time.Sleep in production and a recorder in tests, so the backoff can be asserted
	// without waiting it out.
	sleep func(time.Duration)
}

// newRetryingClient returns a client that retries a refused request. It copies the given client so
// a caller's timeout and any other settings survive.
func newRetryingClient(c *http.Client) *http.Client {
	if c == nil {
		c = http.DefaultClient
	}
	out := *c
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	out.Transport = &retryTransport{base: base, attempts: retryAttempts, sleep: time.Sleep}
	return &out
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	attempts := max(t.attempts, 1)
	var resp *http.Response
	var err error

	for attempt := 1; ; attempt++ {
		// A body has to be rewound before it can be sent again. NewRequest fills GetBody for the
		// in-memory readers these publishers use; anything else is sent once and reported as it
		// comes back, because replaying a stream nobody can rewind is not possible to do quietly.
		if attempt > 1 && req.Body != nil {
			if req.GetBody == nil {
				return resp, err
			}
			body, gerr := req.GetBody()
			if gerr != nil {
				return resp, err
			}
			req.Body = body
		}

		resp, err = t.base.RoundTrip(req)

		if attempt >= attempts || !t.worthRetrying(req, resp, err) {
			return resp, err
		}

		wait := t.backoff(attempt, resp)
		// Draining and closing matters before a retry: an undrained body holds the connection out
		// of the pool, so a retry loop leaks one per attempt.
		if resp != nil {
			_ = resp.Body.Close()
		}
		slog.Debug("retrying request",
			"method", req.Method, "attempt", attempt, "of", attempts, "wait", wait)

		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}
		t.sleep(wait)
		if cerr := req.Context().Err(); cerr != nil {
			return nil, cerr
		}
	}
}

// worthRetrying decides whether this outcome is one more attempt might fix.
func (t *retryTransport) worthRetrying(req *http.Request, resp *http.Response, err error) bool {
	if err != nil {
		// A canceled or expired context is the caller's decision, not a failure to route around.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		// See the type's doc: only a GET is safe to repeat when nothing came back.
		return req.Method == http.MethodGet
	}
	return resp != nil && retryableStatus(resp.StatusCode)
}

// backoff is how long to wait before the next attempt: the server's own Retry-After when it names
// one, otherwise an exponential delay with jitter.
//
// Retry-After wins because it is the only party that knows. Jitter on the fallback because a
// pipeline that fans out several scans would otherwise have all of them come back at once, which
// is the shape that turns a blip into a queue.
func (t *retryTransport) backoff(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if d, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			return min(d, retryMaxDelay)
		}
	}
	delay := min(retryBaseDelay<<(attempt-1), retryMaxDelay)
	// Up to a quarter of the delay again, so concurrent callers separate.
	return delay + time.Duration(rand.Int64N(int64(delay/4)+1)) //#nosec G404 -- jitter, not a secret
}

// retryAfter reads the header in both forms the spec allows: a count of seconds, or an HTTP date.
func retryAfter(v string) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		d := time.Until(when)
		if d < 0 {
			return 0, true // a date already past means "now"
		}
		return d, true
	}
	return 0, false
}
