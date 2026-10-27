package publish

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// pollAnswer is one answer to GET /v1/ingest/runs/{id}/policy.
type pollAnswer struct {
	status int
	header map[string]string
	body   string
}

// pendingLicenses is a setting in force the server decides once the run's evidence is expanded.
var pendingLicenses = map[string]any{
	"rule": "licenses", "profile": "Default", "state": "not_evaluated", "cause": "server",
	"detail": "the run's evidence is not expanded into findings yet", "mode": "enforce",
	"enforceFrom": "2026-10-01", "response": "fail", "profileState": "active", "inForce": true,
	"acts": "none", "pending": true,
}

// brokenLicenses is the same setting decided: the run's findings break it.
var brokenLicenses = map[string]any{
	"rule": "licenses", "profile": "Default", "state": "violates", "mode": "enforce",
	"enforceFrom": "2026-10-01", "response": "fail", "inForce": true, "acts": "fail",
	"items": []any{map[string]any{"field": "license", "found": "AGPL-3.0", "constraint": "forbidden",
		"expected": "AGPL-3.0", "breaks": true}},
}

// metLicenses is the same setting decided: the run's findings meet it.
var metLicenses = map[string]any{
	"rule": "licenses", "profile": "Default", "state": "meets", "mode": "enforce",
	"enforceFrom": "2026-10-01", "response": "fail", "inForce": true, "acts": "none",
}

// publishAnswer is the policy a publish answer carries while the licenses setting is pending.
var publishAnswer = map[string]any{"schema": 1, "project": "payments", "policyVersion": 7,
	"outcome": "none", "passed": true, "verdicts": []any{pendingLicenses}}

// runPolicy is a 200 answer to the run's policy.
func runPolicy(t *testing.T, pending bool, outcome string, verdicts ...any) pollAnswer {
	t.Helper()
	body, err := json.Marshal(map[string]any{"schema": 1, "project": "payments", "policyVersion": 7,
		"paused": false, "outcome": outcome, "passed": outcome == "none", "pending": pending,
		"verdicts": verdicts})
	if err != nil {
		t.Fatal(err)
	}
	return pollAnswer{status: http.StatusOK, body: string(body)}
}

// quickPolls makes the wait between polls a millisecond and records each wait asked for.
func quickPolls(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	var waits []time.Duration
	prevInterval, prevSleep := policyPollInterval, policySleep
	policyPollInterval = 7 * time.Second
	policySleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return prevSleep(ctx, time.Millisecond)
	}
	t.Cleanup(func() { policyPollInterval, policySleep = prevInterval, prevSleep })
	return &waits
}

// pollCount is how many times the run's policy was asked for. Read under the server's lock, because
// a poll the wait's limit cut short may still be in the handler.
func (p *server) pollCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.polled)
}

// judgeOne publishes to one server and returns what Judge made of it.
func judgeOne(t *testing.T, p *server, wait time.Duration) (*skald.PolicyCheck, error) {
	t.Helper()
	srv := p.server(t)
	t.Setenv(apiURLEnv, srv.URL)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	return Judge(context.Background(), []saga.PublisherConfig{{Kind: "draugr-api"}}, sampleData(), wait)
}

func TestAVerdictThatPassesIsAPass(t *testing.T) {
	quickPolls(t)
	p := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, false, "none", metLicenses)}}
	got, err := judgeOne(t, p, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Checked || got.Pending || got.Fails() || got.Version != 7 || got.Outcome != "none" || len(got.Verdicts) != 1 {
		t.Errorf("a decided, passing verdict: %+v", got)
	}
	if len(p.completed) != 1 || p.pollCount() != 1 || p.polled[0] != "run-1" {
		t.Errorf("completed %v, then polled %v", p.completed, p.polled)
	}
	if !strings.HasPrefix(got.Server, "http://127.0.0.1:") {
		t.Errorf("server = %q", got.Server)
	}
}

func TestAVerdictThatFailsFailsTheCheckAndNotThePublish(t *testing.T) {
	quickPolls(t)
	p := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, false, "fail", brokenLicenses)}}
	got, err := judgeOne(t, p, time.Minute)
	if err != nil {
		t.Errorf("the failure belongs to the gate, and publishing succeeded: %v", err)
	}
	if !got.Checked || got.Pending || !got.Fails() || got.Verdicts[0].Breaking()[0].String() != "license: AGPL-3.0 · forbidden: AGPL-3.0" {
		t.Errorf("a failing verdict, in the server's words: %+v", got)
	}
}

func TestAVerdictArrivingAfterSeveralPollsIsWaitedFor(t *testing.T) {
	waits := quickPolls(t)
	pending := runPolicy(t, true, "none", pendingLicenses)
	p := &server{policy: publishAnswer, polls: []pollAnswer{pending, pending, pending, runPolicy(t, false, "fail", brokenLicenses)}}
	got, err := judgeOne(t, p, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Checked || got.Pending || !got.Fails() || p.pollCount() != 4 {
		t.Errorf("polled %d times for %+v", p.pollCount(), got)
	}
	if len(*waits) != 3 || (*waits)[0] != 7*time.Second {
		t.Errorf("waited %v between polls, want the interval three times", *waits)
	}
}

func TestRunningOutOfTimeIsNotAPass(t *testing.T) {
	quickPolls(t)
	// Decided so far: the threshold fails. Still pending: licenses.
	p := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, true, "fail", failingThreshold, pendingLicenses)}}
	got, err := judgeOne(t, p, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Checked || !got.Pending || !got.Fails() || len(got.Verdicts) != 2 || p.pollCount() < 2 {
		t.Errorf("ran out of time after %d polls: %+v", p.pollCount(), got)
	}
}

func TestNotWaitingKeepsThePublishAnswerAsPending(t *testing.T) {
	p := &server{policy: publishAnswer}
	got, err := judgeOne(t, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Checked || !got.Pending || got.Fails() || p.pollCount() != 0 {
		t.Errorf("--policy-wait 0 asks nothing, and the answer is not a pass: %+v, %d polls", got, p.pollCount())
	}
}

func TestAnAnswerWithNothingPendingIsFinal(t *testing.T) {
	p := &server{policy: map[string]any{"schema": 1, "policyVersion": 7, "outcome": "fail", "verdicts": []any{failingThreshold}}}
	got, err := judgeOne(t, p, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Checked || got.Pending || !got.Fails() || p.pollCount() != 0 {
		t.Errorf("a decided publish answer is the verdict: %+v, %d polls", got, p.pollCount())
	}
}

// A retried job's run, and evidence the server already holds, are runs that exist, so their
// verdict is waited for as well.
func TestARunAlreadyRecordedIsStillWaitedFor(t *testing.T) {
	quickPolls(t)
	for name, p := range map[string]*server{
		"duplicate": {duplicate: true},
		"held":      {held: true},
	} {
		t.Run(name, func(t *testing.T) {
			p.policy = publishAnswer
			p.polls = []pollAnswer{runPolicy(t, false, "fail", brokenLicenses)}
			got, err := judgeOne(t, p, time.Minute)
			if err != nil || !got.Fails() || p.pollCount() != 1 || len(p.uploads) != 0 {
				t.Errorf("%+v, %v, %d polls, %d uploads", got, err, p.pollCount(), len(p.uploads))
			}
		})
	}
}

func TestAServerThatWillNotSayIsNotChecked(t *testing.T) {
	quickPolls(t)
	for _, c := range []struct {
		name   string
		answer pollAnswer
		reason string
	}{
		{"401", pollAnswer{status: http.StatusUnauthorized}, "401 Unauthorized"},
		{"404", pollAnswer{status: http.StatusNotFound, body: `{"error":"not_found","detail":"no run with that id in this token's project"}`},
			"404 not_found: no run with that id in this token's project"},
		{"500", pollAnswer{status: http.StatusInternalServerError, body: `{"error":"internal"}`}, "500 internal"},
		{"unreadable", pollAnswer{status: http.StatusOK, body: "<html>"}, "the run's policy: unreadable response"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := &server{policy: publishAnswer, polls: []pollAnswer{c.answer}}
			got, err := judgeOne(t, p, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if got.Checked || got.Fails() || !strings.HasPrefix(got.Reason, c.reason) {
				t.Errorf("never a pass, and carries the status: %+v", got)
			}
		})
	}
}

func TestARateLimitIsWaitedOutAsTheServerAsks(t *testing.T) {
	waits := quickPolls(t)
	limited := pollAnswer{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "12"},
		body: `{"error":"rate_limited"}`}
	plain := pollAnswer{status: http.StatusTooManyRequests}
	p := &server{policy: publishAnswer, polls: []pollAnswer{limited, limited, limited, plain, plain, plain,
		runPolicy(t, false, "none", metLicenses)}}
	srv := p.server(t)
	t.Setenv(apiURLEnv, srv.URL)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	pub := publisherFor(t, srv.URL).(draugrAPIPublisher)
	// The transport retries a 429 itself before the poll sees it; recorded rather than slept.
	var retried []time.Duration
	pub.client.Transport.(*retryTransport).sleep = func(d time.Duration) { retried = append(retried, d) }
	got, err := pub.judge(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Checked || got.Pending || p.pollCount() != 7 {
		t.Errorf("%d polls for %+v", p.pollCount(), got)
	}
	if len(*waits) != 2 || (*waits)[0] != 12*time.Second || (*waits)[1] != 7*time.Second {
		t.Errorf("waited %v: Retry-After, then the interval where none was named", *waits)
	}
	if len(retried) != 4 || retried[0] != retryMaxDelay {
		t.Errorf("the transport waited %v", retried)
	}
}

// Two servers judge the run apart. The combined check is the strongest outcome with every verdict,
// and is checked only where both answered.
func TestTwoServersCombine(t *testing.T) {
	quickPolls(t)
	two := func(t *testing.T, a, b *server) *skald.PolicyCheck {
		t.Helper()
		one, other := a.server(t), b.server(t)
		t.Setenv(apiURLEnv, one.URL)
		t.Setenv(apiTokenEnv, "drgr_ci_test")
		t.Setenv(apiOriginsEnv, other.URL)
		got, err := Judge(context.Background(), []saga.PublisherConfig{
			{Kind: "draugr-api", URL: one.URL},
			{Kind: "draugr-api", URL: other.URL},
			{Kind: "file", Dir: t.TempDir(), Reports: []saga.ReportConfig{{Format: "json"}}},
		}, sampleData(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got.Server, one.URL) || !strings.Contains(got.Server, other.URL) {
			t.Errorf("server = %q", got.Server)
		}
		return got
	}
	t.Run("both answer", func(t *testing.T) {
		a := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, false, "none", metLicenses)}}
		b := &server{policy: map[string]any{"schema": 1, "policyVersion": 9, "outcome": "fail", "verdicts": []any{failingThreshold}}}
		got := two(t, a, b)
		if !got.Checked || got.Pending || got.Outcome != "fail" || got.Version != 9 || len(got.Verdicts) != 2 {
			t.Errorf("combined = %+v", got)
		}
	})
	t.Run("one cannot say", func(t *testing.T) {
		a := &server{policy: publishAnswer, polls: []pollAnswer{{status: http.StatusUnauthorized}}}
		b := &server{policy: map[string]any{"schema": 1, "policyVersion": 9, "outcome": "fail", "verdicts": []any{failingThreshold}}}
		got := two(t, a, b)
		if got.Checked || !got.Fails() || !strings.HasSuffix(got.Reason, ": 401 Unauthorized") || len(got.Verdicts) != 1 {
			t.Errorf("not checked, and the other's failure kept: %+v", got)
		}
	})
	t.Run("one still deciding", func(t *testing.T) {
		a := &server{policy: publishAnswer}
		a.polls = []pollAnswer{runPolicy(t, true, "none", pendingLicenses)}
		b := &server{policy: map[string]any{"schema": 1, "outcome": "none"}}
		one, other := a.server(t), b.server(t)
		t.Setenv(apiURLEnv, one.URL)
		t.Setenv(apiTokenEnv, "drgr_ci_test")
		t.Setenv(apiOriginsEnv, other.URL)
		got, err := Judge(context.Background(), []saga.PublisherConfig{
			{Kind: "draugr-api", URL: one.URL}, {Kind: "draugr-api", URL: other.URL},
		}, sampleData(), 20*time.Millisecond)
		if err != nil || !got.Checked || !got.Pending {
			t.Errorf("one pending makes the whole pending: %+v, %v", got, err)
		}
	})
}

func TestTheWaitIsOneLimitAcrossServers(t *testing.T) {
	quickPolls(t)
	// Both still deciding. The first spends the whole limit, so the second, already published to,
	// is not asked again: two servers wait no longer than one.
	a := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, true, "none", pendingLicenses)}}
	b := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, true, "none", pendingLicenses)}}
	one, other := a.server(t), b.server(t)
	t.Setenv(apiURLEnv, one.URL)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	t.Setenv(apiOriginsEnv, other.URL)
	got, err := Judge(context.Background(), []saga.PublisherConfig{
		{Kind: "draugr-api", URL: one.URL}, {Kind: "draugr-api", URL: other.URL},
	}, sampleData(), 20*time.Millisecond)
	if err != nil || !got.Checked || !got.Pending {
		t.Fatalf("both pending: %+v, %v", got, err)
	}
	first, second := a.pollCount(), b.pollCount()
	if first == 0 || second != 0 {
		t.Errorf("polls: first %d, second %d; the second should have had no time left", first, second)
	}
}

func TestJudgeAsksNothingOfAServerThatJudgesNoPolicy(t *testing.T) {
	got, err := judgeOne(t, &server{}, time.Minute)
	if err != nil || got != nil {
		t.Errorf("no policy in the answer is no check: %+v, %v", got, err)
	}
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiTokenEnv, "")
	got, err = Judge(context.Background(), []saga.PublisherConfig{{Kind: "draugr-api"}}, sampleData(), time.Minute)
	if err != nil || got != nil {
		t.Errorf("a skipped publisher judges nothing: %+v, %v", got, err)
	}
}

func TestAPublishThatFailsIsAPublishingError(t *testing.T) {
	got, err := judgeOne(t, &server{evidenceError: "no storage"}, time.Minute)
	if err == nil || got != nil || !strings.Contains(err.Error(), "evidence refused: no storage") {
		t.Errorf("%+v, %v", got, err)
	}
}

// The caller's own context ending stops the wait as an error, never as a verdict.
func TestACanceledScanStopsWaiting(t *testing.T) {
	quickPolls(t)
	p := &server{policy: publishAnswer, polls: []pollAnswer{runPolicy(t, true, "none", pendingLicenses)}}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL).(draugrAPIPublisher)
	ctx, cancel := context.WithCancel(context.Background())
	prev := policySleep
	policySleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	t.Cleanup(func() { policySleep = prev })
	got, err := pub.judge(ctx, artifacts(`{"verdict":"pass"}`, `{"runs":[]}`), time.Minute)
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Errorf("%+v, %v", got, err)
	}
}

func TestExceptAPI(t *testing.T) {
	got := ExceptAPI([]saga.PublisherConfig{{Kind: "draugr-api"}, {Kind: "file"}, {Kind: "github-pr-comment"}})
	if len(got) != 2 || got[0].Kind != "file" || got[1].Kind != "github-pr-comment" {
		t.Errorf("ExceptAPI = %+v", got)
	}
}
