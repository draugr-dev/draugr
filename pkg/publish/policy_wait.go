package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// DefaultPolicyWait is how long a scan waits, by default, for the servers' verdict on the run it
// published.
const DefaultPolicyWait = 5 * time.Minute

// policyPollInterval is how often a run's verdict is asked for while the server decides it. A
// variable so tests can ask without waiting.
var policyPollInterval = 5 * time.Second

// policySleep waits d, or until ctx ends. A variable so tests can record the waits instead.
var policySleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Judge delivers the run to each draugr-api publisher, and waits up to wait, in all, for the
// servers' verdict on the run's findings. One limit rather than one per server, so the time a
// pipeline spends waiting is the time the flag says, however many servers the descriptor names. The verdicts are combined the way the pre-flight combines its
// checks: the strongest outcome, every verdict, and every reason a server could not be asked.
//
// A server decides a policy over findings only once they arrive, so these publishers go before
// every other: what they answer is what the console, the artifacts and the rest of the publishers
// then report. The check is nil where no server that judges policy received the run.
//
// The error is a publishing failure only. A policy that fails the run is in the check, and the
// caller decides what it does to the gate, so the failure is not reported twice.
func Judge(ctx context.Context, publishers []saga.PublisherConfig, data report.Data, wait time.Duration) (*skald.PolicyCheck, error) {
	// Every server receives the run before any is waited on, and the limit starts once they all
	// have: the wait is for the verdict, not for the uploads ahead of it.
	type delivered struct {
		api      draugrAPIPublisher
		accepted acceptedRun
	}
	var runs []delivered
	err := deliverAll(ctx, APIPublishers(publishers), data,
		func(ctx context.Context, p Publisher, _ report.Data, artifacts []report.Artifact) error {
			api, ok := p.(draugrAPIPublisher)
			if !ok {
				// Skipped, with nowhere to send: it says why itself.
				return p.Publish(ctx, artifacts)
			}
			accepted, err := api.deliver(ctx, artifacts)
			if err == nil && accepted.Policy != nil {
				runs = append(runs, delivered{api, accepted})
			}
			return err
		})
	deadline := time.Now().Add(wait)
	var checks []*skald.PolicyCheck
	for _, r := range runs {
		check, werr := r.api.awaitPolicy(ctx, r.accepted.Run, *r.accepted.Policy, max(time.Until(deadline), 0))
		if werr != nil {
			return nil, errors.Join(err, werr)
		}
		checks = append(checks, check)
	}
	return combineRunChecks(checks), err
}

// ExceptAPI is every publisher Judge does not deliver to.
func ExceptAPI(cfgs []saga.PublisherConfig) []saga.PublisherConfig {
	var out []saga.PublisherConfig
	for _, c := range cfgs {
		if c.Kind != "draugr-api" {
			out = append(out, c)
		}
	}
	return out
}

// combineRunChecks is one check for several servers. It is checked only where every server
// answered, because a server that could not say is never a pass, and it keeps what the others
// said, so a failure from one still fails the gate.
func combineRunChecks(checks []*skald.PolicyCheck) *skald.PolicyCheck {
	switch len(checks) {
	case 0:
		return nil
	case 1:
		return checks[0]
	}
	out := &skald.PolicyCheck{Checked: true}
	var servers, reasons []string
	for _, c := range checks {
		servers = append(servers, c.Server)
		if !c.Checked {
			out.Checked = false
			reasons = append(reasons, c.Server+": "+c.Reason)
			continue
		}
		out.Pending = out.Pending || c.Pending
		out.Version = max(out.Version, c.Version)
		out.Outcome = skald.Strongest(out.Outcome, c.Outcome)
		out.Verdicts = append(out.Verdicts, c.Verdicts...)
	}
	out.Server = strings.Join(servers, ", ")
	out.Reason = strings.Join(reasons, "; ")
	return out
}

// judge delivers the run and returns the server's verdict on it, waited for where the server
// decides part of it after the answer. Nil where the server judges no policy.
func (p draugrAPIPublisher) judge(ctx context.Context, artifacts []report.Artifact, wait time.Duration) (*skald.PolicyCheck, error) {
	accepted, err := p.deliver(ctx, artifacts)
	if err != nil || accepted.Policy == nil {
		return nil, err
	}
	return p.awaitPolicy(ctx, accepted.Run, *accepted.Policy, wait)
}

// awaitPolicy asks for the run's policy until the server has decided every setting or wait runs
// out. An answer with nothing pending is final as it stands and asks nothing.
//
// Running out of time keeps what was decided so far and marks the check pending, which is never a
// pass. A server that will not say, a 401, a 404 or a failure, is not checked, with its status. The
// error is the caller's context ending, and nothing else.
func (p draugrAPIPublisher) awaitPolicy(ctx context.Context, run string, answer skald.PolicyOutcome, wait time.Duration) (*skald.PolicyCheck, error) {
	latest := answer
	if !latest.Undecided() {
		return p.decided(latest, false), nil
	}
	if wait > 0 {
		slog.Info("waiting for the policy verdict", "run", run, "server", p.endpoint, "limit", wait)
		waitCtx, cancel := context.WithTimeout(ctx, wait)
		defer cancel()
		for {
			got, err := p.pollPolicy(waitCtx, run)
			switch {
			case ctx.Err() != nil:
				return nil, ctx.Err()
			case waitCtx.Err() != nil:
				// The limit ended the request: what was decided so far is all there is.
			case err != nil:
				return &skald.PolicyCheck{Server: p.endpoint, Reason: err.Error()}, nil
			case got.refused != "":
				return &skald.PolicyCheck{Server: p.endpoint, Reason: got.refused}, nil
			case !got.limited && !got.outcome.Pending:
				return p.decided(got.outcome, false), nil
			}
			if waitCtx.Err() != nil {
				break
			}
			next := policyPollInterval
			if got.limited {
				next = got.retryAfter
			} else {
				latest = got.outcome
			}
			if err := policySleep(waitCtx, next); err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				break
			}
		}
	}
	logPending(run, latest)
	return p.decided(latest, true), nil
}

// decided is a server's answer as a check.
func (p draugrAPIPublisher) decided(o skald.PolicyOutcome, pending bool) *skald.PolicyCheck {
	outcome := o.Outcome
	if outcome == "" {
		outcome = skald.PolicyNone
	}
	return &skald.PolicyCheck{Server: p.endpoint, Checked: true, Pending: pending,
		Version: o.PolicyVersion, Outcome: outcome, Verdicts: o.Verdicts}
}

// policyPoll is one answer to GET /v1/ingest/runs/{id}/policy.
type policyPoll struct {
	outcome skald.PolicyOutcome
	// limited is a 429, to be asked again after retryAfter.
	limited    bool
	retryAfter time.Duration
	// refused is the status of an answer that is not a verdict, which is never a pass.
	refused string
}

// pollPolicy asks once for the run's policy, with the token that published the run.
func (p draugrAPIPublisher) pollPolicy(ctx context.Context, run string) (policyPoll, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		p.endpoint+"/v1/ingest/runs/"+url.PathEscape(run)+"/policy", nil)
	if err != nil {
		return policyPoll{}, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	resp, err := p.client.Do(req)
	if err != nil {
		return policyPoll{}, fmt.Errorf("the run's policy: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		wait, ok := retryAfter(resp.Header.Get("Retry-After"))
		if !ok {
			wait = policyPollInterval
		}
		return policyPoll{limited: true, retryAfter: wait}, nil
	case resp.StatusCode != http.StatusOK:
		return policyPoll{refused: statusSaid(resp)}, nil
	}
	var out policyPoll
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out.outcome); err != nil {
		return policyPoll{}, fmt.Errorf("the run's policy: unreadable response: %w", err)
	}
	return out, nil
}

// statusSaid is a failure as the POLICY line and report.json carry it: the status first, so a 401
// and a 404 are told apart at a glance, then the server's own code and detail.
func statusSaid(resp *http.Response) string {
	r := readRefusal(resp)
	switch {
	case r.Code == "":
		return resp.Status
	case r.Detail == "":
		return strconv.Itoa(resp.StatusCode) + " " + r.Code
	}
	return strconv.Itoa(resp.StatusCode) + " " + r.Code + ": " + r.Detail
}
