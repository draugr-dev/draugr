package publish

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// failingThreshold is a verdict as the server words it: a setting in force the run breaks.
var failingThreshold = map[string]any{
	"rule": "threshold", "profile": "PCI scope", "state": "violates", "mode": "enforce",
	"enforceFrom": "2026-10-01", "response": "fail", "inForce": true, "acts": "fail",
	"items": []any{map[string]any{"field": "failOn", "found": "P1", "constraint": "required",
		"expected": "P2 or stricter", "breaks": true}},
}

func TestThePreflightSendsTheDescriptorAndReadsTheOutcome(t *testing.T) {
	var got struct {
		auth string
		body map[string]map[string]string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/ingest/policy/check" {
			http.NotFound(w, r)
			return
		}
		got.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema": 1, "project": "payments", "policyVersion": 7, "outcome": "fail", "passed": false,
			"verdicts": []any{failingThreshold},
		})
	}))
	defer srv.Close()

	// #nosec G101 -- a placeholder the test server checks, not a credential.
	dest := APIDestination{Endpoint: srv.URL, Token: "drgr_ci_test"}
	out, err := NewPolicyClient().Check(context.Background(), dest, "project: payments\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.auth != "Bearer drgr_ci_test" || got.body["descriptor"]["effective"] != "project: payments\n" {
		t.Errorf("the check sent %q and %v", got.auth, got.body)
	}
	if out.PolicyVersion != 7 || out.Outcome != "fail" || len(out.Verdicts) != 1 ||
		out.Verdicts[0].Items[0].String() != "failOn: P1 · required: P2 or stricter" {
		t.Errorf("outcome = %+v", out)
	}
}

func TestAServerWithNoPolicyIsNotAFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, err := NewPolicyClient().Check(context.Background(), APIDestination{Endpoint: srv.URL, Token: "t"}, "")
	if !errors.Is(err, ErrNoPolicyCheck) {
		t.Errorf("a 404 means no policy check, got %v", err)
	}
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate_limited","detail":"the token's allowance is spent"}`)
	}))
	defer refusing.Close()
	if _, err := NewPolicyClient().Check(context.Background(), APIDestination{Endpoint: refusing.URL, Token: "t"}, ""); err == nil ||
		!strings.Contains(err.Error(), "rate_limited") {
		t.Errorf("the server's own reason should surface: %v", err)
	}
}

// A run the organization's policy fails is recorded whole and then fails the build, naming the rule.
func TestAFailingPolicyFailsThePublishAfterTheRunIsRecorded(t *testing.T) {
	p := &server{policy: map[string]any{"schema": 1, "outcome": "fail", "verdicts": []any{failingThreshold}}}
	srv := p.server(t)
	err := publisherFor(t, srv.URL).Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil || !strings.Contains(err.Error(), "policy fails it: threshold failOn: P1 · required: P2 or stricter") {
		t.Fatalf("err = %v", err)
	}
	if len(p.uploads) != 1 || len(p.completed) != 1 {
		t.Errorf("the run should be recorded whole before the build fails: %d uploads, %d completed", len(p.uploads), len(p.completed))
	}
}

func TestAPassingOrPendingPolicyPublishes(t *testing.T) {
	pending := map[string]any{"rule": "licenses", "profile": "Default", "state": "not_evaluated", "mode": "enforce",
		"response": "fail", "inForce": true, "acts": "none", "pending": true}
	p := &server{policy: map[string]any{"schema": 1, "outcome": "none", "passed": true, "verdicts": []any{pending}}}
	srv := p.server(t)
	if err := publisherFor(t, srv.URL).Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Errorf("a policy that passes, with a verdict still to decide, publishes: %v", err)
	}
}

func TestARefusalByPolicySaysWhichRule(t *testing.T) {
	refused := map[string]any{"rule": "effects", "profile": "Default", "state": "violates", "mode": "enforce",
		"enforceFrom": "2026-10-01", "response": "refuse", "inForce": true, "acts": "refuse",
		"items": []any{map[string]any{"field": "allowEffects", "found": "mutate", "constraint": "forbidden",
			"expected": "mutate", "breaks": true}}}
	body, _ := json.Marshal(map[string]any{"error": "policy_refused", "detail": "refused",
		"policy": map[string]any{"schema": 1, "outcome": "refuse", "verdicts": []any{refused}}})
	p := &server{status: http.StatusUnprocessableEntity, body: string(body)}
	srv := p.server(t)
	err := publisherFor(t, srv.URL).Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil || !strings.Contains(err.Error(), "policy refused the run: effects allowEffects: mutate · forbidden: mutate (Default · refuses, since 2026-10-01)") {
		t.Errorf("err = %v", err)
	}
}

func TestResolveAPIIsThePublishersResolution(t *testing.T) {
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiTokenEnv, "")
	if _, skip, err := ResolveAPI(saga.PublisherConfig{Kind: "draugr-api"}); err != nil || skip == "" {
		t.Errorf("neither endpoint nor token is a skip with a reason: %q, %v", skip, err)
	}
	t.Setenv(apiTokenEnv, "t")
	dest, skip, err := ResolveAPI(saga.PublisherConfig{Kind: "draugr-api", DefaultURL: "https://draugr.example/"})
	if err != nil || skip != "" || dest.Endpoint != "https://draugr.example" || dest.Token != "t" {
		t.Errorf("dest = %+v, %q, %v", dest, skip, err)
	}
	if got := APIPublishers([]saga.PublisherConfig{{Kind: "file"}, {Kind: "draugr-api"}}); len(got) != 1 {
		t.Errorf("APIPublishers = %+v", got)
	}
}
