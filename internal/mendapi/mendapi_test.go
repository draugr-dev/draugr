package mendapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// server answers each requestType from a table, so a test states only what it cares about.
func server(t *testing.T, replies map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		reply, ok := replies[req["requestType"].(string)]
		if !ok {
			reply = `{}`
		}
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "test-key")
	return c
}

// Mend answers failures with HTTP 200 and an errorMessage. A client trusting the status code
// would read a permission failure as an empty result — which for this integration means
// reporting a clean scan.
func TestErrorInABodyWithStatus200IsAnError(t *testing.T) {
	c := server(t, map[string]string{
		"getAllProjects": `{"errorCode":5001,"errorMessage":"User is not allowed to perform this action"}`,
	})
	_, err := c.Projects(context.Background(), "prod")
	if err == nil {
		t.Fatal("an errorMessage in a 200 reply was treated as success")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("error should relay what Mend said: %v", err)
	}
}

// The user key authenticates every call and must never appear in an error, which is where a
// message tends to end up in a log.
func TestUserKeyNeverAppearsInAnError(t *testing.T) {
	c := server(t, map[string]string{"getAllProjects": `{"errorMessage":"nope"}`})
	c.UserKey = "super-secret-user-key"
	_, err := c.Projects(context.Background(), "prod")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), c.UserKey) {
		t.Error("the user key leaked into an error message")
	}
}

func TestProjectByNameFindsAndReports(t *testing.T) {
	c := server(t, map[string]string{
		"getAllProjects": `{"projects":[{"projectName":"a","projectToken":"ta"},{"projectName":"b","projectToken":"tb"}]}`,
	})
	p, err := c.ProjectByName(context.Background(), "prod", "b")
	if err != nil || p.Token != "tb" {
		t.Fatalf("got %+v, %v", p, err)
	}
	if _, err := c.ProjectByName(context.Background(), "prod", "missing"); err == nil {
		t.Error("a missing project should be an error naming it")
	}
}

// The property the whole design rests on: an upload that has not landed must not be reported as
// a project with no findings.
func TestAwaitWaitsForTheUploadToLand(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		switch req["requestType"] {
		case "getAllProjects":
			_, _ = io.WriteString(w, `{"projects":[{"projectName":"p","projectToken":"tp"}]}`)
		case "getProjectVitals":
			calls++
			// Stale for the first two polls, then our upload appears.
			if calls < 3 {
				_, _ = io.WriteString(w, `{"projectVitals":[{"requestToken":"older","lastUpdatedDate":"x"}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"projectVitals":[{"requestToken":"mine","lastUpdatedDate":"y"}]}`)
		case "getProjectAlerts":
			_, _ = io.WriteString(w, `{"alerts":[{"type":"SECURITY_VULNERABILITY","vulnerability":{"name":"CVE-1"}}]}`)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "k")
	alerts, err := c.Await(context.Background(), AwaitOpts{
		ProductToken: "prod", ProjectName: "p", RequestToken: "mine",
		Timeout: time.Minute, Interval: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Vulnerability.Name != "CVE-1" {
		t.Errorf("alerts = %+v", alerts)
	}
	if calls < 3 {
		t.Errorf("returned after %d polls; it should have waited for the matching token", calls)
	}
}

// A timeout means "not read yet", which is not the same as "nothing found". Returning an empty
// result here would publish a pass for a scan nobody processed.
func TestAwaitTimingOutIsAnErrorNotAnEmptyResult(t *testing.T) {
	c := server(t, map[string]string{
		"getAllProjects":   `{"projects":[{"projectName":"p","projectToken":"tp"}]}`,
		"getProjectVitals": `{"projectVitals":[{"requestToken":"someone-elses"}]}`,
	})
	alerts, err := c.Await(context.Background(), AwaitOpts{
		ProductToken: "prod", ProjectName: "p", RequestToken: "mine",
		Timeout: time.Nanosecond, Interval: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err == nil {
		t.Fatal("a timeout returned success")
	}
	if alerts != nil {
		t.Error("a timeout must not return alerts — an empty slice reads as a clean scan")
	}
	if !strings.Contains(err.Error(), "nothing to report yet") {
		t.Errorf("the error should distinguish not-ready from not-found: %v", err)
	}
}

// A project that does not exist yet is the ordinary early state — the upload creates it — so it
// must not abort the wait.
func TestAwaitToleratesTheProjectNotExistingYet(t *testing.T) {
	seen := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		switch req["requestType"] {
		case "getAllProjects":
			seen++
			if seen < 2 {
				_, _ = io.WriteString(w, `{"projects":[]}`)
				return
			}
			_, _ = io.WriteString(w, `{"projects":[{"projectName":"p","projectToken":"tp"}]}`)
		case "getProjectVitals":
			_, _ = io.WriteString(w, `{"projectVitals":[{"requestToken":"mine"}]}`)
		case "getProjectAlerts":
			_, _ = io.WriteString(w, `{"alerts":[]}`)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "k")
	if _, err := c.Await(context.Background(), AwaitOpts{
		ProductToken: "prod", ProjectName: "p", RequestToken: "mine",
		Timeout: time.Minute, Interval: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}); err != nil {
		t.Fatalf("Await should wait through a missing project: %v", err)
	}
}

func TestAwaitStopsWhenTheRunIsCancelled(t *testing.T) {
	c := server(t, map[string]string{
		"getAllProjects":   `{"projects":[{"projectName":"p","projectToken":"tp"}]}`,
		"getProjectVitals": `{"projectVitals":[{"requestToken":"other"}]}`,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Await(ctx, AwaitOpts{
		ProductToken: "prod", ProjectName: "p", RequestToken: "mine",
		Timeout: time.Minute, Interval: time.Millisecond,
	}); err == nil {
		t.Error("a cancelled run should stop the wait")
	}
}

// Without a request token the fallback is weaker but must still not treat an untouched project
// as processed.
func TestLandedFallsBackWhenNoRequestTokenIsKnown(t *testing.T) {
	c := server(t, map[string]string{
		"getProjectVitals": `{"projectVitals":[{"lastUpdatedDate":"2026-01-01"}]}`,
	})
	ok, err := c.landed(context.Background(), "tp", AwaitOpts{})
	if err != nil || !ok {
		t.Errorf("an updated project should count as landed: %v %v", ok, err)
	}

	never := server(t, map[string]string{"getProjectVitals": `{"projectVitals":[{"lastUpdatedDate":""}]}`})
	if ok, _ := never.landed(context.Background(), "tp", AwaitOpts{}); ok {
		t.Error("a project that was never updated is not landed")
	}
}

func TestVitalsReportsAnEmptyReply(t *testing.T) {
	c := server(t, map[string]string{"getProjectVitals": `{"projectVitals":[]}`})
	if _, err := c.Vitals(context.Background(), "tp"); err == nil {
		t.Error("an empty vitals list should be an error, not a zero value")
	}
}

func TestCallReportsTransportAndDecodeFailures(t *testing.T) {
	// A body that is not the shape we asked for.
	c := server(t, map[string]string{"getAllProjects": `{"projects":"not-an-array"}`})
	if _, err := c.Projects(context.Background(), "p"); err == nil {
		t.Error("an unreadable reply should be an error")
	}
	// An unreachable tenant.
	dead := New("http://127.0.0.1:1", "k")
	if _, err := dead.Projects(context.Background(), "p"); err == nil {
		t.Error("an unreachable tenant should be an error")
	}
}

func TestCallReportsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "k").Projects(context.Background(), "p"); err == nil {
		t.Error("a non-200 should be an error")
	}
}

func TestSleepCtxReturnsAfterTheInterval(t *testing.T) {
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx: %v", err)
	}
}

// The agent's CLI prints no request token, so this is the check that actually runs: the inventory
// reaching the count the agent said it resolved. Without it the poll returns immediately against
// an empty project, which reads as a clean scan.
func TestLandedWaitsForTheInventoryToMatchWhatWasSent(t *testing.T) {
	short := server(t, map[string]string{
		"getProjectInventory": `{"libraries":[{},{}]}`,
	})
	ok, err := short.landed(context.Background(), "tp", AwaitOpts{ExpectLibraries: 3})
	if ok {
		t.Error("an inventory holding fewer libraries than were sent counts as landed")
	}
	if err == nil || !strings.Contains(err.Error(), "2 of the 3") {
		t.Errorf("the state should say how far along it is: %v", err)
	}

	full := server(t, map[string]string{"getProjectInventory": `{"libraries":[{},{},{}]}`})
	if ok, err := full.landed(context.Background(), "tp", AwaitOpts{ExpectLibraries: 3}); !ok || err != nil {
		t.Errorf("a complete inventory should count as landed: %v %v", ok, err)
	}
}

func TestLibraryCountReportsAnErrorRatherThanZero(t *testing.T) {
	c := server(t, map[string]string{"getProjectInventory": `{"errorMessage":"denied"}`})
	if _, err := c.LibraryCount(context.Background(), "tp"); err == nil {
		t.Error("a refused inventory must be an error, not a count of zero")
	}
}

func TestAwaitPassesTheExpectedCountThrough(t *testing.T) {
	c := server(t, map[string]string{
		"getAllProjects":      `{"projects":[{"projectName":"p","projectToken":"tp"}]}`,
		"getProjectInventory": `{"libraries":[{},{},{}]}`,
		"getProjectAlerts":    `{"alerts":[{"type":"SECURITY_VULNERABILITY","vulnerability":{"name":"CVE-1"}}]}`,
	})
	alerts, err := c.Await(context.Background(), AwaitOpts{
		ProductToken: "prod", ProjectName: "p", ExpectLibraries: 3,
		Timeout: time.Minute, Interval: time.Millisecond,
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil || len(alerts) != 1 {
		t.Fatalf("alerts = %v, err = %v", alerts, err)
	}
}

func TestLandedAndVitalsSurfaceTheirFailures(t *testing.T) {
	// A refused vitals call is a state we do not know, not a scan that has landed.
	c := server(t, map[string]string{"getProjectVitals": `{"errorMessage":"denied"}`})
	if ok, err := c.landed(context.Background(), "tp", AwaitOpts{RequestToken: "x"}); ok || err == nil {
		t.Errorf("ok=%v err=%v", ok, err)
	}
	if ok, err := c.landed(context.Background(), "tp", AwaitOpts{}); ok || err == nil {
		t.Errorf("fallback: ok=%v err=%v", ok, err)
	}
	// A refused inventory likewise.
	inv := server(t, map[string]string{"getProjectInventory": `{"errorMessage":"denied"}`})
	if ok, err := inv.landed(context.Background(), "tp", AwaitOpts{ExpectLibraries: 2}); ok || err == nil {
		t.Errorf("inventory: ok=%v err=%v", ok, err)
	}
}

// Await applies its own defaults when a caller supplies none, so a zero-value opts still bounds
// the wait rather than polling forever.
func TestAwaitDefaultsItsTimeoutAndInterval(t *testing.T) {
	c := server(t, map[string]string{"getAllProjects": `{"projects":[]}`})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Await(ctx, AwaitOpts{ProductToken: "p", ProjectName: "nope"}); err == nil {
		t.Error("expected the wait to end")
	}
}
