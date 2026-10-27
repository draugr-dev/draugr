package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// pendingLicenses is a setting the server decides once the run's findings arrive.
var pendingLicenses = skald.PolicyVerdict{Rule: "licenses", Profile: "Default", State: "not_evaluated",
	Detail: "the run's evidence is not expanded into findings yet", Mode: "enforce", EnforceFrom: "2026-10-01",
	Response: "fail", InForce: true, Acts: "none", Pending: true}

// brokenLicenses is the same setting, decided: the run's findings break it.
var brokenLicenses = skald.PolicyVerdict{Rule: "licenses", Profile: "Default", State: "violates", Mode: "enforce",
	EnforceFrom: "2026-10-01", Response: "fail", InForce: true, Acts: "fail",
	Items: []skald.PolicyItem{{Field: "license", Found: "AGPL-3.0", Constraint: "forbidden", Expected: "AGPL-3.0", Breaks: true}}}

// judgingServer is a draugr-api server whose policy judges the run's findings once they arrive. Its
// pre-flight passes the descriptor, its publish answer leaves licenses pending, and each poll of the
// run's policy gets poll's answer.
func judgingServer(t *testing.T, poll func(n int) (int, any)) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	polls := 0
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	answer := skald.PolicyOutcome{Schema: 1, Project: "payments", PolicyVersion: 7, Outcome: "none", Passed: true,
		Verdicts: []skald.PolicyVerdict{pendingLicenses}}
	mux.HandleFunc("POST /v1/ingest/policy/check", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, answer)
	})
	var srv *httptest.Server
	mux.HandleFunc("POST /v1/runs", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"run": "run-1", "project": "payments", "verdict": "pass",
			"policy": answer, "evidence": map[string]any{"upload": srv.URL + "/evidence"}})
	})
	mux.HandleFunc("PUT /evidence", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /v1/runs/{id}/complete", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/ingest/runs/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "run-1" || r.Header.Get("Authorization") != "Bearer drgr_ci_test" {
			t.Errorf("polled %s with %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		mu.Lock()
		polls++
		n := polls
		mu.Unlock()
		status, body := poll(n)
		writeJSON(w, status, body)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Setenv("DRAUGR_API_URL", srv.URL)
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	return srv, &polls
}

// decidedRun is the run's policy once licenses is decided.
func decidedRun(outcome string, v skald.PolicyVerdict) skald.PolicyOutcome {
	return skald.PolicyOutcome{Schema: 1, Project: "payments", PolicyVersion: 7, Outcome: outcome,
		Passed: outcome == "none", Verdicts: []skald.PolicyVerdict{v}}
}

// judgedSaga publishes to the environment's draugr-api server and writes report.json to dir.
func judgedSaga(dir string) string {
	return `project: payments
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  publishers:
    - kind: draugr-api
    - kind: file
      dir: ` + dir + `
      reports:
        - format: json
components:
  - name: web
    images:
      - image: nginx:1
`
}

// A rule over findings that the server decides after the run is published fails the scan as the
// pre-flight's would: the console names it, the verdict is FAIL, and the file publisher, delivered
// after the wait, records the same verdict.
func TestAVerdictOnTheFindingsFailsTheScan(t *testing.T) {
	_, polls := judgingServer(t, func(int) (int, any) { return http.StatusOK, decidedRun("fail", brokenLicenses) })
	dir := t.TempDir()
	var out bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, judgedSaga(dir)),
		scanOptions{failOn: "error", policyWait: time.Minute}, fakeRegistry(sarif.LevelNote), &out)
	if err == nil || err.Error() != "policy verdict: fail" {
		t.Fatalf("err = %v, want the gate to fail on the policy alone", err)
	}
	got := out.String()
	for _, want := range []string{
		"FAIL",
		"POLICY  version 7 · http://127.0.0.1:",
		"licenses  license: AGPL-3.0 · forbidden: AGPL-3.0  Default · fails the gate, since 2026-10-01",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the console is missing %q:\n%s", want, got)
		}
	}
	if *polls != 1 {
		t.Errorf("polled %d times", *polls)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json")) // #nosec G304 -- this test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Verdict string `json:"verdict"`
		Policy  struct {
			Checked bool `json:"checked"`
			Run     *struct {
				Checked bool   `json:"checked"`
				Outcome string `json:"outcome"`
			} `json:"run"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Verdict != "fail" || !doc.Policy.Checked || doc.Policy.Run == nil || !doc.Policy.Run.Checked || doc.Policy.Run.Outcome != "fail" {
		t.Errorf("the file publisher did not see the waited verdict:\n%s", raw)
	}
}

func TestAVerdictTheScanCouldNotGet(t *testing.T) {
	pending := func(int) (int, any) {
		return http.StatusOK, skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "none", Passed: true, Pending: true,
			Verdicts: []skald.PolicyVerdict{pendingLicenses}}
	}
	unauthorized := func(int) (int, any) { return http.StatusUnauthorized, nil }
	for _, c := range []struct {
		name     string
		poll     func(int) (int, any)
		wait     time.Duration
		heading  string
		required string
	}{
		{"the wait ran out", pending, 50 * time.Millisecond,
			"POLICY  version 7 · http://127.0.0.1:", "the server had not decided the organization's policy on the published run within --policy-wait 50ms"},
		{"no wait", pending, 0,
			"POLICY  version 7 · http://127.0.0.1:", "after publish, and --policy-wait 0 waits for none of it"},
		{"401", unauthorized, time.Minute,
			"· run not checked · 401 Unauthorized", "the organization's policy was not checked on the published run: 401 Unauthorized"},
	} {
		t.Run(c.name, func(t *testing.T) {
			judgingServer(t, c.poll)
			var out bytes.Buffer
			err := runScan(context.Background(), writeSaga(t, judgedSaga(t.TempDir())),
				scanOptions{failOn: "error", policyWait: c.wait}, fakeRegistry(sarif.LevelNote), &out)
			if err != nil {
				t.Errorf("without --policy, a verdict not had is said and fails nothing: %v", err)
			}
			got := out.String()
			if !strings.Contains(got, c.heading) || strings.Contains(got, "none broken") {
				t.Errorf("the POLICY line does not say so:\n%s", got)
			}
			if status, _ := c.poll(0); status == http.StatusOK && !strings.Contains(got, "· decided after publish") {
				t.Errorf("a pending verdict reads as decided after publish:\n%s", got)
			}

			out.Reset()
			err = runScan(context.Background(), writeSaga(t, judgedSaga(t.TempDir())),
				scanOptions{failOn: "error", policyWait: c.wait, requirePolicy: true}, fakeRegistry(sarif.LevelNote), &out)
			if err == nil || !strings.HasPrefix(err.Error(), "--policy: ") || !strings.Contains(err.Error(), c.required) {
				t.Errorf("--policy: err = %v", err)
			}
			if !strings.Contains(out.String(), "CONTROLS") {
				t.Errorf("--policy still prints the report before it fails:\n%s", out.String())
			}
		})
	}
}

func TestRequireRunPolicy(t *testing.T) {
	if err := requireRunPolicy(nil, time.Minute); err != nil {
		t.Errorf("nothing asked: %v", err)
	}
	if err := requireRunPolicy(&skald.PolicyCheck{Checked: true}, time.Minute); err != nil {
		t.Errorf("published to no server that judges: %v", err)
	}
	if err := requireRunPolicy(&skald.PolicyCheck{Checked: true, Run: &skald.PolicyCheck{Checked: true, Outcome: "fail"}}, time.Minute); err != nil {
		t.Errorf("a decided verdict satisfies --policy, and the gate acts on it: %v", err)
	}
}
