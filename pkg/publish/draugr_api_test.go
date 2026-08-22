package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// server records what a publisher sent it and answers the way the real one does.
type server struct {
	mu sync.Mutex

	runs      []planeRequest
	uploads   [][]byte
	completed []string

	// held answers "this tenant already has that evidence".
	held bool
	// evidenceError stands in for a server with no storage configured.
	evidenceError string
	// status, when set, is the answer to POST /v1/runs.
	status int
	body   string
	// duplicate answers a retried post.
	duplicate bool
}

type planeRequest struct {
	key, digest, bytes, auth string
	body                     []byte
}

func (p *server) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	upload := ""

	mux.HandleFunc("POST /v1/runs", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.runs = append(p.runs, planeRequest{
			key:    r.Header.Get("Idempotency-Key"),
			digest: r.Header.Get("X-Draugr-Evidence-Sha256"),
			bytes:  r.Header.Get("X-Draugr-Evidence-Bytes"),
			auth:   r.Header.Get("Authorization"),
			body:   body,
		})
		p.mu.Unlock()

		if p.status != 0 {
			w.WriteHeader(p.status)
			_, _ = io.WriteString(w, p.body)
			return
		}
		evidence := map[string]any{"held": p.held}
		switch {
		case p.evidenceError != "":
			evidence["error"] = p.evidenceError
		case !p.held:
			evidence["upload"] = upload
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"run": "run-1", "project": "payments", "verdict": "pass",
			"duplicate": p.duplicate, "evidence": evidence,
		})
	})
	mux.HandleFunc("PUT /evidence", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.uploads = append(p.uploads, body)
		p.mu.Unlock()
		if r.Header.Get("Authorization") != "" {
			t.Error("the ingest token was sent to the storage endpoint")
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /v1/runs/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.completed = append(p.completed, r.PathValue("id"))
		p.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	upload = srv.URL + "/evidence"
	return srv
}

// artifacts is a report and its evidence.
func artifacts(reportJSON, sarif string) []report.Artifact {
	var out []report.Artifact
	if reportJSON != "" {
		out = append(out, report.Artifact{Format: "json", Bytes: []byte(reportJSON)})
	}
	if sarif != "" {
		out = append(out, report.Artifact{Format: "sarif", Bytes: []byte(sarif)})
	}
	return out
}

// publisherFor builds the publisher against a server.
func publisherFor(t *testing.T, url string) Publisher {
	t.Helper()
	t.Setenv(apiURLEnv, url)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	p, err := For(saga.PublisherConfig{Kind: "draugr-api"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestItPostsTheRunThenUploadsTheEvidence(t *testing.T) {
	// Two documents traveling differently is the whole shape: the report is the run and goes in
	// the body; the SARIF is the evidence and never goes through the API.
	p := &server{}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	sarif := `{"version":"2.1.0","runs":[]}`
	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, sarif)); err != nil {
		t.Fatal(err)
	}

	if len(p.runs) != 1 || len(p.uploads) != 1 || len(p.completed) != 1 {
		t.Fatalf("runs=%d uploads=%d completed=%d, want 1 each", len(p.runs), len(p.uploads), len(p.completed))
	}
	if string(p.runs[0].body) != `{"verdict":"pass"}` {
		t.Errorf("body = %s, want the report unchanged", p.runs[0].body)
	}
	if string(p.uploads[0]) != sarif {
		t.Errorf("uploaded %s, want the SARIF unchanged", p.uploads[0])
	}
	if p.completed[0] != "run-1" {
		t.Errorf("completed %q", p.completed[0])
	}

	// The digest travels before the bytes do, which is what lets the server address the evidence
	// by its content and answer "already held" for a re-run that produced the same findings.
	sum := sha256.Sum256([]byte(sarif))
	if want := hex.EncodeToString(sum[:]); p.runs[0].digest != want {
		t.Errorf("digest = %q, want %q", p.runs[0].digest, want)
	}
	if p.runs[0].bytes != strconv.Itoa(len(sarif)) {
		t.Errorf("bytes = %q, want %d", p.runs[0].bytes, len(sarif))
	}
	if p.runs[0].auth != "Bearer drgr_ci_test" {
		t.Errorf("authorization = %q", p.runs[0].auth)
	}
}

func TestHeldEvidenceIsNotUploadedAgain(t *testing.T) {
	// A retried job, a re-run of the same commit, or two projects sharing a repository all
	// produce evidence the server already has. Sending it again spends the customer's bandwidth
	// writing bytes that are byte-identical to the ones already there.
	p := &server{held: true}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Fatal(err)
	}
	if len(p.uploads) != 0 {
		t.Errorf("uploaded %d objects the server already held", len(p.uploads))
	}
	// And nothing to complete: the server marks a run complete when it says it holds the evidence.
	if len(p.completed) != 0 {
		t.Errorf("completed %d runs that needed no upload", len(p.completed))
	}
}

func TestARepeatedRunIsNotUploadedTwice(t *testing.T) {
	p := &server{duplicate: true}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Fatal(err)
	}
	if len(p.uploads) != 0 || len(p.completed) != 0 {
		t.Errorf("a repeat uploaded %d and completed %d", len(p.uploads), len(p.completed))
	}
}

func TestAPlaneWithNoStorageIsReportedRatherThanIgnored(t *testing.T) {
	// The run was taken and its findings will never arrive. A publish that returned success there
	// would be worse than one that failed, because it looks fine.
	p := &server{evidenceError: "evidence storage is not configured"}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil {
		t.Fatal("a run whose evidence was refused reported success")
	}
	if !strings.Contains(err.Error(), "storage is not configured") {
		t.Errorf("err = %q, want the server's own reason", err)
	}
}

func TestThePlanesOwnReasonIsWhatSurfaces(t *testing.T) {
	// "400 Bad Request" in a build log tells somebody nothing they can act on. The server answers
	// with a code and a detail, and those are what a person needs to read.
	p := &server{
		status: http.StatusBadRequest,
		body:   `{"error":"invalid_field","detail":"verdict: required; post report.json, not results.sarif"}`,
	}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	err := pub.Publish(context.Background(), artifacts(`{}`, `{"runs":[]}`))
	if err == nil {
		t.Fatal("a refused run reported success")
	}
	if !strings.Contains(err.Error(), "invalid_field") || !strings.Contains(err.Error(), "results.sarif") {
		t.Errorf("err = %q, want the server's code and detail", err)
	}
}

func TestAnUnreadableFailureFallsBackToTheStatus(t *testing.T) {
	// A proxy or a load balancer answers in HTML. Reporting the status beats reporting nothing.
	p := &server{status: http.StatusBadGateway, body: "<html>bad gateway</html>"}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("err = %v, want the status", err)
	}
}

func TestBothReportsAreRequiredAndNamedSeparately(t *testing.T) {
	// Separate mistakes with separate fixes: one is a missing `json` in config.reports, the other
	// a missing `sarif`.
	p := &server{}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	for name, tc := range map[string]struct {
		artifacts []report.Artifact
		want      string
	}{
		"no json":  {artifacts("", `{"runs":[]}`), "'json'"},
		"no sarif": {artifacts(`{"verdict":"pass"}`, ""), "'sarif'"},
	} {
		t.Run(name, func(t *testing.T) {
			err := pub.Publish(context.Background(), tc.artifacts)
			if err == nil {
				t.Fatal("published without both reports")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to name %s", err, tc.want)
			}
		})
	}
}

func TestItSkipsWhereNoPlaneIsConfigured(t *testing.T) {
	// A descriptor naming this publisher on a developer's machine is somebody running the same
	// Saga locally. Failing their scan over it would make the descriptor unusable outside CI.
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiTokenEnv, "")

	p, err := For(saga.PublisherConfig{Kind: "draugr-api"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Errorf("a skipped publisher failed: %v", err)
	}
}

func TestHalfConfiguredIsAMistakeRatherThanAnIntention(t *testing.T) {
	// A scan that silently did not publish is one somebody believes was published.
	for name, env := range map[string]struct{ url, token string }{
		"url without token": {"https://server.example", ""},
		"token without url": {"", "drgr_ci_test"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(apiURLEnv, env.url)
			t.Setenv(apiTokenEnv, env.token)
			if _, err := For(saga.PublisherConfig{Kind: "draugr-api"}); err == nil {
				t.Error("a half-configured publisher was accepted")
			}
		})
	}
}

func TestTheKeyIsTheJobWhereThereIsOneAndTheReportOtherwise(t *testing.T) {
	// A retried job and a deliberate re-run of the same commit are different events, and only the
	// pipeline can tell them apart: identical inputs produce identical reports.
	runReport := []byte(`{"verdict":"pass"}`)
	sum := sha256.Sum256(runReport)
	digest := hex.EncodeToString(sum[:])

	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"github":         {map[string]string{"GITHUB_RUN_ID": "77"}, "77"},
		"github retried": {map[string]string{"GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "2"}, "77-2"},
		"gitlab":         {map[string]string{"CI_JOB_ID": "88"}, "88"},
		"azure":          {map[string]string{"BUILD_BUILDID": "99"}, "99"},
		"local":          {nil, digest},
	} {
		t.Run(name, func(t *testing.T) {
			for _, v := range []string{"GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "CI_JOB_ID",
				"BUILD_BUILDID", "CIRCLE_WORKFLOW_ID", "BUILDKITE_BUILD_ID"} {
				t.Setenv(v, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			p := draugrAPIPublisher{jobID: ciJobID()}
			if got := p.runKeyFor(runReport); got != tc.want {
				t.Errorf("key = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTheKeyIsNeverEmpty(t *testing.T) {
	// The server refuses a run without one, correctly. A publisher that let one through would fail
	// every scan run outside CI.
	p := draugrAPIPublisher{}
	if p.runKeyFor([]byte(`{}`)) == "" {
		t.Error("a run went out with no idempotency key")
	}
}

func TestTheEndpointToleratesATrailingSlash(t *testing.T) {
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiURLEnv, srv.URL+"/")
	t.Setenv(apiTokenEnv, "drgr_ci_test")

	pub, err := For(saga.PublisherConfig{Kind: "draugr-api"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Errorf("a trailing slash broke the endpoint: %v", err)
	}
}

func TestTheURLMayComeFromTheDescriptor(t *testing.T) {
	// The endpoint is not a secret and an on-prem team may want it written down. The token still
	// never is.
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiTokenEnv, "drgr_ci_test")

	pub, err := For(saga.PublisherConfig{Kind: "draugr-api", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Fatal(err)
	}
	if len(p.runs) != 1 {
		t.Errorf("the descriptor's url was not used")
	}
}

func TestTheKindIsRegistered(t *testing.T) {
	for _, k := range Kinds() {
		if k == "draugr-api" {
			return
		}
	}
	t.Errorf("draugr-api is not among %v", Kinds())
}

func TestTheOrganizationsDefaultIsUsedLast(t *testing.T) {
	// The whole point of the chain: config file, then environment, then the descriptor, with
	// explicit winning. A default that beat an environment variable, or an environment variable
	// that beat somebody's written choice, would each be the wrong way round.
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiTokenEnv, "drgr_ci_test")

	for name, tc := range map[string]struct {
		descriptor, env, orgDefault string
		want                        string
	}{
		"only the org default":      {"", "", srv.URL, srv.URL},
		"env beats the org default": {"", srv.URL, "https://never.example", srv.URL},
		"the descriptor beats both": {srv.URL, "https://never.example", "https://never.example", srv.URL},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(apiURLEnv, tc.env)
			pub, err := For(saga.PublisherConfig{
				Kind: "draugr-api", URL: tc.descriptor, DefaultURL: tc.orgDefault,
			})
			if err != nil {
				t.Fatal(err)
			}
			before := len(p.runs)
			if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
				t.Fatalf("publishing to %s: %v", tc.want, err)
			}
			if len(p.runs) != before+1 {
				t.Errorf("the run did not reach %s", tc.want)
			}
		})
	}
}

func TestAnOrganizationDefaultAloneIsEnoughToPublish(t *testing.T) {
	// A team whose runner image sets the endpoint once should not have to write it in every
	// descriptor, and must not have their scan skip for want of a URL nobody typed.
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiTokenEnv, "drgr_ci_test")

	pub, err := For(saga.PublisherConfig{Kind: "draugr-api", DefaultURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, skipped := pub.(skipPublisher); skipped {
		t.Fatal("a configured endpoint was treated as no endpoint at all")
	}
	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Fatal(err)
	}
}
