package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/pkg/ci"
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
	// policy, when set, is the organization's verdict the server answers with.
	policy map[string]any
	// polls are the answers to GET /v1/ingest/runs/{id}/policy, in order, the last repeated.
	polls []pollAnswer
	// polled records the run each poll asked about.
	polled []string
	// upload, when set, is where the server says to put the evidence: a presigned URL on another
	// origin, as an object store's is. Unset, the evidence goes to this server's own /evidence.
	upload string
	// redirect, when set, answers POST /v1/runs with a 307 to it.
	redirect string
	// moved, when set, is a path prefix the server answers with a 308 to the same path without it.
	moved string

	// requests counts everything that reached the server, and tokens the Authorization each carried.
	requests int
	tokens   []string
}

// reached is how many requests arrived, and every Authorization header among them.
func (p *server) reached() (int, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests, slices.Clone(p.tokens)
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
		if p.redirect != "" {
			http.Redirect(w, r, p.redirect, http.StatusTemporaryRedirect)
			return
		}
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
		answer := map[string]any{
			"run": "run-1", "project": "payments", "verdict": "pass",
			"duplicate": p.duplicate, "evidence": evidence,
		}
		if p.policy != nil {
			answer["policy"] = p.policy
		}
		_ = json.NewEncoder(w).Encode(answer)
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
	mux.HandleFunc("GET /v1/ingest/runs/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		n := len(p.polled)
		p.polled = append(p.polled, r.PathValue("id"))
		p.mu.Unlock()
		if len(p.polls) == 0 {
			t.Error("the run's policy was asked for, and the test expected no poll")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		a := p.polls[min(n, len(p.polls)-1)]
		for k, v := range a.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	})
	mux.HandleFunc("POST /v1/runs/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.completed = append(p.completed, r.PathValue("id"))
		p.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.requests++
		if auth := r.Header.Get("Authorization"); auth != "" {
			p.tokens = append(p.tokens, auth)
		}
		p.mu.Unlock()
		if p.moved != "" && strings.HasPrefix(r.URL.Path, p.moved+"/") {
			http.Redirect(w, r, strings.TrimPrefix(r.URL.Path, p.moved), http.StatusPermanentRedirect) // #nosec G710 -- a test server redirecting to a path on itself
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	upload = firstNonEmpty(p.upload, srv.URL+"/evidence")
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
	if err := pub.Publish(context.Background(), artifacts("{\n  \"verdict\": \"pass\"\n}\n", sarif)); err != nil {
		t.Fatal(err)
	}

	if len(p.runs) != 1 || len(p.uploads) != 1 || len(p.completed) != 1 {
		t.Fatalf("runs=%d uploads=%d completed=%d, want 1 each", len(p.runs), len(p.uploads), len(p.completed))
	}
	// Compact whatever the reporter wrote: a server bounds what it accepts, and indentation is
	// size nobody reads.
	if string(p.runs[0].body) != `{"verdict":"pass"}` {
		t.Errorf("body = %q, want the report compacted", p.runs[0].body)
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

// A server that reads only newer reports says which version it needs, and the error leads with that
// and with how to get it rather than with the server's code.
func TestAServerNeedingANewerDraugrSaysWhichAndHow(t *testing.T) {
	p := &server{status: http.StatusUnprocessableEntity, body: `{"error":"draugr_too_old",` +
		`"minimum":"0.122.0","detail":"this server reads runs from Draugr v0.122.0 or later"}`}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	err := pub.Publish(context.Background(),
		artifacts(`{"draugr":{"version":"0.110.0"},"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil {
		t.Fatal("published to a server that refused the report")
	}
	for _, want := range []string{srv.URL, "Draugr v0.122.0 or later", "this run used v0.110.0", "draugr self-update"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "draugr_too_old") {
		t.Errorf("err = %v, leads with the server's code", err)
	}
}

// Without the version to install the refusal is passed on as the server worded it.
func TestARefusalWithoutAMinimumIsPassedOnAsWorded(t *testing.T) {
	p := &server{status: http.StatusUnprocessableEntity,
		body: `{"error":"draugr_too_old","detail":"upgrade Draugr"}`}
	srv := p.server(t)
	pub := publisherFor(t, srv.URL)

	err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil || !strings.Contains(err.Error(), "draugr_too_old: upgrade Draugr") {
		t.Errorf("err = %v, want the server's own words", err)
	}
}

func TestAReportThatNamesNoVersionIsSaidPlainly(t *testing.T) {
	if got := versionIn([]byte(`{"verdict":"pass"}`)); got != "a Draugr that does not say its version" {
		t.Errorf("versionIn = %q", got)
	}
	if got := versionIn([]byte(`{"draugr":{"version":"v0.1.0"}}`)); got != "v0.1.0" {
		t.Errorf("versionIn = %q", got)
	}
}

func TestBothReportsAreRequiredAndNamedSeparately(t *testing.T) {
	// The publisher renders both for itself, so either one missing is a renderer that failed, and
	// the error names which.
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
			// The marker variables too, and not only the run ids: this suite runs inside CI,
			// where the real platform's marker is set and would win the detection.
			for _, v := range []string{"GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "CI_JOB_ID",
				"BUILD_BUILDID", "CIRCLE_WORKFLOW_ID", "BUILDKITE_BUILD_ID",
				"GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "CIRCLECI", "BUILDKITE"} {
				t.Setenv(v, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			p := draugrAPIPublisher{jobID: ci.Detect().JobID()}
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

func TestTheDescriptorsURLIsUsedWhereTheEnvironmentAllowsIt(t *testing.T) {
	// The endpoint is not a secret and an on-prem team may want it written down. The descriptor
	// changes by pull request, though, and the token goes where the url points, so the url is used
	// only on the environment's own origin or one the pipeline lists.
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiTokenEnv, "drgr_ci_test")

	for name, tc := range map[string]struct{ env, origins string }{
		"the origin $DRAUGR_API_URL names":   {srv.URL + "/another/path", ""},
		"an origin DRAUGR_API_ORIGINS lists": {"", "https://other.example, " + srv.URL + "/"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(apiURLEnv, tc.env)
			t.Setenv(apiOriginsEnv, tc.origins)
			pub, err := For(saga.PublisherConfig{Kind: "draugr-api", URL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			before := len(p.runs)
			if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
				t.Fatal(err)
			}
			if len(p.runs) != before+1 {
				t.Errorf("the descriptor's url was not used")
			}
		})
	}
}

// One legitimate destination and one a pull request added. The token reaches the one the
// environment names and nothing reaches the other: not the run, not the policy pre-flight, not the
// token.
func TestAURLTheEnvironmentDoesNotAllowGetsNoRequestAndNoToken(t *testing.T) {
	legit, hostile := &server{}, &server{}
	legitSrv, hostileSrv := legit.server(t), hostile.server(t)
	t.Setenv(apiURLEnv, legitSrv.URL)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	t.Setenv(apiOriginsEnv, "")

	err := Run(context.Background(), []saga.PublisherConfig{
		{Kind: "draugr-api"},
		{Kind: "draugr-api", URL: hostileSrv.URL},
	}, sampleData())
	if !errors.Is(err, ErrOriginRefused) {
		t.Fatalf("err = %v, want the descriptor's url refused", err)
	}
	for _, want := range []string{"the descriptor's url (" + hostileSrv.URL + ")", "$DRAUGR_API_URL (" + legitSrv.URL + ")", "DRAUGR_API_ORIGINS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if n, tokens := hostile.reached(); n != 0 || len(tokens) != 0 {
		t.Errorf("the hostile server got %d requests carrying %v", n, tokens)
	}
	if n, tokens := legit.reached(); n == 0 || len(legit.runs) != 1 || !slices.Contains(tokens, "Bearer drgr_ci_test") {
		t.Errorf("the environment's server got %d requests, %d runs, tokens %v", n, len(legit.runs), tokens)
	}

	// The pre-flight resolves the same way, so it is refused before anything is asked.
	_, _, err = ResolveAPI(saga.PublisherConfig{Kind: "draugr-api", URL: hostileSrv.URL})
	var refused *OriginRefusedError
	if !errors.As(err, &refused) || refused.Reason() != "the descriptor's url is not an allowed origin" {
		t.Errorf("ResolveAPI = %v", err)
	}
	if n, _ := hostile.reached(); n != 0 {
		t.Errorf("the hostile server got %d requests", n)
	}
}

func TestADescriptorsURLAloneIsNotWhereATokenGoes(t *testing.T) {
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiURLEnv, "")
	t.Setenv(apiOriginsEnv, "")

	t.Run("with a token", func(t *testing.T) {
		t.Setenv(apiTokenEnv, "drgr_ci_test")
		_, err := For(saga.PublisherConfig{Kind: "draugr-api", URL: srv.URL})
		if !errors.Is(err, ErrOriginRefused) || !strings.Contains(err.Error(), "$DRAUGR_API_URL is not set") ||
			!strings.Contains(err.Error(), "Set $DRAUGR_API_URL") {
			t.Errorf("err = %v, want DRAUGR_API_URL named", err)
		}
	})
	t.Run("without one", func(t *testing.T) {
		// A developer running the descriptor locally: nothing to send, so nothing to refuse.
		t.Setenv(apiTokenEnv, "")
		pub, err := For(saga.PublisherConfig{Kind: "draugr-api", URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		if _, skipped := pub.(skipPublisher); !skipped {
			t.Errorf("publisher = %T, want it skipped", pub)
		}
	})
	if n, _ := p.reached(); n != 0 {
		t.Errorf("the descriptor's server got %d requests", n)
	}
}

func TestAnUnreadableOriginIsAnError(t *testing.T) {
	t.Setenv(apiURLEnv, "https://draugr.example")
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	for name, tc := range map[string]struct{ url, origins, want string }{
		"the url":            {"ftp://draugr.example", "", "the descriptor's url"},
		"DRAUGR_API_ORIGINS": {"https://other.example", "draugr.example", "$DRAUGR_API_ORIGINS"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(apiOriginsEnv, tc.origins)
			_, _, err := ResolveAPI(saga.PublisherConfig{Kind: "draugr-api", URL: tc.url})
			if err == nil || errors.Is(err, ErrOriginRefused) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want an unreadable %s", err, tc.want)
			}
		})
	}
}

func TestTheTokenTravelsOnlyOverTLSOrToLoopback(t *testing.T) {
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	for endpoint, refused := range map[string]bool{
		"https://draugr.example":  false,
		"http://localhost:8080":   false,
		"http://127.0.0.1:8080":   false,
		"http://draugr.example":   true,
		"http://192.168.1.4:8080": true,
	} {
		t.Setenv(apiURLEnv, endpoint)
		_, _, err := ResolveAPI(saga.PublisherConfig{Kind: "draugr-api"})
		if got := err != nil; got != refused {
			t.Errorf("%s: err = %v, want refused: %v", endpoint, err, refused)
		}
		if refused && !errors.Is(err, credential.ErrInsecure) {
			t.Errorf("%s: err = %v, want ErrInsecure", endpoint, err)
		}
	}
}

// A tokenEnv names which of the job's secrets is sent. The descriptor may name the publisher's own
// variable, or one the pipeline lists.
func TestTheTokenEnvIsOneThePipelineAllows(t *testing.T) {
	t.Setenv(apiURLEnv, "https://draugr.example")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("PLANE_TOKEN", "drgr_ci_test")
	t.Setenv(credential.TokenEnvsVar, "PLANE_TOKEN")

	_, _, err := ResolveAPI(saga.PublisherConfig{Kind: "draugr-api", TokenEnv: "AWS_SECRET_ACCESS_KEY"}) // #nosec G101 -- the name of an environment variable
	var refused *credential.RefusedVariableError
	if !errors.As(err, &refused) || refused.Name != "AWS_SECRET_ACCESS_KEY" || strings.Contains(err.Error(), "aws-secret") {
		t.Errorf("err = %v, want AWS_SECRET_ACCESS_KEY refused without its value", err)
	}
	dest, _, err := ResolveAPI(saga.PublisherConfig{Kind: "draugr-api", TokenEnv: "PLANE_TOKEN"})
	if err != nil || dest.Token != "drgr_ci_test" {
		t.Errorf("a listed variable: %+v, %v", dest, err)
	}
}

// The evidence goes to the presigned URL the server returns, on another origin, and carries no
// Authorization: the signature is in the URL.
func TestTheEvidenceGoesToStorageWithoutTheToken(t *testing.T) {
	var mu sync.Mutex
	var puts, auths []string
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		puts = append(puts, r.Method+" "+r.URL.Path)
		auths = append(auths, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(storage.Close)
	p := &server{upload: storage.URL + "/bucket/evidence?X-Amz-Signature=abc"}
	pub := publisherFor(t, p.server(t).URL)

	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(puts) != 1 || puts[0] != "PUT /bucket/evidence" || auths[0] != "" {
		t.Errorf("storage got %v with Authorization %q", puts, auths)
	}
	if len(p.completed) != 1 {
		t.Errorf("completed %d runs, want 1", len(p.completed))
	}
}

// The server sends the token to whatever answers a redirect only where the redirect stays on its
// origin. Elsewhere the request is refused, and the other server is never asked.
func TestARedirectToAnotherOriginIsRefused(t *testing.T) {
	elsewhere := &server{}
	elsewhereSrv := elsewhere.server(t)
	p := &server{redirect: elsewhereSrv.URL + "/v1/runs"}
	pub := publisherFor(t, p.server(t).URL)

	err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`))
	if err == nil || !strings.Contains(err.Error(), "refused a redirect") {
		t.Fatalf("err = %v, want the redirect refused", err)
	}
	if n, tokens := elsewhere.reached(); n != 0 || len(tokens) != 0 {
		t.Errorf("the redirect's target got %d requests carrying %v", n, tokens)
	}
}

// A server cleaning a path answers with a relative Location, on its own origin, and the request
// follows it with the token.
func TestARedirectOnTheSameOriginIsFollowed(t *testing.T) {
	p := &server{moved: "/old"}
	pub := publisherFor(t, p.server(t).URL+"/old")

	if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
		t.Fatal(err)
	}
	if len(p.runs) != 1 || p.runs[0].auth != "Bearer drgr_ci_test" || len(p.completed) != 1 {
		t.Errorf("runs = %+v, completed = %v", p.runs, p.completed)
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

func TestTheEnvironmentNamesTheServer(t *testing.T) {
	// $DRAUGR_API_URL, then the machine's configuration. The project's draugr.config.yaml is
	// committed with the repository, so like the descriptor's url it is consulted where the
	// environment allows it and never beats the environment.
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	t.Setenv(apiOriginsEnv, "")

	for name, tc := range map[string]struct {
		env, machine, project string
	}{
		"only the machine's default":                     {"", srv.URL, ""},
		"env beats the machine's default":                {srv.URL, "https://never.example", ""},
		"env beats the project's file":                   {srv.URL, "", "https://never.example"},
		"the project's file on the machine's own origin": {"", srv.URL + "/old", srv.URL},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(apiURLEnv, tc.env)
			pub, err := For(saga.PublisherConfig{
				Kind: "draugr-api", DefaultURL: tc.machine, ProjectURL: tc.project,
			})
			if err != nil {
				t.Fatal(err)
			}
			before := len(p.runs)
			if err := pub.Publish(context.Background(), artifacts(`{"verdict":"pass"}`, `{"runs":[]}`)); err != nil {
				t.Fatalf("publishing to %s: %v", srv.URL, err)
			}
			if len(p.runs) != before+1 {
				t.Errorf("the run did not reach %s", srv.URL)
			}
		})
	}

	t.Run("the project's file on another origin", func(t *testing.T) {
		t.Setenv(apiURLEnv, "")
		_, err := For(saga.PublisherConfig{Kind: "draugr-api", DefaultURL: srv.URL, ProjectURL: "https://elsewhere.example"})
		var refused *OriginRefusedError
		if !errors.As(err, &refused) || refused.Reason() != "publish.apiUrl in the project's draugr.config.yaml is not an allowed origin" ||
			!strings.Contains(err.Error(), "publish.apiUrl in the machine's configuration ("+srv.URL+")") {
			t.Errorf("err = %v", err)
		}
	})
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

// A destination that can deliver only one thing knows what that thing is. `kind: draugr-api` and
// nothing else has to be a complete instruction: the server needs the run report and the evidence,
// neither is a choice anybody makes, and a descriptor that has to name them is one that fails when
// somebody forgets, on a publisher that cannot work without them.
//
// Through Run rather than the publisher directly, because what is being asserted is what the
// publisher was handed, and only Run decides that.
func TestTheAPIPublisherNeedsNothingDeclaredBesideIt(t *testing.T) {
	t.Setenv(apiTokenEnv, "t0ken")
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiURLEnv, srv.URL)

	err := Run(context.Background(),
		[]saga.PublisherConfig{{Kind: "draugr-api"}},
		sampleData(),
	)
	if err != nil {
		t.Fatalf("a draugr-api publisher standing alone should publish: %v", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.runs) != 1 {
		t.Fatalf("posted %d runs, want 1", len(p.runs))
	}
	// The run report is the request body, and it has to be the JSON document rather than whatever
	// happened to be first.
	var doc map[string]any
	if err := json.Unmarshal(p.runs[0].body, &doc); err != nil {
		t.Errorf("the run report was not the json report: %v", err)
	}
	if len(p.uploads) != 1 {
		t.Fatalf("uploaded %d evidence documents, want 1", len(p.uploads))
	}
	if !bytes.Contains(p.uploads[0], []byte("$schema")) {
		t.Error("the evidence uploaded was not the SARIF report")
	}
}

// The run a publisher posts says which Draugr produced it, as the report.json written to disk
// does. A platform refuses a run that cannot say, so a document that dropped the block on the way
// to the publisher turned every publish into a refusal while the file beside it looked complete.
func TestThePostedRunSaysWhichDraugrProducedIt(t *testing.T) {
	p := &server{}
	srv := p.server(t)
	t.Setenv(apiURLEnv, srv.URL)
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	d := sampleData()
	d.Version, d.Commit = "0.143.0", "19b01f2"
	if err := Run(context.Background(), []saga.PublisherConfig{{Kind: "draugr-api"}}, d); err != nil {
		t.Fatal(err)
	}
	if len(p.runs) != 1 {
		t.Fatalf("runs posted = %d, want 1", len(p.runs))
	}
	var posted struct {
		Draugr *struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		} `json:"draugr"`
	}
	if err := json.Unmarshal(p.runs[0].body, &posted); err != nil {
		t.Fatalf("posted run is not JSON: %v", err)
	}
	if posted.Draugr == nil || posted.Draugr.Version != "0.143.0" || posted.Draugr.Commit != "19b01f2" {
		t.Errorf("draugr block = %+v, want version 0.143.0 and commit 19b01f2:\n%s", posted.Draugr, p.runs[0].body)
	}
}

// A json report that is not JSON is said plainly rather than sent for the server to refuse.
func TestAReportThatIsNotJSONIsRefusedBeforeItIsSent(t *testing.T) {
	p := &server{}
	srv := p.server(t)
	err := publisherFor(t, srv.URL).Publish(context.Background(), artifacts(`{"verdict":`, `{"runs":[]}`))
	if err == nil || !strings.Contains(err.Error(), "not JSON") || len(p.runs) != 0 {
		t.Errorf("err = %v, posted %d runs", err, len(p.runs))
	}
}
