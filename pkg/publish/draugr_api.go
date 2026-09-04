package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// draugrAPIPublisher posts a run to anything implementing Draugr's run-ingest API.
//
// Named for the protocol rather than for one server, because the protocol is the interesting part.
// Draugr Server implements it, hosted and on-premise; so can anybody else — the three calls are
// documented in the reports-and-publishers guide, and nothing here privileges one implementation
// over another. A publisher named after a product would have made the endpoint look like a
// configuration detail of that product rather than an interface.
//
// Two documents, and they travel differently. `report.json` is the run — small, always — and goes
// in the request body. `results.sarif` is the evidence and never goes through the API at all: the
// response returns a URL to put it to, and this uploads it directly.
//
// That is the only path rather than an optimization for large payloads. At roughly 2.5 KB of SARIF
// per finding, a descriptor covering twenty images is around 20 MB before anything unusual
// happens, and a request body is the wrong place for it — body limits, proxy timeouts and the
// server parsing it all arrive together.
type draugrAPIPublisher struct {
	endpoint string
	token    string
	// jobID names the CI job, when the platform provides one.
	jobID  string
	client *http.Client
}

// Environment the publisher reads. The token is never taken from the descriptor: a Saga is a file
// people commit, and a credential in one is a credential in their git history.
//
// Named for the API too, so a team pointing at their own implementation is not setting a variable
// named after somebody else's product.
const (
	apiURLEnv = "DRAUGR_API_URL"
	// #nosec G101 -- the name of an environment variable, not a credential. The value is read
	// from the environment at run time and never appears in this repository.
	apiTokenEnv = "DRAUGR_API_TOKEN"
)

func newDraugrAPIPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, apiTokenEnv)
	p := draugrAPIPublisher{
		// Explicit, then ambient-immediate, then the organization's default. Documented in the
		// Saga reference under the draugr-api publisher.
		endpoint: strings.TrimRight(firstNonEmpty(cfg.URL, os.Getenv(apiURLEnv), cfg.DefaultURL), "/"),
		token:    os.Getenv(tokenEnv),
		jobID:    ci.Detect().JobID(),
		client:   newRetryingClient(http.DefaultClient),
	}

	// Both or neither. A descriptor naming this publisher on a machine with no endpoint configured
	// is somebody running the same Saga locally, and failing their scan over it would make the
	// descriptor unusable outside CI — which is the opposite of the point.
	if p.endpoint == "" && p.token == "" {
		return skipPublisher{
			kind:   "draugr-api",
			reason: "no $" + apiURLEnv + " or $" + tokenEnv,
		}, nil
	}
	var missing []string
	if p.endpoint == "" {
		missing = append(missing, "url (or $"+apiURLEnv+")")
	}
	if p.token == "" {
		missing = append(missing, "$"+tokenEnv)
	}
	if len(missing) > 0 {
		// Half-configured is a mistake rather than an intention, and a scan that silently did not
		// publish is one somebody believes was published.
		return nil, fmt.Errorf("draugr-api publisher: %s", strings.Join(missing, ", "))
	}
	return p, nil
}

// Kind is the publisher's config selector.
func (draugrAPIPublisher) Kind() string { return "draugr-api" }

// Publish posts the run, uploads the evidence, and says the upload landed.
func (p draugrAPIPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	var runReport, evidence []byte
	for _, a := range artifacts {
		switch a.Format {
		case "json":
			runReport = a.Bytes
		case "sarif":
			evidence = a.Bytes
		}
	}
	// Named separately, because they are separate mistakes with separate fixes.
	if runReport == nil {
		return fmt.Errorf("draugr-api publisher requires a 'json' report in config.reports")
	}
	if evidence == nil {
		return fmt.Errorf("draugr-api publisher requires a 'sarif' report in config.reports")
	}

	accepted, err := p.postRun(ctx, runReport, evidence)
	if err != nil {
		return err
	}
	if accepted.Duplicate {
		// A retried job. The run exists; there is nothing to upload and nothing to complete.
		slog.Info("run already recorded", "run", accepted.Run, "project", accepted.Project)
		return nil
	}
	if accepted.Evidence.Held {
		slog.Info("evidence already held", "run", accepted.Run, "project", accepted.Project)
		return nil
	}
	if accepted.Evidence.Error != "" {
		// The server took the run and cannot take its evidence. Reported rather than swallowed: a
		// run whose findings never arrive is worse than a failed publish, because it looks fine.
		return fmt.Errorf("draugr-api publisher: run %s recorded, evidence refused: %s",
			accepted.Run, accepted.Evidence.Error)
	}
	if accepted.Evidence.Upload == "" {
		return fmt.Errorf("draugr-api publisher: run %s recorded with no upload URL", accepted.Run)
	}

	if err := p.putEvidence(ctx, accepted.Evidence.Upload, evidence); err != nil {
		return err
	}
	if err := p.complete(ctx, accepted.Run); err != nil {
		return err
	}
	slog.Info("run published", "run", accepted.Run, "project", accepted.Project,
		"verdict", accepted.Verdict)
	return nil
}

// acceptedRun is what the server answers.
type acceptedRun struct {
	Run       string `json:"run"`
	Project   string `json:"project"`
	Verdict   string `json:"verdict"`
	Duplicate bool   `json:"duplicate"`
	Evidence  struct {
		Held   bool   `json:"held"`
		Upload string `json:"upload"`
		Error  string `json:"error"`
	} `json:"evidence"`
}

// postRun sends the report and asks where the evidence should go.
func (p draugrAPIPublisher) postRun(ctx context.Context, runReport, evidence []byte) (acceptedRun, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/v1/runs",
		bytes.NewReader(runReport))
	if err != nil {
		return acceptedRun{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Idempotency-Key", p.runKeyFor(runReport))
	// The digest travels before the bytes do, which is what lets a server address the evidence by
	// its content and answer "already held" for a re-run that produced the same findings.
	req.Header.Set("X-Draugr-Evidence-Sha256", digestOf(evidence))
	req.Header.Set("X-Draugr-Evidence-Bytes", strconv.Itoa(len(evidence)))

	resp, err := p.client.Do(req)
	if err != nil {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: post run: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: post run: %s", serverError(resp))
	}
	var accepted acceptedRun
	if err := json.NewDecoder(resp.Body).Decode(&accepted); err != nil {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: unreadable response: %w", err)
	}
	return accepted, nil
}

// putEvidence uploads the SARIF straight to storage.
func (p draugrAPIPublisher) putEvidence(ctx context.Context, url string, evidence []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(evidence))
	if err != nil {
		return err
	}
	// Set explicitly, so the body is sent with a length rather than chunked. A presigned URL is
	// signed for a specific request shape, and some stores refuse a chunked one.
	req.ContentLength = int64(len(evidence))
	// Deliberately no Authorization header. The URL carries its own signature, and sending the
	// ingest token to a storage endpoint would hand a credential to a host that has no business
	// holding one.
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("draugr-api publisher: upload evidence: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("draugr-api publisher: upload evidence: %s", serverError(resp))
	}
	return nil
}

// complete says the evidence has landed.
func (p draugrAPIPublisher) complete(ctx context.Context, runID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.endpoint+"/v1/runs/"+runID+"/complete", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("draugr-api publisher: complete run: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("draugr-api publisher: complete run: %s", serverError(resp))
	}
	return nil
}

// serverError renders what the server said, preferring its own code over an HTTP status.
//
// The API answers failures as a stable code and a short detail. Reporting those beats reporting
// "400 Bad Request", which tells somebody reading a build log nothing they can act on.
func serverError(resp *http.Response) string {
	var body struct {
		Code   string `json:"error"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&body); err != nil || body.Code == "" {
		return resp.Status
	}
	if body.Detail == "" {
		return fmt.Sprintf("%s (%s)", body.Code, resp.Status)
	}
	return fmt.Sprintf("%s: %s", body.Code, body.Detail)
}

// digestOf is the content address of some bytes.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// runKeyFor identifies this run to the server.
//
// A CI job id where there is one, so a retried job is recognized as the same run and a deliberate
// re-run of the same commit is recognized as a different one. Those are different events and only
// the pipeline can tell them apart: identical inputs produce identical reports, so a digest alone
// would call the second a duplicate of the first.
//
// The digest of the report when nothing names the job — the local case, where the same report
// posted twice is a retry by any reasonable reading. Never empty: the API refuses a run without
// a key, correctly, and a publisher that let one through would fail every scan run outside CI.
func (p draugrAPIPublisher) runKeyFor(runReport []byte) string {
	if p.jobID != "" {
		return p.jobID
	}
	return digestOf(runReport)
}
