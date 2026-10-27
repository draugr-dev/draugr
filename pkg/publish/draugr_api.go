package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// draugrAPIPublisher posts a run to anything implementing Draugr's run-ingest API.
//
// Named for the protocol rather than for one server, because the protocol is the interesting part.
// Draugr Server implements it, hosted and on-premise; so can anybody else. The calls are
// documented in the reports-and-publishers guide, and nothing here privileges one implementation
// over another. A publisher named after a product would have made the endpoint look like a
// configuration detail of that product rather than an interface.
//
// Two documents, and they travel differently. `report.json` is the run, bounded, and goes in the
// request body. `results.sarif` is the evidence and never goes through the API at all: the
// response returns a URL to put it to, and this uploads it directly.
//
// That is the only path rather than an optimization for large payloads. At roughly 2.5 KB of SARIF
// per finding, a descriptor covering twenty images is around 20 MB before anything unusual
// happens, and a request body is the wrong place for it, body limits, proxy timeouts and the
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
	// apiOriginsEnv lists further origins a descriptor's url may name, comma-separated.
	apiOriginsEnv = "DRAUGR_API_ORIGINS"
)

// APIDestination is the server a draugr-api publisher sends a run to, and the token it sends.
type APIDestination struct {
	Endpoint string
	Token    string
	// Login is the person's login the token came from, nil for a token from the environment. Only
	// ResolvePolicyAPI sets it, so only a policy check carries one.
	Login *login.Login
}

// ErrOriginRefused is a url, written in the descriptor or in the project's draugr.config.yaml,
// that names a server the environment does not allow.
var ErrOriginRefused = errors.New("not an allowed origin")

// OriginRefusedError is a url the token may not be sent to, and what it was compared with.
type OriginRefusedError struct {
	// Field says where the refused url was written.
	Field string
	// URL is the refused address.
	URL string
	// Endpoint is the address the environment names, and EndpointFrom where it was read. Both are
	// empty where the environment names none.
	Endpoint, EndpointFrom string
}

func (e *OriginRefusedError) Error() string {
	if e.Endpoint == "" {
		return fmt.Sprintf("draugr-api publisher: %s (%s) is not an allowed origin, and $%s is not set. "+
			"Set $%s to the server's address, or add the url's origin to $%s",
			e.Field, e.URL, apiURLEnv, apiURLEnv, apiOriginsEnv)
	}
	return fmt.Sprintf("draugr-api publisher: %s (%s) and %s (%s) name different origins, and the token "+
		"is sent only to the one the environment names. Remove the url, or add its origin to $%s",
		e.Field, e.URL, e.EndpointFrom, e.Endpoint, apiOriginsEnv)
}

// Is makes the error match ErrOriginRefused.
func (e *OriginRefusedError) Is(target error) bool { return target == ErrOriginRefused }

// Reason is the refusal as a policy check's "not checked" reason.
func (e *OriginRefusedError) Reason() string { return e.Field + " is not an allowed origin" }

// APIURLSet reports whether the environment names a draugr-api server.
func APIURLSet() bool { return os.Getenv(apiURLEnv) != "" }

// ResolveAPI finds where a draugr-api publisher would send a run, the way the publisher does.
//
// The server comes from the environment: $DRAUGR_API_URL, else publish.apiUrl in the machine's
// configuration. A url written in the descriptor, or in the project's own draugr.config.yaml, is a
// value that changes by pull request in the repository being scanned, so it is used only where its
// origin is the environment's, or one $DRAUGR_API_ORIGINS lists. Otherwise the token would go to
// whichever server the most recent change to the repository named.
//
// Neither an endpoint nor a token is somebody running the descriptor locally, which is not a
// mistake: skip says why there is nowhere to send. One without the other is a mistake, and an
// error. So is a token bound for a url the environment does not allow, an *OriginRefusedError, and
// a token bound for a server reached without TLS.
func ResolveAPI(cfg saga.PublisherConfig) (dest APIDestination, skip string, err error) {
	tokenEnv, token, err := credential.Token(cfg.TokenEnv, apiTokenEnv)
	if err != nil {
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: %w", err)
	}
	endpoint, err := apiEndpoint(cfg, token != "")
	if err != nil {
		return APIDestination{}, "", err
	}
	dest = APIDestination{Endpoint: strings.TrimRight(endpoint, "/"), Token: token}
	// Both or neither. A descriptor naming this publisher on a machine with no endpoint configured is
	// somebody running the same Saga locally, and failing their scan over it would make the
	// descriptor unusable outside CI, the opposite of the point.
	if dest.Endpoint == "" && dest.Token == "" {
		return APIDestination{}, "no $" + apiURLEnv + " or $" + tokenEnv, nil
	}
	var missing []string
	if dest.Endpoint == "" {
		missing = append(missing, "$"+apiURLEnv)
	}
	if dest.Token == "" {
		missing = append(missing, "$"+tokenEnv)
	}
	if len(missing) > 0 {
		// Half-configured is a mistake rather than an intention, and a scan that silently did not
		// publish is one somebody believes was published.
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: %s", strings.Join(missing, ", "))
	}
	if err := credential.RequireTLS(dest.Endpoint); err != nil {
		return APIDestination{}, "", fmt.Errorf("draugr-api publisher: $%s: %w", tokenEnv, err)
	}
	return dest, "", nil
}

// apiEndpoint is the server a run goes to.
//
// The environment's address, or a url the repository wrote where the environment allows it. A
// refused url on a machine with no endpoint and no token is a local run with nothing to send, so it
// resolves to no endpoint and ResolveAPI skips.
func apiEndpoint(cfg saga.PublisherConfig, hasToken bool) (string, error) {
	return apiEndpointAllowing(cfg, hasToken, nil)
}

// apiEndpointAllowing is apiEndpoint, where loggedIn, when set, also allows a url whose origin
// holds a login.
func apiEndpointAllowing(cfg saga.PublisherConfig, hasToken bool, loggedIn func(origin string) bool) (string, error) {
	trusted, trustedFrom := os.Getenv(apiURLEnv), "$"+apiURLEnv
	if trusted == "" {
		trusted, trustedFrom = cfg.DefaultURL, "publish.apiUrl in the machine's configuration"
	}
	named, field := cfg.URL, "the descriptor's url"
	// The project's draugr.config.yaml has always lost to $DRAUGR_API_URL, so it is consulted only
	// where that is unset. It is committed with the repository, so it is held to the descriptor's
	// rule rather than trusted as the machine's.
	if named == "" && os.Getenv(apiURLEnv) == "" {
		named, field = cfg.ProjectURL, "publish.apiUrl in the project's draugr.config.yaml"
	}
	if named == "" {
		return trusted, nil
	}
	ok, err := allowedOrigin(named, trusted)
	if err != nil {
		return "", fmt.Errorf("draugr-api publisher: %s: %w", field, err)
	}
	if !ok && loggedIn != nil {
		origin, _ := credential.Origin(named)
		ok = loggedIn(origin)
	}
	switch {
	case ok:
		return named, nil
	case trusted == "" && !hasToken:
		return "", nil
	}
	return "", &OriginRefusedError{Field: field, URL: named, Endpoint: trusted, EndpointFrom: trustedFrom}
}

// allowedOrigin reports whether a url the repository wrote may receive the token: its origin is the
// environment's endpoint's, or $DRAUGR_API_ORIGINS lists it.
func allowedOrigin(named, trusted string) (bool, error) {
	origin, err := credential.Origin(named)
	if err != nil {
		return false, err
	}
	if trusted != "" {
		if t, err := credential.Origin(trusted); err == nil && t == origin {
			return true, nil
		}
	}
	for _, entry := range credential.List(apiOriginsEnv) {
		listed, err := credential.Origin(entry)
		if err != nil {
			return false, fmt.Errorf("$%s: %w", apiOriginsEnv, err)
		}
		if listed == origin {
			return true, nil
		}
	}
	return false, nil
}

func newDraugrAPIPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	dest, skip, err := ResolveAPI(cfg)
	if err != nil {
		return nil, err
	}
	if skip != "" {
		return skipPublisher{kind: "draugr-api", reason: skip}, nil
	}
	return draugrAPIPublisher{
		endpoint: dest.Endpoint,
		token:    dest.Token,
		jobID:    ci.Detect().JobID(),
		client:   newRetryingClient(http.DefaultClient),
	}, nil
}

// Kind is the publisher's config selector.
func (draugrAPIPublisher) Kind() string { return "draugr-api" }

// Publish posts the run, uploads the evidence, and says the upload landed. A run the
// organization's policy fails is an error once the run is recorded.
func (p draugrAPIPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	accepted, err := p.deliver(ctx, artifacts)
	if err != nil {
		return err
	}
	// The organization's verdict on the run, returned once the run is fully recorded, so a failing
	// policy fails the build without leaving the run half published.
	return policyFailure(accepted.Run, accepted.Policy)
}

// deliver posts the run, uploads the evidence, says the upload landed, and returns the server's
// answer. A retried run and evidence the server already holds are delivered too: the run exists.
func (p draugrAPIPublisher) deliver(ctx context.Context, artifacts []report.Artifact) (acceptedRun, error) {
	var runReport, evidence []byte
	for _, a := range artifacts {
		switch a.Format {
		case "json":
			runReport = a.Bytes
		case "sarif":
			evidence = a.Bytes
		}
	}
	// Named separately, because each comes from a different reporter and the error says which failed.
	if runReport == nil {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher requires a 'json' report")
	}
	if evidence == nil {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher requires a 'sarif' report")
	}
	// Compact, however the reporter wrote it. The document goes from one program to another, its
	// indentation is a fifth of its size, and a server bounds what it accepts. The evidence is
	// uploaded byte for byte, because its digest is sent ahead of it.
	var packed bytes.Buffer
	if err := json.Compact(&packed, runReport); err != nil {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: the json report is not JSON: %w", err)
	}
	runReport = packed.Bytes()

	accepted, err := p.postRun(ctx, runReport, evidence)
	if err != nil {
		return acceptedRun{}, err
	}
	if accepted.Duplicate {
		// A retried job. The run exists; there is nothing to upload and nothing to complete.
		slog.Info("run already recorded", "run", accepted.Run, "project", accepted.Project)
		return accepted, nil
	}
	if accepted.Evidence.Held {
		slog.Info("evidence already held", "run", accepted.Run, "project", accepted.Project)
		return accepted, nil
	}
	if accepted.Evidence.Error != "" {
		// The server took the run and cannot take its evidence. Reported rather than swallowed: a
		// run whose findings never arrive is worse than a failed publish, because it looks fine.
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: run %s recorded, evidence refused: %s",
			accepted.Run, accepted.Evidence.Error)
	}
	if accepted.Evidence.Upload == "" {
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: run %s recorded with no upload URL", accepted.Run)
	}

	if err := p.putEvidence(ctx, accepted.Evidence.Upload, evidence); err != nil {
		return acceptedRun{}, err
	}
	if err := p.complete(ctx, accepted.Run); err != nil {
		return acceptedRun{}, err
	}
	slog.Info("run published", "run", accepted.Run, "project", accepted.Project,
		"verdict", accepted.Verdict)
	return accepted, nil
}

// policyFailure is the error a run's policy outcome makes, nil where the policy passes it or the
// server said nothing about policy.
//
// A verdict the server decides once the evidence is expanded is noted in the log: nothing waits for
// it on this path, and the run page is where a failure would then appear.
func policyFailure(run string, policy *skald.PolicyOutcome) error {
	if policy == nil {
		return nil
	}
	logPending(run, *policy)
	if policy.Outcome != skald.PolicyFail {
		return nil
	}
	return fmt.Errorf("draugr-api publisher: run %s recorded, and the organization's policy fails it: %s",
		run, policy.Summary(skald.PolicyFail))
}

// logPending notes each setting the server decides after the scan has stopped asking.
func logPending(run string, policy skald.PolicyOutcome) {
	for _, v := range policy.Verdicts {
		if v.Pending {
			slog.Info("policy decided after publish", "run", run, "rule", v.Rule, "profile", v.Profile,
				"term", v.Term())
		}
	}
}

// acceptedRun is what the server answers.
type acceptedRun struct {
	Run       string `json:"run"`
	Project   string `json:"project"`
	Verdict   string `json:"verdict"`
	Duplicate bool   `json:"duplicate"`
	// Policy is the organization's verdict on the run, absent from a server that judges none.
	Policy   *skald.PolicyOutcome `json:"policy,omitempty"`
	Evidence struct {
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
		refused := readRefusal(resp)
		if refused.Code == "policy_refused" && refused.Policy != nil {
			return acceptedRun{}, fmt.Errorf("draugr-api publisher: the organization's policy refused the run: %s",
				refused.Policy.Summary(skald.PolicyRefuse))
		}
		if refused.Code == "draugr_too_old" && refused.Minimum != "" {
			return acceptedRun{}, fmt.Errorf("draugr-api publisher: %s reads runs from Draugr v%s or "+
				"later, and this run used %s. Update with 'draugr self-update', or raise the version the "+
				"pipeline installs", p.endpoint, strings.TrimPrefix(refused.Minimum, "v"), versionIn(runReport))
		}
		return acceptedRun{}, fmt.Errorf("draugr-api publisher: post run: %s", refused.said(resp.Status))
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
	return readRefusal(resp).said(resp.Status)
}

// refusal is the body every failure from the server takes.
//
// Minimum is set on `draugr_too_old` only: the oldest Draugr the server reads, which is what a
// reader has to install and so what the error has to lead with.
type refusal struct {
	Code    string `json:"error"`
	Detail  string `json:"detail"`
	Minimum string `json:"minimum"`
	// Policy is the outcome a `policy_refused` refusal carries.
	Policy *skald.PolicyOutcome `json:"policy"`
}

// readRefusal reads a failure's body, leaving it empty when the body is not one. Read to a megabyte,
// because a policy refusal carries every verdict.
func readRefusal(resp *http.Response) refusal {
	var r refusal
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return refusal{}
	}
	return r
}

// said is the refusal as one line, falling back to the status where the body said nothing.
func (r refusal) said(status string) string {
	switch {
	case r.Code == "":
		return status
	case r.Detail == "":
		return fmt.Sprintf("%s (%s)", r.Code, status)
	default:
		return fmt.Sprintf("%s: %s", r.Code, r.Detail)
	}
}

// versionIn is the Draugr version a report says wrote it, as the server read it.
func versionIn(runReport []byte) string {
	var doc struct {
		Draugr struct {
			Version string `json:"version"`
		} `json:"draugr"`
	}
	if json.Unmarshal(runReport, &doc) != nil || doc.Draugr.Version == "" {
		return "a Draugr that does not say its version"
	}
	return "v" + strings.TrimPrefix(doc.Draugr.Version, "v")
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
// The digest of the report when nothing names the job, the local case, where the same report
// posted twice is a retry by any reasonable reading. Never empty: the API refuses a run without a
// key, correctly, and a publisher that let one through would fail every scan run outside CI.
func (p draugrAPIPublisher) runKeyFor(runReport []byte) string {
	if p.jobID != "" {
		return p.jobID
	}
	return digestOf(runReport)
}
