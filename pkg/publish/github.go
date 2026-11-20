package publish

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// githubPublisher uploads the SARIF report to GitHub code scanning (the Security → Code
// scanning alerts tab). Repo/commit/ref default to the standard GitHub Actions environment
// (GITHUB_REPOSITORY / GITHUB_SHA / GITHUB_REF); the token is read from an environment variable
// (never the Saga) so no secret is stored in the descriptor or logged.
//
// Code scanning is free for public repos; private repos require GitHub Advanced Security.
//
// After the upload it dismisses the alerts of suppressed findings, which code scanning does not do
// for itself; see github_dismiss.go.
type githubPublisher struct {
	repo, commit, ref, token, apiURL string
	client                           *http.Client
	// processingWait is how long to wait for GitHub to process an upload before its alerts can be
	// dismissed, and processingPoll how often to ask.
	processingWait, processingPoll time.Duration
}

func newGithubPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv, token, err := tokenFor(cfg)
	if err != nil {
		return nil, err
	}
	g := githubPublisher{
		repo:   firstNonEmpty(cfg.Repo, os.Getenv("GITHUB_REPOSITORY")),
		commit: firstNonEmpty(cfg.Commit, os.Getenv("GITHUB_SHA")),
		ref:    firstNonEmpty(cfg.Ref, os.Getenv("GITHUB_REF")),
		token:  token,
		apiURL: firstNonEmpty(os.Getenv("GITHUB_API_URL"), "https://api.github.com"),
		client: newRetryingClient(http.DefaultClient),
		// Processing usually takes seconds. The bound is generous because a run that gives up
		// leaves the tab disagreeing with the report, and says so.
		processingWait: 5 * time.Minute,
		processingPoll: 5 * time.Second,
	}
	// The github publisher targets a CI code-scanning upload. When a Saga carries it but the scan
	// runs outside GitHub Actions with no GitHub context resolvable (e.g. a developer running the
	// same Saga locally), skip instead of failing. There is no commit/ref to publish against. Any
	// resolvable field (from config or env) means publishing is intended, so validate strictly.
	if os.Getenv("GITHUB_ACTIONS") != "true" && g.repo == "" && g.commit == "" && g.ref == "" && g.token == "" {
		return skipPublisher{kind: "github", reason: "not a GitHub Actions environment"}, nil
	}
	var missing []string
	if g.repo == "" {
		missing = append(missing, "repo (or $GITHUB_REPOSITORY)")
	}
	if g.commit == "" {
		missing = append(missing, "commit (or $GITHUB_SHA)")
	}
	if g.ref == "" {
		missing = append(missing, "ref (or $GITHUB_REF)")
	}
	if g.token == "" {
		missing = append(missing, "$"+tokenEnv)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("github publisher missing: %s", strings.Join(missing, ", "))
	}
	return g, nil
}

func (githubPublisher) Kind() string { return "github" }

// PublishRun is Publish, with a finding on an image placed on the line of the descriptor that
// declares the image, which the run knows and the rendered report does not carry.
func (g githubPublisher) PublishRun(ctx context.Context, data report.Data, artifacts []report.Artifact) error {
	return g.publish(ctx, artifacts, data.Declared)
}

// Publish uploads the sarif report with a finding on an image left with no location, since without
// the run there is nothing to say where the image is declared.
func (g githubPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	return g.publish(ctx, artifacts, nil)
}

func (g githubPublisher) publish(ctx context.Context, artifacts []report.Artifact, declared sarif.Declarations) error {
	var doc []byte
	for _, a := range artifacts {
		if a.Format == "sarif" {
			doc = a.Bytes
			break
		}
	}
	if doc == nil {
		return fmt.Errorf("github publisher requires a 'sarif' report")
	}
	// What is uploaded, and what the dismissal pass reads, is the report less the copies of flaws
	// another scanner's finding is counted under. The artifact itself is left as rendered, because
	// it is shared with every other destination that asked for the sarif report.
	doc, err := countedOnly(doc)
	if err != nil {
		return err
	}
	// And less the locations code scanning refuses, which would cost the whole upload: an image's
	// reference, a host's URL. The findings stay in the upload without them, and a finding on an image
	// the descriptor declares goes on the line that declares it.
	doc, unplaced, err := sarif.ForCodeScanning(doc, declared)
	if err != nil {
		return fmt.Errorf("github code scanning: could not read the report to hold its locations to what code scanning accepts: %w", err)
	}
	if unplaced > 0 {
		// Said, because GitHub documents that it displays no result without a location, so these are in
		// the upload and not in the Security tab.
		slog.Info("code scanning shows no alert for a finding with no file in the repository",
			"findings", unplaced, "examples", "a host's, or an image's that no file in this repository declares",
			"where", "results.sarif and report.json list them")
	}

	encoded, err := gzipBase64(doc)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"commit_sha": g.commit,
		"ref":        g.ref,
		"sarif":      encoded,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/repos/%s/code-scanning/sarifs", g.apiURL, g.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// The code-scanning upload endpoint returns 202 Accepted on success.
	if resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("github code-scanning upload failed: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var accepted struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&accepted); err != nil || accepted.ID == "" {
		return fmt.Errorf("github code scanning accepted the upload and returned no upload id, so no accepted finding's alert was dismissed. Re-run the publish")
	}
	return g.syncSuppressions(ctx, accepted.ID, doc)
}

// countedOnly returns a SARIF document holding one result per counted finding: the results whose
// properties.correlation.countedUnder names another scanner's finding are left out.
//
// Code scanning opens an alert for every result and reads nothing in the property bag, so a flaw two
// scanners reported would otherwise be two alerts under two rule ids, and the Security tab would count
// what the gate counts once. Leaving the copy out, rather than marking it with a SARIF suppression,
// keeps the dismissal pass and the Security tab from presenting a second scanner's agreement as
// somebody's decision to accept the flaw. The counted result's correlation.alsoFoundBy still names
// the other scanners and what each said.
//
// Every other value in the document is kept as written, the rules included, so a result's
// fingerprints and its ruleIndex into the run's rules are what the report on disk says they are. A
// document with no copy in it is returned unchanged.
func countedOnly(doc []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return nil, fmt.Errorf("github code scanning: could not read the report to leave out the copies of findings counted once: %w", err)
	}
	var runs []map[string]json.RawMessage
	if err := json.Unmarshal(top["runs"], &runs); err != nil {
		return nil, fmt.Errorf("github code scanning: could not read the report's runs: %w", err)
	}
	dropped := false
	for i, run := range runs {
		var results []json.RawMessage
		if raw, ok := run["results"]; ok {
			if err := json.Unmarshal(raw, &results); err != nil {
				return nil, fmt.Errorf("github code scanning: could not read the report's results: %w", err)
			}
		}
		kept := make([]json.RawMessage, 0, len(results))
		for _, r := range results {
			var probe struct {
				Properties struct {
					Correlation struct {
						CountedUnder string `json:"countedUnder"`
					} `json:"correlation"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(r, &probe); err != nil {
				return nil, fmt.Errorf("github code scanning: could not read a result's correlation: %w", err)
			}
			if probe.Properties.Correlation.CountedUnder != "" {
				continue
			}
			kept = append(kept, r)
		}
		if len(kept) == len(results) {
			continue
		}
		dropped = true
		b, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		runs[i]["results"] = b
	}
	if !dropped {
		return doc, nil
	}
	b, err := json.Marshal(runs)
	if err != nil {
		return nil, err
	}
	top["runs"] = b
	return json.Marshal(top)
}

// gzipBase64 gzip-compresses then base64-encodes data, as required by the code-scanning
// SARIF upload API.
func gzipBase64(data []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
