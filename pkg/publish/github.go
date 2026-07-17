package publish

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// githubPublisher uploads the SARIF report to GitHub code scanning (the Security → Code
// scanning alerts tab). Repo/commit/ref default to the standard GitHub Actions environment
// (GITHUB_REPOSITORY / GITHUB_SHA / GITHUB_REF); the token is read from an environment variable
// (never the Saga) so no secret is stored in the descriptor or logged.
//
// Code scanning is free for public repos; private repos require GitHub Advanced Security.
type githubPublisher struct {
	repo, commit, ref, token, apiURL string
	client                           *http.Client
}

func newGithubPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "GITHUB_TOKEN")
	g := githubPublisher{
		repo:   firstNonEmpty(cfg.Repo, os.Getenv("GITHUB_REPOSITORY")),
		commit: firstNonEmpty(cfg.Commit, os.Getenv("GITHUB_SHA")),
		ref:    firstNonEmpty(cfg.Ref, os.Getenv("GITHUB_REF")),
		token:  os.Getenv(tokenEnv),
		apiURL: firstNonEmpty(os.Getenv("GITHUB_API_URL"), "https://api.github.com"),
		client: http.DefaultClient,
	}
	// The github publisher targets a CI code-scanning upload. When a Saga carries it but the
	// scan runs outside GitHub Actions with no GitHub context resolvable (e.g. a developer
	// running the same Saga locally), skip instead of failing — there is no commit/ref to
	// publish against. Any resolvable field (from config or env) means publishing is intended,
	// so validate strictly.
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

func (g githubPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	var sarif []byte
	for _, a := range artifacts {
		if a.Format == "sarif" {
			sarif = a.Bytes
			break
		}
	}
	if sarif == nil {
		return fmt.Errorf("github publisher requires a 'sarif' report in config.reports")
	}

	encoded, err := gzipBase64(sarif)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) //nolint:gosec // API URL from GitHub-provided env
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
	return nil
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
