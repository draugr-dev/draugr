package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// defaultPRMarker is embedded (as an HTML comment) in the sticky PR comment so subsequent runs
// find and update the same comment instead of posting a new one each push.
const defaultPRMarker = "<!-- draugr:pr-comment -->"

// githubPRCommentPublisher posts the markdown report as a sticky pull-request comment on GitHub.
// It's the "where" for a human-facing delta on a PR (pairs with `draugr diff --format markdown`).
// Repo/token come from the environment (never the Saga); the PR number defaults to the one in
// GITHUB_REF. Outside a pull-request context it no-ops, so the same config is safe on push/local.
type githubPRCommentPublisher struct {
	repo, token, apiURL, marker string
	pr                          int
	client                      *http.Client
}

var prRefPattern = regexp.MustCompile(`^refs/pull/(\d+)/`)

func newGithubPRCommentPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "GITHUB_TOKEN")
	p := githubPRCommentPublisher{
		repo:   firstNonEmpty(cfg.Repo, os.Getenv("GITHUB_REPOSITORY")),
		token:  os.Getenv(tokenEnv),
		apiURL: firstNonEmpty(os.Getenv("GITHUB_API_URL"), "https://api.github.com"),
		marker: firstNonEmpty(cfg.Marker, defaultPRMarker),
		pr:     cfg.PR,
		client: http.DefaultClient,
	}
	if p.pr == 0 {
		if m := prRefPattern.FindStringSubmatch(os.Getenv("GITHUB_REF")); m != nil {
			p.pr, _ = strconv.Atoi(m[1])
		}
	}
	// No PR to comment on (push build, local run, or non-PR event) → no-op, so a Saga that
	// carries this publisher still runs cleanly outside a pull request.
	if p.pr == 0 && os.Getenv("GITHUB_ACTIONS") != "true" {
		return skipPublisher{kind: "github-pr-comment", reason: "not a GitHub Actions environment"}, nil
	}
	if p.pr == 0 {
		return skipPublisher{kind: "github-pr-comment", reason: "no pull request in context"}, nil
	}
	var missing []string
	if p.repo == "" {
		missing = append(missing, "repo (or $GITHUB_REPOSITORY)")
	}
	if p.token == "" {
		missing = append(missing, "$"+tokenEnv)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("github-pr-comment publisher missing: %s", strings.Join(missing, ", "))
	}
	return p, nil
}

func (githubPRCommentPublisher) Kind() string { return "github-pr-comment" }

func (p githubPRCommentPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	var md []byte
	for _, a := range artifacts {
		if a.Format == "markdown" || a.Format == "template" {
			md = a.Bytes
			break
		}
	}
	if md == nil {
		return fmt.Errorf("github-pr-comment publisher requires a 'markdown' report")
	}
	body := p.marker + "\n" + string(md)

	id, err := p.findExisting(ctx)
	if err != nil {
		return err
	}
	if id != 0 {
		return p.send(ctx, http.MethodPatch,
			fmt.Sprintf("%s/repos/%s/issues/comments/%d", p.apiURL, p.repo, id), body)
	}
	return p.send(ctx, http.MethodPost,
		fmt.Sprintf("%s/repos/%s/issues/%d/comments", p.apiURL, p.repo, p.pr), body)
}

// findExisting returns the id of the sticky Draugr comment on the PR, or 0 if none.
func (p githubPRCommentPublisher) findExisting(ctx context.Context) (int64, error) {
	url := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=100", p.apiURL, p.repo, p.pr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // API URL from env
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, fmt.Errorf("list PR comments failed: %s: %s", resp.Status, msg)
	}
	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		return 0, err
	}
	for _, c := range comments {
		if bytes.Contains([]byte(c.Body), []byte(p.marker)) {
			return c.ID, nil
		}
	}
	return 0, nil
}

// send POSTs or PATCHes a comment body.
func (p githubPRCommentPublisher) send(ctx context.Context, method, url, body string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payload)) //nolint:gosec // API URL from env
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// POST → 201 Created, PATCH → 200 OK.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("post PR comment failed: %s: %s", resp.Status, msg)
	}
	return nil
}
