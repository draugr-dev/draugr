package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// gitlabMRCommentPublisher posts the markdown report as a sticky merge-request comment on GitLab,
// the counterpart to github-pr-comment and azure-pr-comment.
//
// GitLab calls them notes and keeps them in one flat list per merge request, so the sticky
// behaviour is the simplest of the three: find the note carrying Draugr's marker and edit it.
// Without it every pipeline run adds another copy of the report, and a reviewer scrolls past six
// of them to reach the human conversation.
//
// Everything defaults from the runner environment, so the common case is `kind: gitlab-mr-comment`
// and nothing else. Outside a merge request it no-ops, which keeps one Saga usable on branch
// pipelines and on a laptop.
type gitlabMRCommentPublisher struct {
	apiURL  string // API v4 root, no trailing slash
	project string // numeric id or full path; escaped when the URL is built
	token   string
	marker  string
	mr      int
	client  *http.Client
}

func newGitLabMRCommentPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "GITLAB_TOKEN")

	p := gitlabMRCommentPublisher{
		apiURL:  gitlabAPIURL(),
		project: firstNonEmpty(cfg.Repo, os.Getenv("CI_PROJECT_ID")),
		token:   os.Getenv(tokenEnv),
		marker:  firstNonEmpty(cfg.Marker, defaultPRMarker),
		mr:      cfg.PR,
		client:  http.DefaultClient,
	}
	if p.mr == 0 {
		p.mr, _ = strconv.Atoi(os.Getenv("CI_MERGE_REQUEST_IID"))
	}
	// A branch pipeline, or a laptop. Nothing to comment on is not a failure.
	if p.mr == 0 && os.Getenv("GITLAB_CI") != "true" {
		return skipPublisher{kind: "gitlab-mr-comment", reason: "not a GitLab CI environment"}, nil
	}
	if p.mr == 0 {
		return skipPublisher{kind: "gitlab-mr-comment", reason: "no merge request in context"}, nil
	}

	var missing []string
	if p.project == "" {
		missing = append(missing, "repo (or $CI_PROJECT_ID)")
	}
	if p.token == "" {
		// GitLab puts CI_JOB_TOKEN in every job, so it is the credential already to hand — and it
		// is read-only on the notes API. Naming that here turns an unexplained 401 into the one
		// sentence that fixes it.
		missing = append(missing, "$"+tokenEnv+
			" (a project or group access token with `api` scope, set as a masked CI/CD variable; "+
			"CI_JOB_TOKEN is read-only on the notes API and cannot post)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("gitlab-mr-comment publisher missing: %s", strings.Join(missing, ", "))
	}
	return p, nil
}

// gitlabAPIURL resolves the API v4 root.
//
// CI_API_V4_URL is set by every GitLab runner and already carries the path, which is what makes a
// self-managed instance work without configuration. CI_SERVER_URL is the fallback for the same
// reason it exists: an instance served under a port or a path still answers under it.
func gitlabAPIURL() string {
	if api := os.Getenv("CI_API_V4_URL"); api != "" {
		return strings.TrimSuffix(api, "/")
	}
	if server := os.Getenv("CI_SERVER_URL"); server != "" {
		return strings.TrimSuffix(server, "/") + "/api/v4"
	}
	return "https://gitlab.com/api/v4"
}

func (gitlabMRCommentPublisher) Kind() string { return "gitlab-mr-comment" }

func (p gitlabMRCommentPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	var md []byte
	for _, a := range artifacts {
		if a.Format == "markdown" || a.Format == "template" {
			md = a.Bytes
			break
		}
	}
	if md == nil {
		return fmt.Errorf("gitlab-mr-comment publisher requires a 'markdown' report")
	}
	body := p.marker + "\n" + string(md)

	noteID, err := p.findExisting(ctx)
	if err != nil {
		return err
	}
	if noteID != 0 {
		return p.send(ctx, http.MethodPut,
			fmt.Sprintf("%s/notes/%d", p.mrURL(), noteID), body)
	}
	return p.send(ctx, http.MethodPost, p.mrURL()+"/notes", body)
}

// mrURL is the merge request's API root.
//
// The project may be a numeric id or a full path, and a path inside a group contains slashes that
// have to survive as %2F or the request addresses something else entirely. url.PathEscape encodes
// them; url.QueryEscape also would, but it writes a space as "+", which a path does not mean.
func (p gitlabMRCommentPublisher) mrURL() string {
	return fmt.Sprintf("%s/projects/%s/merge_requests/%d",
		p.apiURL, url.PathEscape(p.project), p.mr)
}

// findExisting returns the id of the sticky Draugr note, or 0.
//
// Paginated, because GitLab answers 20 notes at a time. Reading only the first page would find
// nothing as soon as a merge request had a normal amount of discussion on it, and the publisher
// would post a fresh copy of the report every run — the sticky comment failing by multiplying,
// exactly where the conversation is long enough to need it.
//
// System notes ("added 3 commits", "marked as draft") share the endpoint and are skipped: they are
// not ours to edit, and one quoting a marker would otherwise be mistaken for the report.
func (p gitlabMRCommentPublisher) findExisting(ctx context.Context) (int64, error) {
	for page := 1; page != 0; {
		id, next, err := p.notesPage(ctx, page)
		if err != nil || id != 0 {
			return id, err
		}
		page = next
	}
	return 0, nil
}

// notesPage reads one page of notes, returning the marked note's id and the next page number.
// A next page of 0 means this was the last one.
func (p gitlabMRCommentPublisher) notesPage(ctx context.Context, page int) (int64, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/notes?per_page=100&page=%d", p.mrURL(), page), nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", p.token)
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, 0, fmt.Errorf("list merge request notes failed: %s: %s", resp.Status, msg)
	}
	var notes []struct {
		ID     int64  `json:"id"`
		Body   string `json:"body"`
		System bool   `json:"system"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&notes); err != nil {
		return 0, 0, err
	}
	for _, n := range notes {
		if !n.System && strings.Contains(n.Body, p.marker) {
			return n.ID, 0, nil
		}
	}
	next, _ := strconv.Atoi(resp.Header.Get("x-next-page"))
	return 0, next, nil
}

// send POSTs a new note or PUTs the sticky one.
func (p gitlabMRCommentPublisher) send(ctx context.Context, method, endpoint, body string) error {
	buf, err := json.Marshal(map[string]any{"body": body})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// The request reached GitLab and was refused, which is a property of the token rather
			// than of anything in the Saga. Both causes are worth naming: a token that cannot write
			// and a token that cannot see the project produce the same two status codes.
			return fmt.Errorf("post merge request note refused — the token needs `api` scope and "+
				"at least Developer role on this project: %s: %s", resp.Status, msg)
		}
		return fmt.Errorf("post merge request note failed: %s: %s", resp.Status, msg)
	}
	return nil
}
