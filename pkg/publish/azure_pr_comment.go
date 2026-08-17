package publish

import (
	"bytes"
	"context"
	"encoding/base64"
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

// azurePRCommentPublisher posts the markdown report as a sticky pull-request comment on Azure
// DevOps, the counterpart to github-pr-comment.
//
// Azure models a PR comment as a *thread* containing comments, so the sticky behavior is: find
// the thread whose first comment carries Draugr's marker, and edit that comment in place.
// Without it every push adds another thread, and a reviewer scrolls past six copies of the same
// report to reach the human conversation.
//
// Everything defaults from the pipeline environment, so the common case is `kind:
// azure-pr-comment` and nothing else. Outside a pull request it no-ops, which keeps one Saga
// usable on push builds and on a laptop.
type azurePRCommentPublisher struct {
	baseURL string // collection URI + project, no trailing slash
	repo    string
	token   string
	marker  string
	pr      int
	client  *http.Client
}

func newAzurePRCommentPublisher(cfg saga.PublisherConfig) (Publisher, error) {
	// SYSTEM_ACCESSTOKEN is the build's own identity. Unlike most pipeline variables it is not
	// exposed to a script step unless the step maps it explicitly, which is the single most
	// common reason this publisher cannot authenticate — so the error below names it.
	tokenEnv := firstNonEmpty(cfg.TokenEnv, "SYSTEM_ACCESSTOKEN")
	collection := firstNonEmpty(cfg.Org, os.Getenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"))
	project := firstNonEmpty(cfg.Project, os.Getenv("SYSTEM_TEAMPROJECT"))

	p := azurePRCommentPublisher{
		repo:   firstNonEmpty(cfg.Repo, os.Getenv("BUILD_REPOSITORY_NAME")),
		token:  os.Getenv(tokenEnv),
		marker: firstNonEmpty(cfg.Marker, defaultPRMarker),
		pr:     cfg.PR,
		client: newRetryingClient(http.DefaultClient),
	}
	if p.pr == 0 {
		p.pr, _ = strconv.Atoi(os.Getenv("SYSTEM_PULLREQUEST_PULLREQUESTID"))
	}
	// A push build, or a laptop. Nothing to comment on is not a failure.
	if p.pr == 0 && os.Getenv("TF_BUILD") != "True" {
		return skipPublisher{kind: "azure-pr-comment", reason: "not an Azure Pipelines environment"}, nil
	}
	if p.pr == 0 {
		return skipPublisher{kind: "azure-pr-comment", reason: "no pull request in context"}, nil
	}

	var missing []string
	if collection == "" {
		missing = append(missing, "org (or $SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)")
	}
	if project == "" {
		missing = append(missing, "project (or $SYSTEM_TEAMPROJECT)")
	}
	if p.repo == "" {
		missing = append(missing, "repo (or $BUILD_REPOSITORY_NAME)")
	}
	if p.token == "" {
		missing = append(missing, "$"+tokenEnv+
			" (map it into the step: `env: {SYSTEM_ACCESSTOKEN: $(System.AccessToken)}`)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("azure-pr-comment publisher missing: %s", strings.Join(missing, ", "))
	}
	p.baseURL = strings.TrimSuffix(collection, "/") + "/" + url.PathEscape(project)
	return p, nil
}

func (azurePRCommentPublisher) Kind() string { return "azure-pr-comment" }

func (p azurePRCommentPublisher) Publish(ctx context.Context, artifacts []report.Artifact) error {
	var md []byte
	for _, a := range artifacts {
		if a.Format == "markdown" || a.Format == "template" {
			md = a.Bytes
			break
		}
	}
	if md == nil {
		return fmt.Errorf("azure-pr-comment publisher requires a 'markdown' report")
	}
	body := p.marker + "\n" + string(md)

	threadID, commentID, err := p.findExisting(ctx)
	if err != nil {
		return err
	}
	if threadID != 0 {
		return p.send(ctx, http.MethodPatch,
			fmt.Sprintf("%s/threads/%d/comments/%d", p.prURL(), threadID, commentID),
			map[string]any{"content": body})
	}
	return p.send(ctx, http.MethodPost, p.prURL()+"/threads", map[string]any{
		"comments": []map[string]any{{"parentCommentId": 0, "content": body, "commentType": "text"}},
		"status":   "active",
	})
}

func (p azurePRCommentPublisher) prURL() string {
	return fmt.Sprintf("%s/_apis/git/repositories/%s/pullRequests/%d",
		p.baseURL, url.PathEscape(p.repo), p.pr)
}

// findExisting returns the thread and comment ids of the sticky Draugr comment, or 0, 0.
//
// The marker is matched against the thread's *first* comment only. A reply quoting the report
// would otherwise be mistaken for the report, and Draugr would edit a reviewer's words.
//
// Not paginated, unlike the GitHub and GitLab equivalents. Azure documents this endpoint as
// "retrieve all threads in a pull request" and offers no $top, $skip or continuation token — its
// only query parameters place threads against a diff iteration. Adding paging here would be
// guarding against a limit the API does not have.
func (p azurePRCommentPublisher) findExisting(ctx context.Context) (int64, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		p.prURL()+"/threads?api-version=7.1", nil)
	if err != nil {
		return 0, 0, err
	}
	p.authorize(req)
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, 0, fmt.Errorf("list PR threads failed: %s: %s", resp.Status, msg)
	}
	var out struct {
		Value []struct {
			ID       int64 `json:"id"`
			Comments []struct {
				ID      int64  `json:"id"`
				Content string `json:"content"`
			} `json:"comments"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, 0, err
	}
	for _, t := range out.Value {
		if len(t.Comments) > 0 && strings.Contains(t.Comments[0].Content, p.marker) {
			return t.ID, t.Comments[0].ID, nil
		}
	}
	return 0, 0, nil
}

// send POSTs a new thread or PATCHes the sticky comment.
func (p azurePRCommentPublisher) send(ctx context.Context, method, endpoint string, payload map[string]any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+"?api-version=7.1", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	p.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// Azure answers 200 to both the create and the update.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if resp.StatusCode == http.StatusForbidden {
			// The token is valid but the identity cannot write. Worth naming, because the fix is
			// a permission on the repository rather than anything in the Saga.
			return fmt.Errorf("post PR comment forbidden — grant the build service "+
				"'Contribute to pull requests' on this repository: %s: %s", resp.Status, msg)
		}
		return fmt.Errorf("post PR comment failed: %s: %s", resp.Status, msg)
	}
	return nil
}

// authorize sets the right scheme for the credential it was given.
//
// Azure takes two kinds and they are not interchangeable: the pipeline's own SYSTEM_ACCESSTOKEN
// is a JWT and goes in as a bearer, while a personal access token goes in as basic auth with an
// empty username. Sniffing the JWT header keeps this right even when someone puts the pipeline
// token in a differently named variable.
func (p azurePRCommentPublisher) authorize(req *http.Request) {
	if strings.HasPrefix(p.token, "eyJ") {
		req.Header.Set("Authorization", "Bearer "+p.token)
		return
	}
	req.Header.Set("Authorization", "Basic "+
		base64.StdEncoding.EncodeToString([]byte(":"+p.token)))
}
