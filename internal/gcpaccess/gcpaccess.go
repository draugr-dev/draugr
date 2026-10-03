// Package gcpaccess asks Google Cloud which permissions the caller's credentials hold on a project.
//
// One question, asked by two callers: `draugr doctor`, to say whether a declared account can be read
// at all, and the prowler scanner, to know before Prowler runs which services it will be denied. A
// denied read is the one failure Prowler does not report: depending on the check it passes, fails,
// or disappears, so the answer has to come from somewhere other than its output.
//
// The credentials are Application Default Credentials, the ones Prowler and every Google client
// library read: GOOGLE_APPLICATION_CREDENTIALS, `gcloud auth application-default login`, or the
// metadata server of the machine the scan runs on. Asking with the same credentials is what makes
// the answer about the scan rather than about this process.
package gcpaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"golang.org/x/oauth2/google"
)

// endpoint is Cloud Resource Manager, whose testIamPermissions answers for a project.
const endpoint = "https://cloudresourcemanager.googleapis.com"

// scope is the OAuth scope the question needs. testIamPermissions reads nothing, it compares the
// caller's roles with the list it is given.
const scope = "https://www.googleapis.com/auth/cloud-platform"

// batch is how many permissions one testIamPermissions call accepts.
const batch = 100

// ErrNoCredentials is a machine with no Application Default Credentials to ask with.
var ErrNoCredentials = errors.New("no Google Cloud credentials found: set GOOGLE_APPLICATION_CREDENTIALS " +
	"to a key or a workload identity configuration, or run `gcloud auth application-default login`")

// Tester asks which permissions the credentials hold.
type Tester struct {
	client   *http.Client
	endpoint string
}

// New finds the Application Default Credentials and returns a Tester that asks with them.
func New(ctx context.Context) (*Tester, error) {
	creds, err := google.FindDefaultCredentials(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("%w (%w)", ErrNoCredentials, err)
	}
	return &Tester{client: oauth2Client(ctx, creds), endpoint: endpoint}, nil
}

// NewWith returns a Tester asking endpoint through client, for a caller that brings its own.
func NewWith(client *http.Client, endpointURL string) *Tester {
	return &Tester{client: client, endpoint: endpointURL}
}

// Granted returns the permissions in perms the credentials hold on project, in the order asked.
//
// A project the credentials cannot see at all and a project that does not exist are one answer,
// because Google gives one: permission denied. The error says both.
func (t *Tester) Granted(ctx context.Context, project string, perms []string) ([]string, error) {
	held := map[string]bool{}
	for start := 0; start < len(perms); start += batch {
		got, err := t.ask(ctx, project, perms[start:min(start+batch, len(perms))])
		if err != nil {
			return nil, err
		}
		for _, p := range got {
			held[p] = true
		}
	}
	out := make([]string, 0, len(held))
	for _, p := range perms {
		if held[p] && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (t *Tester) ask(ctx context.Context, project string, perms []string) ([]string, error) {
	body, err := json.Marshal(map[string][]string{"permissions": perms})
	if err != nil {
		return nil, err
	}
	u := t.endpoint + "/v1/projects/" + url.PathEscape(project) + ":testIamPermissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ask Google Cloud about project %s: %w", project, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("ask Google Cloud about project %s: %w", project, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusNotFound:
		return nil, fmt.Errorf("project %s does not exist, or the credentials cannot read it", project)
	default:
		return nil, fmt.Errorf("ask Google Cloud about project %s: %s: %s", project, resp.Status, apiMessage(raw))
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ask Google Cloud about project %s: unreadable answer: %w", project, err)
	}
	return out.Permissions, nil
}

// apiMessage is the message in a Google API error body, or the body itself.
func apiMessage(raw []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return string(bytes.TrimSpace(raw))
}
