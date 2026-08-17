// Package mendapi is the client for Mend's v1.3 API: the half of a Mend scan that returns
// findings.
//
// The Unified Agent uploads an inventory and exits; it reports nothing about what is wrong with
// what it sent. Findings come from here afterwards, which is why a Mend scan is two phases rather
// than one command.
//
// Kept apart from the scanner because the two have different failure modes and different things
// to be careful about. This half talks to a third party over the network, and everything it
// carries — the user key, the tenant, the product a token names — is either a credential or names
// the operator's account.
package mendapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one Mend tenant.
type Client struct {
	// BaseURL is the tenant, e.g. https://saas.mend.io. The API path is appended.
	BaseURL string
	// UserKey authenticates every request. Never logged, never rendered into a finding.
	UserKey string
	// HTTP is injectable so tests need no network.
	HTTP *http.Client
}

// New returns a Client for a tenant.
func New(baseURL, userKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		UserKey: userKey,
		// A generous per-request timeout: this API answers quickly, and the long waits in a Mend
		// scan are between requests rather than inside one.
		HTTP: &http.Client{Timeout: 60 * time.Second},
	}
}

// Project is one project inside a product.
type Project struct {
	ID    int64  `json:"projectId"`
	Name  string `json:"projectName"`
	Token string `json:"projectToken"`
}

// Vitals is what the API knows about a project's last update.
//
// The reason this type exists: it is how a caller tells "the scan has not landed yet" from "the
// scan landed and found nothing". Without it an eager poll reports a clean bill of health for a
// project Mend has not finished reading.
type Vitals struct {
	Name string `json:"name"`
	// RequestToken is the update-request the agent sent. Correlating it is a direct answer to
	// "has my upload been processed", rather than an inference from a clock.
	RequestToken    string `json:"requestToken"`
	LastUpdatedDate string `json:"lastUpdatedDate"`
	CreationDate    string `json:"creationDate"`
}

// Alert is one thing Mend has to say about a library in a project.
type Alert struct {
	Type             string        `json:"type"`
	Level            string        `json:"level"`
	Description      string        `json:"description"`
	DirectDependency bool          `json:"directDependency"`
	Date             string        `json:"date"`
	Library          Library       `json:"library"`
	Vulnerability    Vulnerability `json:"vulnerability"`
}

// Library identifies the component an alert is about.
//
// Filename is the artifact Mend matched — a wheel or a jar — not a path in the repository. There
// is no repository path in an alert, which is why a Mend finding is coarser than one from a
// scanner that read the manifest itself.
type Library struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Filename   string `json:"filename"`
	Type       string `json:"type"`
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
}

// Vulnerability is the CVE an alert reports.
type Vulnerability struct {
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
	URL         string  `json:"url"`
	PublishDate string  `json:"publishDate"`
	TopFix      *Fix    `json:"topFix,omitempty"`
}

// Fix is Mend's suggested remediation.
type Fix struct {
	FixResolution string `json:"fixResolution"`
	Message       string `json:"message"`
	URL           string `json:"url"`
}

// AlertTypeVulnerability is the only alert type that is a security finding.
//
// The others are a different kind of statement: NEW_MAJOR_VERSION is dependency freshness, and
// REJECTED_BY_POLICY_RESOURCE comes from policy configured in the operator's Mend console. Mapping
// the last one would let a second policy engine reach into Draugr's verdict, when the point of the
// gate is that it is decided by a descriptor somebody can read.
const AlertTypeVulnerability = "SECURITY_VULNERABILITY"

// Projects lists the projects in a product.
func (c *Client) Projects(ctx context.Context, productToken string) ([]Project, error) {
	var out struct {
		Projects []Project `json:"projects"`
	}
	err := c.call(ctx, map[string]any{
		"requestType":  "getAllProjects",
		"productToken": productToken,
	}, &out)
	return out.Projects, err
}

// ProjectByName finds one project in a product by name.
func (c *Client) ProjectByName(ctx context.Context, productToken, name string) (Project, error) {
	projects, err := c.Projects(ctx, productToken)
	if err != nil {
		return Project{}, err
	}
	for _, p := range projects {
		if p.Name == name {
			return p, nil
		}
	}
	return Project{}, fmt.Errorf("no project named %q in this product — the upload may not have "+
		"been processed yet, or it went to a different product", name)
}

// Vitals reports a project's last update.
func (c *Client) Vitals(ctx context.Context, projectToken string) (Vitals, error) {
	var out struct {
		Vitals []Vitals `json:"projectVitals"`
	}
	if err := c.call(ctx, map[string]any{
		"requestType":  "getProjectVitals",
		"projectToken": projectToken,
	}, &out); err != nil {
		return Vitals{}, err
	}
	if len(out.Vitals) == 0 {
		return Vitals{}, fmt.Errorf("project has no vitals")
	}
	return out.Vitals[0], nil
}

// Alerts returns every alert on a project.
func (c *Client) Alerts(ctx context.Context, projectToken string) ([]Alert, error) {
	var out struct {
		Alerts []Alert `json:"alerts"`
	}
	err := c.call(ctx, map[string]any{
		"requestType":  "getProjectAlerts",
		"projectToken": projectToken,
	}, &out)
	return out.Alerts, err
}

// InventoryLibrary is one component in a project's inventory, with the licenses Mend attributes
// to it.
type InventoryLibrary struct {
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	Filename   string             `json:"filename"`
	Type       string             `json:"type"`
	GroupID    string             `json:"groupId"`
	ArtifactID string             `json:"artifactId"`
	Licenses   []InventoryLicense `json:"licenses"`
}

// InventoryLicense is one license Mend attributes to a library.
//
// Name is Mend's own vocabulary — "BSD 3", "Apache 2.0" — and SPDXName is frequently empty, which
// is the fact the licenses scanner is built around: a policy written in SPDX cannot match a name
// that is not one.
type InventoryLicense struct {
	Name     string `json:"name"`
	SPDXName string `json:"spdxName"`
	URL      string `json:"url"`
}

// Inventory returns a project's libraries and the licenses attributed to them.
func (c *Client) Inventory(ctx context.Context, projectToken string) ([]InventoryLibrary, error) {
	var out struct {
		Libraries []InventoryLibrary `json:"libraries"`
	}
	err := c.call(ctx, map[string]any{
		"requestType":  "getProjectInventory",
		"projectToken": projectToken,
	}, &out)
	return out.Libraries, err
}

// LibraryCount reports how many libraries a project's inventory holds.
//
// The way a caller tells a processed upload from an unprocessed one when the agent gave no
// request token: the agent says how many dependencies it resolved, so waiting for the inventory
// to hold that many is self-validating — it compares what arrived against what was sent.
func (c *Client) LibraryCount(ctx context.Context, projectToken string) (int, error) {
	var out struct {
		Libraries []struct{} `json:"libraries"`
	}
	err := c.call(ctx, map[string]any{
		"requestType":  "getProjectInventory",
		"projectToken": projectToken,
	}, &out)
	return len(out.Libraries), err
}

// call posts one API request and decodes the reply.
//
// Mend answers errors with HTTP 200 and an errorMessage in the body, so the status code alone
// never establishes success — a caller trusting it would read a permission failure as an empty
// result, which for this integration means reporting a clean scan.
func (c *Client) call(ctx context.Context, body map[string]any, out any) error {
	body["userKey"] = c.UserKey

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("mend api: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1.3", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("mend api: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// Redacted by construction: the request body is never included in the error, because it
		// carries the user key.
		return fmt.Errorf("mend api %s: %w", body["requestType"], err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mend api %s: HTTP %d", body["requestType"], resp.StatusCode)
	}

	var probe struct {
		ErrorCode    int    `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}
	raw, err := readAll(resp)
	if err != nil {
		return fmt.Errorf("mend api %s: %w", body["requestType"], err)
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.ErrorMessage != "" {
		return fmt.Errorf("mend api %s: %s", body["requestType"], probe.ErrorMessage)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("mend api %s: unreadable reply: %w", body["requestType"], err)
	}
	return nil
}

// readAll reads a response body with a ceiling, so a malformed or hostile reply cannot exhaust
// memory. Mend's inventories are large but nowhere near this.
func readAll(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
}

// maxReplyBytes bounds one API reply. A project with tens of thousands of libraries is well
// inside it.
const maxReplyBytes = 128 << 20
