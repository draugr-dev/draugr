// Package registry asks a container registry whether it will serve an image's manifest to this
// machine, with the credentials a scanner running here would use.
//
// One request per image, for the manifest and never a layer, so the answer costs what the first
// step of a pull costs. It answers "can a scan reach this image", not "what is in it".
package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// manifestTypes are the manifest formats a scanner accepts. Sent as Accept because a registry
// asked for none may answer with a format that no longer exists, or with a 404 for an image that is
// only published as an index.
var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// Client checks images against their registries.
type Client struct {
	// HTTP makes the requests. nil means a client honoring the proxy environment.
	HTTP *http.Client
	// Credential returns the credential for a registry host, or a zero Credential when there is
	// none. nil means the Docker configuration, as Trivy, Grype and Cosign read it.
	Credential func(ctx context.Context, host string) (Credential, error)
}

// StatusError is a registry refusing the manifest.
type StatusError struct {
	Code int
	// Host is the registry, named when no credential was found for it so the reader knows which
	// login is missing.
	Host      string
	Anonymous bool
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("%d %s", e.Code, strings.ToLower(http.StatusText(e.Code)))
	if e.Anonymous && (e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden) {
		msg += ", no credential for " + e.Host
	}
	return msg
}

// Check reports whether the registry serves ref's manifest to this machine. nil means it does.
func (c *Client) Check(ctx context.Context, ref string) error {
	r, err := Parse(ref)
	if err != nil {
		return err
	}
	cred, err := c.credential(ctx, r.Host)
	if err != nil {
		return fmt.Errorf("read the credential for %s: %w", r.Host, err)
	}

	scheme := "https"
	code, challenge, err := c.manifest(ctx, scheme, r, "")
	if err != nil && plainHTTPAllowed(r.Host) {
		// A registry on this machine or a private network is often served without TLS, and the
		// scanners fall back to plain HTTP for exactly these addresses.
		scheme = "http"
		code, challenge, err = c.manifest(ctx, scheme, r, "")
	}
	if err != nil {
		return err
	}
	if code == http.StatusUnauthorized {
		authz, err := c.authorize(ctx, challenge, r, cred)
		if err != nil {
			return err
		}
		if authz != "" {
			if code, _, err = c.manifest(ctx, scheme, r, authz); err != nil {
				return err
			}
		}
	}
	if code/100 == 2 {
		return nil
	}
	return &StatusError{Code: code, Host: r.Host, Anonymous: cred.empty()}
}

func (c *Client) credential(ctx context.Context, host string) (Credential, error) {
	if c.Credential != nil {
		return c.Credential(ctx, host)
	}
	return DockerCredential(ctx, host)
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Transport: http.DefaultTransport}
}

// manifest asks for the manifest with a HEAD request, so no body is transferred, and returns the
// status and any authentication challenge.
func (c *Client) manifest(ctx context.Context, scheme string, r Reference, authz string) (int, string, error) {
	u := scheme + "://" + r.Host + "/v2/" + r.Repository + "/manifests/" + r.Reference
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Accept", manifestTypes)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return 0, "", err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), nil
}

// authorize answers a registry's challenge, returning the Authorization header to retry with, or
// "" when there is nothing to retry with.
func (c *Client) authorize(ctx context.Context, challenge string, r Reference, cred Credential) (string, error) {
	scheme, params := parseChallenge(challenge)
	switch scheme {
	case "basic":
		if cred.Username == "" {
			return "", nil
		}
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)), nil
	case "bearer":
		token, err := c.token(ctx, params, r, cred)
		if err != nil {
			return "", err
		}
		return "Bearer " + token, nil
	default:
		return "", nil
	}
}

// token fetches a pull token from the realm a Bearer challenge names: with the credential when
// there is one, anonymously otherwise, since a public image still needs a token.
func (c *Client) token(ctx context.Context, params map[string]string, r Reference, cred Credential) (string, error) {
	realm := params["realm"]
	if realm == "" {
		return "", errors.New("the registry asked for a token and named nowhere to get one")
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + r.Repository + ":pull"
	}

	var req *http.Request
	var err error
	if cred.IdentityToken != "" {
		// An identity token is a refresh token, exchanged by the OAuth2 form of the same endpoint.
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {cred.IdentityToken},
			"service":       {params["service"]},
			"scope":         {scope},
			"client_id":     {"draugr"},
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, realm, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		q := url.Values{"scope": {scope}}
		if s := params["service"]; s != "" {
			q.Set("service", s)
		}
		sep := "?"
		if strings.Contains(realm, "?") {
			sep = "&"
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, realm+sep+q.Encode(), nil)
		if err == nil && cred.Username != "" {
			req.SetBasicAuth(cred.Username, cred.Password)
		}
	}
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		// The token endpoint's refusal is the registry's refusal: a wrong password answers 401
		// here rather than at the manifest.
		return "", &StatusError{Code: resp.StatusCode, Host: r.Host, Anonymous: cred.empty()}
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("read the token response: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("the token response held no token")
}

// parseChallenge splits a WWW-Authenticate header into its scheme, lowercased, and parameters.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var val string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				val, rest = after[1:], ""
			} else {
				val, rest = after[1:end+1], after[end+2:]
			}
		} else {
			val, rest, _ = strings.Cut(after, ",")
		}
		params[strings.ToLower(strings.TrimSpace(key))] = val
	}
	return strings.ToLower(scheme), params
}

// plainHTTPAllowed reports whether a registry address is one the scanners will also try over
// plain HTTP: this machine, or a private network.
func plainHTTPAllowed(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// Reference is an image reference split the way a registry is addressed.
type Reference struct {
	Host       string
	Repository string
	// Reference is the digest when the image names one, the tag otherwise.
	Reference string
}

// dockerHub is where an image with no registry in its name is pulled from.
const dockerHub = "registry-1.docker.io"

// Parse splits an image reference, applying the defaults every container tool applies: Docker Hub
// when no registry is named, `library/` for a one-segment name there, and `latest` when neither a
// tag nor a digest is.
func Parse(ref string) (Reference, error) {
	name := strings.TrimPrefix(ref, "docker://")
	var out Reference
	if n, digest, ok := strings.Cut(name, "@"); ok {
		name, out.Reference = n, digest
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		if out.Reference == "" {
			out.Reference = name[i+1:]
		}
		name = name[:i]
	}
	if out.Reference == "" {
		out.Reference = "latest"
	}
	if name == "" {
		return Reference{}, fmt.Errorf("%q names no image", ref)
	}

	first, rest, hasSlash := strings.Cut(name, "/")
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		out.Host, out.Repository = first, rest
	} else {
		out.Host, out.Repository = dockerHub, name
	}
	if out.Host == "docker.io" || out.Host == "index.docker.io" {
		out.Host = dockerHub
	}
	if out.Host == dockerHub && !strings.Contains(out.Repository, "/") {
		out.Repository = "library/" + out.Repository
	}
	return out, nil
}
