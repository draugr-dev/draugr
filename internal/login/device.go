package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/credential"
)

// The client a server knows `draugr login` as, and the one scope it asks for.
const (
	ClientID = "draugr-cli"
	Scope    = "check"
)

// deviceGrant is the grant_type of a device authorization poll (RFC 8628 §3.4).
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// slowDownStep is what a slow_down answer adds to the interval (RFC 8628 §3.5).
const slowDownStep = 5 * time.Second

// defaultInterval is the poll interval where the server names none (RFC 8628 §3.2).
const defaultInterval = 5 * time.Second

// maxBody bounds what is read from any answer.
const maxBody = 1 << 20

// Errors a poll ends with, besides an *OAuthError carrying the server's own description.
var (
	// ErrExpired is a code that expired before anybody approved it.
	ErrExpired = errors.New("the code expired before it was approved")
	// ErrDenied is a request somebody denied.
	ErrDenied = errors.New("the request was denied")
	// ErrInvalidClient is a server that does not know the client `draugr login` presents.
	ErrInvalidClient = errors.New("the server does not accept " + ClientID + " as a client (invalid_client)")
)

// OAuthError is an error answer in OAuth's shape.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	// Status is the HTTP status line, for an answer that was not in OAuth's shape.
	Status string `json:"-"`
}

func (e *OAuthError) Error() string {
	switch {
	case e.Code == "":
		return e.Status
	case e.Description == "":
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Device describes the machine asking for a login. The server displays it on the approval page and
// decides nothing by it.
type Device struct {
	// Name is the raw hostname.
	Name string
	// Version is the Draugr version.
	Version string
}

// Authorization is the server's answer to a device authorization request (RFC 8628 §3.2).
type Authorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Lifetime is how long the code stays valid.
func (a Authorization) Lifetime() time.Duration { return time.Duration(a.ExpiresIn) * time.Second }

// Client speaks the device authorization grant and revocation to one server.
type Client struct {
	// Server is the server's address, without a trailing slash.
	Server string
	// Device describes this machine.
	Device Device
	// HTTP sends the requests. Nil is a client with a timeout that follows no redirect.
	HTTP *http.Client
	// Sleep waits between polls, returning early with the context's error. Nil waits on a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock a login's expiry is computed from. Nil is time.Now.
	Now func() time.Time
}

// NewClient is a client for server, which must be https, or http to this machine: the token comes
// back over this connection.
func NewClient(server string, device Device) (Client, error) {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if _, err := credential.Origin(server); err != nil {
		return Client{}, err
	}
	if err := credential.RequireTLS(server); err != nil {
		return Client{}, err
	}
	return Client{Server: server, Device: device}, nil
}

// Authorize asks the server for a device code and the code a person enters to approve it.
func (c Client) Authorize(ctx context.Context) (Authorization, error) {
	form := url.Values{
		"client_id":      {ClientID},
		"scope":          {Scope},
		"device_name":    {c.Device.Name},
		"client_version": {c.Device.Version},
		"client_os":      {runtime.GOOS + "/" + runtime.GOARCH},
	}
	var a Authorization
	if err := c.post(ctx, "/v1/device/code", form, &a); err != nil {
		return Authorization{}, fmt.Errorf("device authorization: %w", err)
	}
	if a.DeviceCode == "" || a.UserCode == "" || a.VerificationURI == "" {
		return Authorization{}, fmt.Errorf("device authorization: the answer has no device code, user code or verification address")
	}
	return a, nil
}

// tokenAnswer is a successful poll: RFC 8628's token response, plus whose login it is.
type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
}

// Wait polls until the request is approved, denied or expires, every interval the server set and
// slower each time it answers slow_down. A pending request keeps polling: approval may first wait
// on the person signing in to the console.
func (c Client) Wait(ctx context.Context, a Authorization) (Login, error) {
	interval := time.Duration(a.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	// The server's expiry is the authority; this stops a server that never says expired_token from
	// holding the terminal forever.
	deadline := c.now().Add(a.Lifetime())
	form := url.Values{
		"grant_type":  {deviceGrant},
		"device_code": {a.DeviceCode},
		"client_id":   {ClientID},
	}
	for {
		if a.ExpiresIn > 0 && !c.now().Before(deadline) {
			return Login{}, ErrExpired
		}
		if err := c.sleep(ctx, interval); err != nil {
			return Login{}, err
		}
		var got tokenAnswer
		err := c.post(ctx, "/v1/device/token", form, &got)
		var oe *OAuthError
		if errors.As(err, &oe) {
			switch oe.Code {
			case "authorization_pending":
				continue
			case "slow_down":
				interval += slowDownStep
				continue
			case "expired_token":
				return Login{}, ErrExpired
			case "access_denied":
				return Login{}, ErrDenied
			}
		}
		if err != nil {
			return Login{}, fmt.Errorf("device token: %w", err)
		}
		if got.AccessToken == "" {
			return Login{}, fmt.Errorf("device token: the answer has no access token")
		}
		if got.TokenType != "" && !strings.EqualFold(got.TokenType, "bearer") {
			return Login{}, fmt.Errorf("device token: token type %q, where bearer was expected", got.TokenType)
		}
		issued := c.now().UTC()
		l := Login{Server: c.Server, Token: got.AccessToken, Email: got.Email, Organization: got.Organization, Issued: issued}
		if got.ExpiresIn > 0 {
			l.Expires = issued.Add(time.Duration(got.ExpiresIn) * time.Second)
		}
		return l, nil
	}
}

// Revoke tells the server to stop accepting token (RFC 7009). The server answers success for a
// token that is unknown, revoked or expired, so this succeeds whether or not it was still live.
func (c Client) Revoke(ctx context.Context, token string) error {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	if err := c.post(ctx, "/v1/device/revoke", form, nil); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	return nil
}

// post sends a form and decodes a 200 answer into out, which may be nil.
//
// An error answer comes back as an *OAuthError, or ErrInvalidClient for a 401. No redirect is
// followed: each body carries a device code or a token, and a redirect would carry it to an address
// nobody chose.
func (c Client) post(ctx context.Context, path string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent(c.Device.Version))
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	body := io.LimitReader(resp.Body, maxBody)
	switch resp.StatusCode {
	case http.StatusOK:
		if out == nil {
			return nil
		}
		if err := json.NewDecoder(body).Decode(out); err != nil {
			return fmt.Errorf("unreadable answer: %w", err)
		}
		return nil
	case http.StatusUnauthorized:
		return ErrInvalidClient
	}
	oe := &OAuthError{Status: resp.Status}
	_ = json.NewDecoder(body).Decode(oe)
	return oe
}

// UserAgent is the User-Agent every request sends.
func UserAgent(version string) string {
	return "draugr/" + version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
}

func (c Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
