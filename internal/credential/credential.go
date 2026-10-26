// Package credential decides which credential a descriptor may name and where it may be sent.
//
// A descriptor is a file that changes by pull request, and a pipeline running it holds secrets
// the descriptor's author does not. Every field that names an environment variable holding a
// credential, and every request that carries one, goes through here, so the answer to "can a
// change to the descriptor send this job's secrets somewhere" is given once and given the same way
// for every integration.
//
// Three rules:
//
//   - A descriptor may name only the integration's own variable, or one the pipeline lists in
//     DRAUGR_TOKEN_ENVS. Any other name is refused before anything is read or sent.
//   - A credential travels only over https, or over plain http to a loopback address.
//   - A request carrying a credential does not follow a redirect to another origin.
package credential

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
)

// TokenEnvsVar lists the further variables a descriptor may name as a credential, comma-separated.
//
// Set by the pipeline, which is the party that knows which of its secrets is meant for which
// integration. A descriptor cannot set it.
//
// #nosec G101 -- the name of an environment variable that lists variable names, not a credential.
const TokenEnvsVar = "DRAUGR_TOKEN_ENVS"

// maxRedirects matches net/http's own default, which a client with its own CheckRedirect loses.
const maxRedirects = 10

// RefusedVariableError is a descriptor naming a variable it may not read.
type RefusedVariableError struct {
	// Name is the variable the descriptor named.
	Name string
	// Default is the integration's own variable, empty for one that has none.
	Default string
}

func (e *RefusedVariableError) Error() string {
	set := fmt.Sprintf("Set %s=%s in the pipeline's environment (comma-separated for several)", TokenEnvsVar, e.Name)
	if e.Default == "" {
		return fmt.Sprintf("tokenEnv: $%s is not listed in $%s. %s", e.Name, TokenEnvsVar, set)
	}
	return fmt.Sprintf("tokenEnv: $%s is neither $%s, this publisher's own variable, nor listed in $%s. %s",
		e.Name, e.Default, TokenEnvsVar, set)
}

// Variable is the variable an integration reads its credential from: named, when the descriptor
// names one, and def otherwise.
//
// A name other than def is refused unless DRAUGR_TOKEN_ENVS lists it. def may be empty, for an
// integration with no variable of its own, and then every name has to be listed.
func Variable(named, def string) (string, error) {
	named = strings.TrimSpace(named)
	if named == "" || named == def {
		return def, nil
	}
	if slices.Contains(List(TokenEnvsVar), named) {
		return named, nil
	}
	return named, &RefusedVariableError{Name: named, Default: def}
}

// Token resolves the variable as Variable does and reads its value.
//
// The name is returned with the error too, so a caller can say which variable was refused, and
// with an empty value, so a caller can say which variable to set.
func Token(named, def string) (name, value string, err error) {
	name, err = Variable(named, def)
	if err != nil {
		return name, "", err
	}
	return name, os.Getenv(name), nil
}

// List reads a comma-separated environment variable, dropping blanks and surrounding space.
func List(envVar string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(envVar), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Origin is the scheme, host and port of an http or https address, lowercased, with the scheme's
// default port left out. Two addresses with the same origin reach the same server.
func Origin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	return originOf(u)
}

func originOf(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("%q is not an http or https address", u.Redacted())
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%q names no host", u.Redacted())
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]", nil
	}
	return scheme + "://" + host, nil
}

// Loopback reports whether host is this machine: localhost, 127.0.0.0/8 or ::1.
func Loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ErrInsecure is a credential about to travel without TLS. An *InsecureError matches it.
var ErrInsecure = errors.New("a credential is sent only over https, or http to localhost, 127.0.0.0/8 or ::1")

// InsecureError is an address a credential would reach in clear text.
type InsecureError struct {
	// URL is the address, with any password in it redacted.
	URL string
}

func (e *InsecureError) Error() string {
	return e.URL + " is not https. A credential is sent only over https, or http to localhost, " +
		"127.0.0.0/8 or ::1; use an https address"
}

// Is makes the error match ErrInsecure.
func (e *InsecureError) Is(target error) bool { return target == ErrInsecure }

// RequireTLS refuses an address a credential would cross the network to in clear text.
//
// Plain http to localhost, 127.0.0.0/8 or ::1 is accepted, because the bytes never leave the
// machine and a local server under test is the ordinary reason to use it.
func RequireTLS(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	return requireTLS(u)
}

func requireTLS(u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if Loopback(u.Hostname()) {
			return nil
		}
	}
	return &InsecureError{URL: u.Redacted()}
}

// credentialHeaders are the request headers that carry a credential Draugr set.
var credentialHeaders = []string{"Authorization", "Private-Token"}

// Carries reports whether a request's headers hold a credential.
func Carries(h http.Header) bool {
	for _, name := range credentialHeaders {
		if h.Get(name) != "" {
			return true
		}
	}
	return false
}

// Guard refuses a request that carries a credential over an address RequireTLS refuses. A
// transport calls it before every request it sends, redirects included.
func Guard(req *http.Request) error {
	if req.URL == nil || !Carries(req.Header) {
		return nil
	}
	return requireTLS(req.URL)
}

// CheckRedirect is an http.Client CheckRedirect that refuses to take a credential to another
// origin.
//
// A request that carries none follows redirects as net/http would, because some do so by design:
// an upload to a presigned storage URL carries its authority in the URL and may be redirected
// between a store's own hosts.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	first := via[0]
	if !Carries(first.Header) {
		return nil
	}
	from, ferr := originOf(first.URL)
	to, terr := originOf(req.URL)
	if ferr != nil || terr != nil || from != to {
		return fmt.Errorf("refused a redirect from %s to %s: the request carries a credential, "+
			"which is sent only to the origin it was addressed to", first.URL.Redacted(), req.URL.Redacted())
	}
	return nil
}

// Client returns a copy of c that refuses to take a credential to another origin on a redirect.
func Client(c *http.Client) *http.Client {
	if c == nil {
		c = http.DefaultClient
	}
	out := *c
	out.CheckRedirect = CheckRedirect
	return &out
}
