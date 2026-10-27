// Package login holds a person's short-lived, check-only token for a Draugr server: the OAuth 2.0
// device authorization grant (RFC 8628) that issues it, the revocation (RFC 7009) that ends it, and
// the OS keychain that keeps it between runs.
//
// The token is kept in the keychain and nowhere else. A file holding it would be readable by
// anything running as the person, would be copied by backups and dotfile repositories, and would
// outlive the sign-in that produced it, which are the properties a token in a shell profile
// already has and this exists to replace.
package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/draugr-dev/draugr/internal/credential"
)

// Login is a token a server issued to a person, and whose it is.
type Login struct {
	// Server is the address `draugr login` was given, without a trailing slash.
	Server string `json:"server"`
	// Token is the bearer token. Never logged and never printed.
	Token string `json:"token"`
	// Email and Organization say whose login it is, as the server answered.
	Email        string `json:"email"`
	Organization string `json:"organization"`
	// Issued is when the token arrived, and Expires when the server stops accepting it.
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
}

// Expired reports whether the token has expired at now.
func (l Login) Expired(now time.Time) bool { return !l.Expires.IsZero() && !now.Before(l.Expires) }

// String describes the login without its token, so a %v in an error or a test cannot print it.
func (l Login) String() string {
	return fmt.Sprintf("login{server=%s email=%s organization=%s expires=%s}",
		l.Server, l.Email, l.Organization, l.Expires.UTC().Format(time.RFC3339))
}

// GoString is String, for %#v.
func (l Login) GoString() string { return l.String() }

// Store keeps logins, one for each server origin.
type Store interface {
	// Get returns the login for an origin, or an error matching ErrNotLoggedIn.
	Get(origin string) (Login, error)
	// Set keeps a login for an origin, replacing any it held.
	Set(origin string, l Login) error
	// Delete removes the login for an origin, or returns an error matching ErrNotLoggedIn.
	Delete(origin string) error
}

// ErrNotLoggedIn is a store holding no login for the origin asked about.
var ErrNotLoggedIn = errors.New("not logged in")

// ErrNoKeychain is a machine with no OS keychain Draugr can reach. A *KeychainError matches it.
var ErrNoKeychain = errors.New("the OS keychain is not available")

// KeychainError is a keychain that could not be read or written.
type KeychainError struct {
	Err error
}

func (e *KeychainError) Error() string {
	return "the OS keychain is not available (macOS Keychain, Windows Credential Manager, or a Secret " +
		"Service such as GNOME Keyring or KWallet on Linux), and a login is stored nowhere else: " + e.Err.Error()
}

// Unwrap returns the keychain's own error.
func (e *KeychainError) Unwrap() error { return e.Err }

// Is makes the error match ErrNoKeychain.
func (e *KeychainError) Is(target error) bool { return target == ErrNoKeychain }

// Origin is the key a login is stored under: the server's scheme, host and port.
func Origin(server string) (string, error) { return credential.Origin(server) }

// keychainService is the service name every login is stored under, with the origin as the account.
const keychainService = "draugr"

// Keychain is the Store the OS keychain backs.
type Keychain struct{}

// Get returns the login the keychain holds for origin.
func (Keychain) Get(origin string) (Login, error) {
	secret, err := keyring.Get(keychainService, origin)
	if err != nil {
		return Login{}, keychainErr(err)
	}
	var l Login
	if err := json.Unmarshal([]byte(secret), &l); err != nil {
		// The error is not wrapped: json's message can quote the bytes it failed on.
		return Login{}, fmt.Errorf("the keychain entry for %s is not a Draugr login; run `draugr logout %s`", origin, origin)
	}
	return l, nil
}

// Set keeps l in the keychain under origin.
func (Keychain) Set(origin string, l Login) error {
	secret, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return keychainErr(keyring.Set(keychainService, origin, string(secret)))
}

// Delete removes the keychain's login for origin.
func (Keychain) Delete(origin string) error {
	return keychainErr(keyring.Delete(keychainService, origin))
}

// keychainErr maps the keyring's errors onto this package's.
func keychainErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotLoggedIn
	}
	return &KeychainError{Err: err}
}
