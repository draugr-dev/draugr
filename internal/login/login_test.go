package login

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// TestMain puts the keyring behind its in-memory mock before any test runs, so nothing here reads
// or writes the keychain of the machine running the tests.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

var ana = Login{
	Server: "https://draugr.example", Token: "drgl_secret", Email: "ana@acme.com", Organization: "acme",
	Expires: time.Date(2026, 10, 28, 6, 12, 0, 0, time.UTC),
}

func TestKeychainKeepsALoginPerOrigin(t *testing.T) {
	k := Keychain{}
	if _, err := k.Get("https://draugr.example"); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("an empty keychain: %v", err)
	}
	if err := k.Set("https://draugr.example", ana); err != nil {
		t.Fatal(err)
	}
	other := ana
	other.Server, other.Email = "https://other.example", "bo@acme.com"
	if err := k.Set("https://other.example", other); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get("https://draugr.example")
	if err != nil || got != ana {
		t.Errorf("got %s, %v", got, err)
	}
	if err := k.Delete("https://draugr.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Get("https://draugr.example"); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("after delete: %v", err)
	}
	if err := k.Delete("https://draugr.example"); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("deleting twice: %v", err)
	}
	if got, err := k.Get("https://other.example"); err != nil || got.Email != "bo@acme.com" {
		t.Errorf("the other origin's login: %s, %v", got, err)
	}
}

func TestKeychainEntryThatIsNotALogin(t *testing.T) {
	if err := keyring.Set(keychainService, "https://odd.example", "drgl_secret{"); err != nil {
		t.Fatal(err)
	}
	_, err := Keychain{}.Get("https://odd.example")
	if err == nil || strings.Contains(err.Error(), "drgl_secret") || !strings.Contains(err.Error(), "draugr logout") {
		t.Errorf("err = %v", err)
	}
}

// A machine with no keychain is an error that says so. Nothing falls back to a file.
func TestNoKeychainIsAnError(t *testing.T) {
	keyring.MockInitWithError(errors.New("org.freedesktop.secrets was not provided by any .service files"))
	t.Cleanup(keyring.MockInit)
	for name, err := range map[string]error{
		"get":    func() error { _, err := Keychain{}.Get("https://draugr.example"); return err }(),
		"set":    Keychain{}.Set("https://draugr.example", ana),
		"delete": Keychain{}.Delete("https://draugr.example"),
	} {
		var ke *KeychainError
		if !errors.Is(err, ErrNoKeychain) || !errors.As(err, &ke) || errors.Unwrap(ke) == nil ||
			!strings.Contains(err.Error(), "Secret Service") || !strings.Contains(err.Error(), "org.freedesktop.secrets") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestALoginNeverPrintsItsToken(t *testing.T) {
	for _, s := range []string{fmt.Sprint(ana), fmt.Sprintf("%+v", ana), fmt.Sprintf("%#v", ana), ana.String()} {
		if strings.Contains(s, "drgl_secret") || !strings.Contains(s, "ana@acme.com") {
			t.Errorf("printed %q", s)
		}
	}
}

func TestExpired(t *testing.T) {
	if ana.Expired(ana.Expires.Add(-time.Second)) || !ana.Expired(ana.Expires) {
		t.Error("expired at its expiry, and not before")
	}
	if (Login{}).Expired(time.Now()) {
		t.Error("a login with no expiry is the server's to judge")
	}
}

func TestOrigin(t *testing.T) {
	if o, err := Origin("HTTPS://Draugr.Example:443/api/"); err != nil || o != "https://draugr.example" {
		t.Errorf("origin = %q, %v", o, err)
	}
}
