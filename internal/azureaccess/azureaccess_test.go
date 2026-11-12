package azureaccess

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Every test here runs against a local server with a fixed token, or fake credentials. New and
// azidentityMakers are never called: they build a real credential, and asking one for a token would
// use whatever sign-in the machine holds.

const testSubscription = "00000000-0000-0000-0000-000000000000"

func staticToken(context.Context) (string, error) { return "aaaa", nil }

// newTestClient serves handler on a local server and returns a Client asking it.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewWith(srv.Client(), srv.URL, staticToken)
}

func TestAuthFlagFollowsTheEnvironment(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"nothing set", nil, "--az-cli-auth"},
		{"a service principal", map[string]string{"AZURE_CLIENT_ID": "a", "AZURE_TENANT_ID": "b", "AZURE_CLIENT_SECRET": "c"}, "--sp-env-auth"},
		// Prowler refuses --sp-env-auth with any of the three missing.
		{"a service principal with no secret", map[string]string{"AZURE_CLIENT_ID": "a", "AZURE_TENANT_ID": "b"}, "--az-cli-auth"},
		{"workload identity", map[string]string{"AZURE_CLIENT_ID": "a", "AZURE_TENANT_ID": "b", "AZURE_FEDERATED_TOKEN_FILE": "f"}, "--az-cli-auth"},
		{"a managed identity", map[string]string{"IDENTITY_ENDPOINT": "http://localhost"}, "--managed-identity-auth"},
		{"a service principal on a managed host", map[string]string{"AZURE_CLIENT_ID": "a", "AZURE_TENANT_ID": "b", "AZURE_CLIENT_SECRET": "c", "IDENTITY_ENDPOINT": "http://localhost"}, "--sp-env-auth"},
	} {
		if got := AuthFlag(func(k string) string { return c.env[k] }); got != c.want {
			t.Errorf("%s = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSubscriptionAsksWithTheToken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aaaa" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/subscriptions/"+testSubscription || r.URL.Query().Get("api-version") != subscriptionsAPI {
			t.Errorf("asked %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"subscriptionId": testSubscription, "displayName": "Shop"})
	})
	got, err := c.Subscription(context.Background(), testSubscription)
	if err != nil || got != (Subscription{ID: testSubscription, Name: "Shop"}) {
		t.Errorf("subscription = %+v, %v", got, err)
	}
}

// A subscription the credentials hold no role on and one that does not exist read the same, and the
// error names it. Another failure says what failed.
func TestSubscriptionErrorsNameIt(t *testing.T) {
	want := "subscription " + testSubscription + " does not exist, or the credentials cannot read it"
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		if _, err := c.Subscription(context.Background(), testSubscription); err == nil || err.Error() != want {
			t.Errorf("%d = %v", status, err)
		}
	}
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"Internal","message":"try later"}}`))
	})
	if _, err := c.Subscription(context.Background(), testSubscription); err == nil ||
		!strings.Contains(err.Error(), "ask Azure about subscription "+testSubscription+": 500 Internal Server Error: try later") {
		t.Errorf("a server error = %v", err)
	}
	c = newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	if _, err := c.Subscription(context.Background(), testSubscription); err == nil || !strings.Contains(err.Error(), "unreadable answer") {
		t.Errorf("an unreadable answer = %v", err)
	}
}

// A machine with no token is told so, with no request made.
func TestNoTokenIsNoCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request was made with no token")
	}))
	defer srv.Close()
	c := NewWith(srv.Client(), srv.URL, func(context.Context) (string, error) { return "", ErrNoCredentials })
	if _, err := c.Subscription(context.Background(), testSubscription); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("subscription = %v", err)
	}
	if _, err := c.Permissions(context.Background(), testSubscription); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("permissions = %v", err)
	}
}

// fakeCredential is a credential that answers without leaving the process.
type fakeCredential struct {
	token  string
	err    error
	scopes []string
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.scopes = opts.Scopes
	return azcore.AccessToken{Token: f.token}, f.err
}

// fakeMakers builds fake credentials, each answering with its own name as the token.
func fakeMakers() makers {
	named := func(name string) func() (azcore.TokenCredential, error) {
		return func() (azcore.TokenCredential, error) { return &fakeCredential{token: name}, nil }
	}
	return makers{
		environment: named("environment"), managed: named("managed"), workload: named("workload"),
		cli: named("cli"), developer: named("developer"),
	}
}

// The credential asked with is the one the flag leaves Prowler with. Whichever answers first in a
// chain is what a scan runs as, so a federated token file comes ahead of an `az login` session.
func TestCredentialMatchesTheFlag(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"a service principal", map[string]string{"AZURE_CLIENT_ID": "a", "AZURE_TENANT_ID": "b", "AZURE_CLIENT_SECRET": "c"}, "environment"},
		{"a managed identity", map[string]string{"IDENTITY_ENDPOINT": "http://localhost"}, "managed"},
		{"an az login session", nil, "cli"},
		{"workload identity", map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "f"}, "workload"},
	} {
		cred, err := credential(func(k string) string { return c.env[k] }, fakeMakers())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := tokenFrom(cred)(context.Background())
		if err != nil || got != c.want {
			t.Errorf("%s = %q, %v, want %q", c.name, got, err, c.want)
		}
	}
	broken := fakeMakers()
	broken.developer = func() (azcore.TokenCredential, error) { return nil, errors.New("cannot build") }
	if _, err := credential(func(string) string { return "" }, broken); err == nil {
		t.Error("a credential that cannot be built was accepted")
	}
}

// A credential is asked for Azure Resource Manager's scope. Its failure is ErrNoCredentials, whose
// words say what to do, unless the run itself was canceled.
func TestTokenFromAsksForResourceManager(t *testing.T) {
	cred := &fakeCredential{token: "aaaa"}
	got, err := tokenFrom(cred)(context.Background())
	if err != nil || got != "aaaa" || !slices.Equal(cred.scopes, []string{"https://management.azure.com/.default"}) {
		t.Errorf("token = %q, %v, scopes %v", got, err, cred.scopes)
	}
	failing := &fakeCredential{err: errors.New("every credential in the chain failed")}
	if _, err := tokenFrom(failing)(context.Background()); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("a failed credential = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tokenFrom(failing)(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled run = %v", err)
	}
}

func TestPermissionsReadsEveryPage(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			if r.URL.Path != "/subscriptions/"+testSubscription+"/providers/Microsoft.Authorization/permissions" ||
				r.URL.Query().Get("api-version") != permissionsAPI {
				t.Errorf("asked %s", r.URL)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":    []Permission{{Actions: []string{"*/read"}}},
				"nextLink": srv.URL + "/next?page=2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []Permission{{Actions: []string{"Microsoft.Web/*"}}}})
	}))
	defer srv.Close()
	got, err := NewWith(srv.Client(), srv.URL, staticToken).Permissions(context.Background(), testSubscription)
	if err != nil || len(got) != 2 || got[1].Actions[0] != "Microsoft.Web/*" {
		t.Errorf("permissions = %+v, %v", got, err)
	}
}

// The token goes with every request, so a next page on another host is not asked for.
func TestPermissionsStaysOnTheEndpoint(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"nextLink": "https://example.invalid/next"})
	})
	if _, err := c.Permissions(context.Background(), testSubscription); err == nil || !strings.Contains(err.Error(), "another host") {
		t.Errorf("err = %v", err)
	}
}

func TestPermissionsSaysWhenItIsRefused(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		if _, err := c.Permissions(context.Background(), testSubscription); !errors.Is(err, ErrRefused) {
			t.Errorf("%d = %v, want ErrRefused", status, err)
		}
	}
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if _, err := c.Permissions(context.Background(), testSubscription); err == nil || errors.Is(err, ErrRefused) ||
		!strings.Contains(err.Error(), "ask Azure about the permissions on subscription") {
		t.Errorf("a server error = %v", err)
	}
}

// Credentials with no role get an empty list, and a role granting data actions alone allows no read a
// check makes.
func TestHoldsAnAction(t *testing.T) {
	for _, c := range []struct {
		name   string
		grants []Permission
		want   bool
	}{
		{"an empty list", nil, false},
		{"data actions alone", []Permission{{DataActions: []string{"Microsoft.KeyVault/vaults/keys/read"}}}, false},
		{"Reader", []Permission{{Actions: []string{"*/read"}}}, true},
		{"one of two", []Permission{{}, {Actions: []string{"Microsoft.Storage/*"}}}, true},
	} {
		if got := HoldsAnAction(c.grants); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

// Azure's own rules for reading a grant: a star spans segments, case does not matter, and a
// NotActions entry takes away from its own entry alone.
func TestDeniedReadsGrantsAsAzureDoes(t *testing.T) {
	const (
		vm   = "Microsoft.Compute/virtualMachines/read"
		keys = "Microsoft.KeyVault/vaults/keys/read"
		sa   = "Microsoft.Storage/storageAccounts/read"
	)
	actions := []string{vm, keys, sa}
	for _, c := range []struct {
		name   string
		grants []Permission
		want   []string
	}{
		{"no grants", nil, actions},
		{"Reader", []Permission{{Actions: []string{"*/read"}}}, nil},
		{"Owner", []Permission{{Actions: []string{"*"}}}, nil},
		{"one provider", []Permission{{Actions: []string{"Microsoft.Storage/*"}}}, []string{vm, keys}},
		{"another case", []Permission{{Actions: []string{"microsoft.compute/VIRTUALMACHINES/READ"}}}, []string{keys, sa}},
		{"a write only", []Permission{{Actions: []string{"Microsoft.Storage/storageAccounts/write"}}}, actions},
		{"a star inside", []Permission{{Actions: []string{"Microsoft.KeyVault/*/read"}}}, []string{vm, sa}},
		{"excluded", []Permission{{Actions: []string{"*/read"}, NotActions: []string{"Microsoft.KeyVault/*"}}}, []string{keys}},
		{"excluded by one role, allowed by another", []Permission{
			{Actions: []string{"*/read"}, NotActions: []string{"Microsoft.KeyVault/*"}},
			{Actions: []string{keys}},
		}, nil},
	} {
		if got := Denied(c.grants, actions); !slices.Equal(got, c.want) {
			t.Errorf("%s: denied = %v, want %v", c.name, got, c.want)
		}
	}
}

// Each real credential builds from the environment it needs without contacting anything: azidentity
// asks for a token only when one is wanted.
func TestTheRealCredentialsBuildWithoutAskingAnything(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
	t.Setenv("AZURE_CLIENT_SECRET", "not-a-secret")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", token)
	for name, build := range map[string]func() (azcore.TokenCredential, error){
		"environment": azidentityMakers.environment, "managed": azidentityMakers.managed,
		"workload": azidentityMakers.workload, "cli": azidentityMakers.cli, "developer": azidentityMakers.developer,
	} {
		if c, err := build(); err != nil || c == nil {
			t.Errorf("%s: %v, %v", name, c, err)
		}
	}
	if c, err := New(context.Background()); err != nil || c == nil {
		t.Errorf("New with a service principal = %v, %v", c, err)
	}
}

// A credential that cannot be built is no credential, said the one way the scan reads it.
func TestNewWithACredentialThatCannotBeBuiltIsNoCredentials(t *testing.T) {
	for _, v := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "IDENTITY_ENDPOINT", "MSI_ENDPOINT"} {
		t.Setenv(v, "")
	}
	// Workload identity is chosen by its token file, and without a client ID it cannot be built.
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))
	if c, err := New(context.Background()); !errors.Is(err, ErrNoCredentials) || c != nil {
		t.Errorf("New = %v, %v, want ErrNoCredentials", c, err)
	}
}
