package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/awsaccess"
	"github.com/draugr-dev/draugr/internal/azureaccess"
	"github.com/draugr-dev/draugr/internal/gcpaccess"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// One account named by two components, whole and by a region, is one check; a second account is
// another, and its failure is reported against it rather than the first.
func TestAnAccountIsCheckedOncePerProject(t *testing.T) {
	var (
		mu    sync.Mutex
		asked []string
	)
	p := Probes{Account: func(_ context.Context, provider, id string) (string, error) {
		mu.Lock()
		asked = append(asked, provider+"/"+id)
		mu.Unlock()
		if id == "shop-data-1177" {
			return "", errors.New("project shop-data-1177 does not exist, or the credentials cannot read it")
		}
		return "project " + id + " · the credentials can read it", nil
	}}
	checks := Run(context.Background(), []plugin.Target{
		plugin.AccountTarget{Account: "prod", Provider: "gcp", ID: "shop-prod-4821"},
		plugin.AccountTarget{Account: "prod", Provider: "gcp", ID: "shop-prod-4821", Regions: []string{"us-central1"}},
		plugin.AccountTarget{Account: "data", Provider: "gcp", ID: "shop-data-1177"},
	}, Options{Probes: p})
	want := []Check{
		{"account", "gcp/shop-prod-4821", Passed, "project shop-prod-4821 · the credentials can read it"},
		{"account", "gcp/shop-data-1177", Failed, "project shop-data-1177 does not exist, or the credentials cannot read it"},
	}
	if !slices.Equal(checks, want) {
		t.Errorf("checks = %v\nwant %v", checks, want)
	}
	if len(asked) != 2 {
		t.Errorf("asked %v, want each project once", asked)
	}

	checks = Run(context.Background(), []plugin.Target{plugin.AccountTarget{Provider: "gcp", ID: "p"}},
		Options{Probes: p, Offline: true})
	if len(checks) != 1 || checks[0].Status != NotChecked {
		t.Errorf("offline = %v, want not checked", checks)
	}
}

// Whether the credentials can read a project is whether they hold its get permission, which every
// role reading anything in it carries.
func TestAProjectIsReadableWhenTheCredentialsCanGetIt(t *testing.T) {
	grant := map[string][]string{"readable": {readProject}, "opaque": {}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		project := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/"), ":testIamPermissions")
		held, ok := grant[project]
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string][]string{"permissions": held})
	}))
	defer srv.Close()
	tester := gcpaccess.NewWith(srv.Client(), srv.URL)

	if got, err := projectReadable(context.Background(), tester, "readable"); err != nil || got != "project readable · the credentials can read it" {
		t.Errorf("readable = %q, %v", got, err)
	}
	if _, err := projectReadable(context.Background(), tester, "opaque"); err == nil ||
		!strings.Contains(err.Error(), "the credentials hold no role on project opaque that can read it") {
		t.Errorf("opaque = %v", err)
	}
	if _, err := projectReadable(context.Background(), tester, "missing"); err == nil ||
		!strings.Contains(err.Error(), "does not exist, or the credentials cannot read it") {
		t.Errorf("missing = %v", err)
	}
}

func TestReachAccountNamesWhatItCannotCheck(t *testing.T) {
	if _, err := reachAccount(context.Background(), "oracle", "123"); err == nil || !strings.Contains(err.Error(), "cannot check accounts on oracle") {
		t.Errorf("oracle = %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", t.TempDir()+"/missing.json")
	if _, err := reachAccount(context.Background(), "gcp", "p"); !errors.Is(err, gcpaccess.ErrNoCredentials) {
		t.Errorf("no credentials = %v", err)
	}
	dir := t.TempDir()
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", dir+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", dir+"/credentials")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	if _, err := reachAccount(context.Background(), "aws", "111111111111"); !errors.Is(err, awsaccess.ErrNoCredentials) {
		t.Errorf("no AWS credentials = %v", err)
	}
}

// staticCaller is an STS answer naming one identity.
type staticCaller awsaccess.Caller

func (c staticCaller) CallerIdentity(context.Context) (awsaccess.Caller, error) {
	return awsaccess.Caller(c), nil
}

// An AWS account is reachable when the credentials are an identity in it, and doctor names the
// identity, which is what tells somebody which profile a scan would run as.
func TestAnAWSAccountIsReachableAsAnIdentityInIt(t *testing.T) {
	role := staticCaller{Account: "111111111111", ARN: "arn:aws:sts::111111111111:assumed-role/audit/scan"}
	got, err := callerInAccount(context.Background(), role, "111111111111")
	if err != nil || got != "account 111111111111 · the credentials are arn:aws:sts::111111111111:assumed-role/audit/scan" {
		t.Errorf("the declared account = %q, %v", got, err)
	}
	if _, err := callerInAccount(context.Background(), role, "222222222222"); err == nil ||
		!strings.Contains(err.Error(), "in account 111111111111, not the declared account 222222222222") {
		t.Errorf("another account = %v", err)
	}
}

// fakeSubscriptions is Azure Resource Manager, synthetic: reachAccount's "azure" case builds a real
// credential, so no test calls it.
type fakeSubscriptions struct {
	sub       azureaccess.Subscription
	err       error
	grants    []azureaccess.Permission
	grantsErr error
}

func (f fakeSubscriptions) Subscription(context.Context, string) (azureaccess.Subscription, error) {
	return f.sub, f.err
}

func (f fakeSubscriptions) Permissions(context.Context, string) ([]azureaccess.Permission, error) {
	return f.grants, f.grantsErr
}

// An Azure subscription is reachable when the credentials can read it and hold a role on it, and doctor
// names it, which tells somebody whose subscription a scan would read.
func TestAnAzureSubscriptionIsReachableWhenItCanBeRead(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000000"
	shop := azureaccess.Subscription{ID: id, Name: "Shop"}
	reader := []azureaccess.Permission{{Actions: []string{"*/read"}}}
	const readable = "subscription " + id + " (Shop) · the credentials can read it"

	got, err := subscriptionReadable(context.Background(), fakeSubscriptions{sub: shop, grants: reader}, id)
	if err != nil || got != readable {
		t.Errorf("readable = %q, %v", got, err)
	}
	refused := errors.New("subscription " + id + " does not exist, or the credentials cannot read it")
	if _, err := subscriptionReadable(context.Background(), fakeSubscriptions{err: refused}, id); !errors.Is(err, refused) {
		t.Errorf("refused = %v", err)
	}
	// Visible with no role: the subscription answers and the list is empty, so a scan reads nothing.
	if _, err := subscriptionReadable(context.Background(), fakeSubscriptions{sub: shop}, id); err == nil ||
		err.Error() != "subscription "+id+" (Shop) · the credentials hold no role on it; grant Reader" {
		t.Errorf("no role = %v", err)
	}
	// A list Azure will not give says nothing about the role, so the subscription stays reachable.
	got, err = subscriptionReadable(context.Background(), fakeSubscriptions{sub: shop, grantsErr: azureaccess.ErrRefused}, id)
	if err != nil || got != readable {
		t.Errorf("list refused = %q, %v", got, err)
	}
}

func TestTheAccountProbeDefaultsToTheRealOne(t *testing.T) {
	if (Probes{}).withDefaults().Account == nil {
		t.Error("no default account probe")
	}
}
