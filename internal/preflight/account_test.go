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
	if _, err := reachAccount(context.Background(), "aws", "123"); err == nil || !strings.Contains(err.Error(), "cannot check accounts on aws") {
		t.Errorf("aws = %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", t.TempDir()+"/missing.json")
	if _, err := reachAccount(context.Background(), "gcp", "p"); !errors.Is(err, gcpaccess.ErrNoCredentials) {
		t.Errorf("no credentials = %v", err)
	}
}

func TestTheAccountProbeDefaultsToTheRealOne(t *testing.T) {
	if (Probes{}).withDefaults().Account == nil {
		t.Error("no default account probe")
	}
}
