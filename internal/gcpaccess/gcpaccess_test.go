package gcpaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// fakeIAM answers testIamPermissions for one project, granting what it holds and refusing every
// other project the way Google does, with permission denied.
func fakeIAM(t *testing.T, project string, holds ...string) (*httptest.Server, *[][]string) {
	t.Helper()
	var asked [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/"+project+":testIamPermissions" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":{"code":403,"message":"The caller does not have permission"}}`)
			return
		}
		var body struct {
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("request body: %v", err)
		}
		asked = append(asked, body.Permissions)
		var granted []string
		for _, p := range body.Permissions {
			if slices.Contains(holds, p) {
				granted = append(granted, p)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string][]string{"permissions": granted})
	}))
	t.Cleanup(srv.Close)
	return srv, &asked
}

func TestGrantedReturnsWhatTheCredentialsHoldInTheOrderAsked(t *testing.T) {
	srv, _ := fakeIAM(t, "shop-prod-4821", "compute.instances.list", "storage.buckets.list")
	got, err := NewWith(srv.Client(), srv.URL).Granted(context.Background(), "shop-prod-4821",
		[]string{"storage.buckets.list", "cloudsql.instances.list", "compute.instances.list", "storage.buckets.list"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"storage.buckets.list", "compute.instances.list"}; !slices.Equal(got, want) {
		t.Errorf("granted = %v, want %v", got, want)
	}
}

// Google takes at most a hundred permissions a call, so a longer list is asked in parts and
// answered as one.
func TestGrantedAsksInBatches(t *testing.T) {
	var perms []string
	for i := range batch + 5 {
		perms = append(perms, fmt.Sprintf("svc.thing%03d.list", i))
	}
	srv, asked := fakeIAM(t, "p", perms[0], perms[batch+4])
	got, err := NewWith(srv.Client(), srv.URL).Granted(context.Background(), "p", perms)
	if err != nil {
		t.Fatal(err)
	}
	if len(*asked) != 2 || len((*asked)[0]) != batch || len((*asked)[1]) != 5 {
		t.Errorf("asked in %d calls of %v", len(*asked), lens(*asked))
	}
	if len(got) != 2 {
		t.Errorf("granted = %v", got)
	}
}

func lens(calls [][]string) []int {
	var out []int
	for _, c := range calls {
		out = append(out, len(c))
	}
	return out
}

// A project the credentials cannot see and one that does not exist get one answer from Google, and
// the error names both.
func TestAProjectTheCredentialsCannotReadIsAnError(t *testing.T) {
	srv, _ := fakeIAM(t, "shop-prod-4821")
	_, err := NewWith(srv.Client(), srv.URL).Granted(context.Background(), "shop-data-1177", []string{"a.b.c"})
	if err == nil || !strings.Contains(err.Error(), "project shop-data-1177 does not exist, or the credentials cannot read it") {
		t.Errorf("error = %v", err)
	}
}

func TestAnUnexpectedAnswerCarriesGooglesMessage(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"an invalid permission":   {http.StatusBadRequest, `{"error":{"message":"Permission x.y.z is not valid"}}`, "400 Bad Request: Permission x.y.z is not valid"},
		"a body that is not JSON": {http.StatusInternalServerError, "upstream down", "500 Internal Server Error: upstream down"},
		"an unreadable success":   {http.StatusOK, "not json", "unreadable answer"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			_, err := NewWith(srv.Client(), srv.URL).Granted(context.Background(), "p", []string{"a.b.c"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAnUnreachableEndpointIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	if _, err := NewWith(http.DefaultClient, srv.URL).Granted(context.Background(), "p", []string{"a.b.c"}); err == nil {
		t.Error("a closed endpoint answered")
	}
}

// With no credentials anywhere, the error says where Draugr looked and how to provide some.
func TestNoCredentialsSaysHowToProvideThem(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", t.TempDir()+"/missing.json")
	_, err := New(context.Background())
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("error = %v, want ErrNoCredentials", err)
	}
}

func TestNewFindsCredentialsFromTheEnvironment(t *testing.T) {
	path := t.TempDir() + "/adc.json"
	key := `{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"token"}`
	if err := writeFile(path, key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	if _, err := New(context.Background()); err != nil {
		t.Errorf("New: %v", err)
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
