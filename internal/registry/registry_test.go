package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := map[string]Reference{
		"nginx":                             {dockerHub, "library/nginx", "latest"},
		"nginx:1.27":                        {dockerHub, "library/nginx", "1.27"},
		"docker.io/acme/web:2":              {dockerHub, "acme/web", "2"},
		"index.docker.io/acme/web":          {dockerHub, "acme/web", "latest"},
		"acme/web":                          {dockerHub, "acme/web", "latest"},
		"ghcr.io/acme/web:1.4":              {"ghcr.io", "acme/web", "1.4"},
		"ghcr.io/acme/web:1.4@sha256:abc":   {"ghcr.io", "acme/web", "sha256:abc"},
		"localhost:5000/web":                {"localhost:5000", "web", "latest"},
		"localhost/web:dev":                 {"localhost", "web", "dev"},
		"docker://registry.example.com/a/b": {"registry.example.com", "a/b", "latest"},
	}
	for ref, want := range cases {
		got, err := Parse(ref)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", ref, got, err, want)
		}
	}
	if _, err := Parse("@sha256:abc"); err == nil {
		t.Error("a reference with no name parsed")
	}
}

// fakeRegistry serves one repository's manifest behind the auth scheme given.
type fakeRegistry struct {
	scheme   string // "", "basic" or "bearer"
	user     string
	pass     string
	refresh  string // identity token accepted at the realm
	public   bool   // anonymous tokens may pull
	srv      *httptest.Server
	manifest int // HEAD requests seen
}

func newFakeRegistry(t *testing.T, r *fakeRegistry) *fakeRegistry {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("scope") != "repository:acme/web:pull" && req.FormValue("scope") != "repository:acme/web:pull" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		switch req.Method {
		case http.MethodPost:
			if req.FormValue("grant_type") != "refresh_token" || req.FormValue("refresh_token") != r.refresh {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "granted"})
		default:
			u, p, ok := req.BasicAuth()
			if ok && (u != r.user || p != r.pass) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !ok && !r.public {
				_ = json.NewEncoder(w).Encode(map[string]string{"token": "anonymous"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "granted"})
		}
	})
	mux.HandleFunc("/v2/acme/web/manifests/", func(w http.ResponseWriter, req *http.Request) {
		r.manifest++
		if req.Method != http.MethodHead || !strings.Contains(req.Header.Get("Accept"), "oci.image.index") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.HasSuffix(req.URL.Path, "/1.0") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		authz := req.Header.Get("Authorization")
		switch r.scheme {
		case "basic":
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte(r.user+":"+r.pass))
			if authz != want {
				w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		case "bearer":
			if authz != "Bearer granted" {
				w.Header().Set("WWW-Authenticate",
					`Bearer realm="`+r.srv.URL+`/token",service="fake",scope="repository:acme/web:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

// host is the fake's address, which Check reaches over plain HTTP because it is loopback.
func (r *fakeRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "http://") }

func clientWith(c Credential) *Client {
	return &Client{Credential: func(context.Context, string) (Credential, error) { return c, nil }}
}

func TestCheck(t *testing.T) {
	ctx := context.Background()

	open := newFakeRegistry(t, &fakeRegistry{})
	if err := clientWith(Credential{}).Check(ctx, open.host()+"/acme/web:1.0"); err != nil {
		t.Errorf("open registry: %v", err)
	}
	var se *StatusError
	if err := clientWith(Credential{}).Check(ctx, open.host()+"/acme/web:2.0"); !errors.As(err, &se) || se.Code != 404 {
		t.Errorf("absent tag: %v", err)
	} else if se.Error() != "404 not found" {
		t.Errorf("404 message: %q", se.Error())
	}

	basic := newFakeRegistry(t, &fakeRegistry{scheme: "basic", user: "u", pass: "p"})
	if err := clientWith(Credential{Username: "u", Password: "p"}).Check(ctx, basic.host()+"/acme/web:1.0"); err != nil {
		t.Errorf("basic with a credential: %v", err)
	}
	err := clientWith(Credential{}).Check(ctx, basic.host()+"/acme/web:1.0")
	if !errors.As(err, &se) || err.Error() != "401 unauthorized, no credential for "+basic.host() {
		t.Errorf("basic without a credential: %v", err)
	}

	bearer := newFakeRegistry(t, &fakeRegistry{scheme: "bearer", user: "u", pass: "p", refresh: "rt"})
	if err := clientWith(Credential{Username: "u", Password: "p"}).Check(ctx, bearer.host()+"/acme/web:1.0"); err != nil {
		t.Errorf("bearer with a password: %v", err)
	}
	if err := clientWith(Credential{IdentityToken: "rt"}).Check(ctx, bearer.host()+"/acme/web:1.0"); err != nil {
		t.Errorf("bearer with an identity token: %v", err)
	}
	// A wrong password is refused at the realm, and the credential was not missing.
	err = clientWith(Credential{Username: "u", Password: "wrong"}).Check(ctx, bearer.host()+"/acme/web:1.0")
	if !errors.As(err, &se) || err.Error() != "401 unauthorized" {
		t.Errorf("bearer with a wrong password: %v", err)
	}
	// Anonymous gets a token that the manifest refuses.
	err = clientWith(Credential{}).Check(ctx, bearer.host()+"/acme/web:1.0")
	if err == nil || !strings.Contains(err.Error(), "no credential for") {
		t.Errorf("bearer anonymously: %v", err)
	}

	public := newFakeRegistry(t, &fakeRegistry{scheme: "bearer", public: true})
	if err := clientWith(Credential{}).Check(ctx, public.host()+"/acme/web:1.0"); err != nil {
		t.Errorf("public image with an anonymous token: %v", err)
	}
}

func TestCheckErrors(t *testing.T) {
	ctx := context.Background()
	if err := clientWith(Credential{}).Check(ctx, "@sha256:x"); err == nil {
		t.Error("an unparseable reference passed")
	}
	failing := &Client{Credential: func(context.Context, string) (Credential, error) { return Credential{}, errors.New("helper broke") }}
	if err := failing.Check(ctx, "ghcr.io/acme/web:1"); err == nil || !strings.Contains(err.Error(), "helper broke") {
		t.Errorf("credential error: %v", err)
	}

	// A challenge naming no realm, and a realm answering nonsense.
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/norealm/manifests/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer service="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/v2/garbled/manifests/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+srvURL+`/garbled-token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/garbled-token", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) })
	mux.HandleFunc("/v2/unknown/manifests/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Negotiate`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	host := strings.TrimPrefix(srv.URL, "http://")

	if err := clientWith(Credential{}).Check(ctx, host+"/norealm:1"); err == nil || !strings.Contains(err.Error(), "named nowhere") {
		t.Errorf("no realm: %v", err)
	}
	if err := clientWith(Credential{}).Check(ctx, host+"/garbled:1"); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Errorf("empty token response: %v", err)
	}
	if err := clientWith(Credential{}).Check(ctx, host+"/unknown:1"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("unknown scheme: %v", err)
	}
	// Nothing listening, and not an address plain HTTP is tried for.
	if err := clientWith(Credential{}).Check(ctx, "registry.invalid/acme/web:1"); err == nil {
		t.Error("an unresolvable registry passed")
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, p := parseChallenge(`Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:a/b:pull"`)
	if scheme != "bearer" || p["realm"] != "https://auth.example.com/token" || p["service"] != "registry.example.com" ||
		p["scope"] != "repository:a/b:pull" {
		t.Errorf("got %s %v", scheme, p)
	}
	if _, p := parseChallenge(`Basic realm=unquoted, charset="UTF-8`); p["realm"] != "unquoted" || p["charset"] != "UTF-8" {
		t.Errorf("unquoted and unterminated: %v", p)
	}
}

func TestPlainHTTPAllowed(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost:5000": true, "127.0.0.1": true, "10.0.0.8:5000": true, "192.168.1.2": true,
		"ghcr.io": false, "8.8.8.8": false, "registry.example.com:5000": false,
	} {
		if got := plainHTTPAllowed(host); got != want {
			t.Errorf("plainHTTPAllowed(%q) = %v", host, got)
		}
	}
}

func writeConfig(t *testing.T, cfg string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
}

// fakeHelper puts docker-credential-<name> on PATH, answering get with body, or failing with
// stderr when body is empty.
func fakeHelper(t *testing.T, name, body, stderr string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat >/dev/null\n"
	if body != "" {
		script += "printf '%s' '" + body + "'\n"
	} else {
		script += "echo '" + stderr + "' >&2\nexit 1\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-credential-"+name), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test helper
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestDockerCredential(t *testing.T) {
	ctx := context.Background()
	auth := base64.StdEncoding.EncodeToString([]byte("alice:pw"))

	t.Run("auths", func(t *testing.T) {
		writeConfig(t, `{"auths":{"https://index.docker.io/v1/":{"auth":"`+auth+`"},"ghcr.io":{"identitytoken":"rt"}}}`)
		if c, err := DockerCredential(ctx, dockerHub); err != nil || c.Username != "alice" || c.Password != "pw" {
			t.Errorf("docker hub: %+v %v", c, err)
		}
		if c, err := DockerCredential(ctx, "ghcr.io"); err != nil || c.IdentityToken != "rt" {
			t.Errorf("identity token: %+v %v", c, err)
		}
		if c, err := DockerCredential(ctx, "quay.io"); err != nil || !c.empty() {
			t.Errorf("unlisted host: %+v %v", c, err)
		}
	})

	t.Run("helper", func(t *testing.T) {
		fakeHelper(t, "fake", `{"Username":"bob","Secret":"s"}`, "")
		writeConfig(t, `{"credHelpers":{"ghcr.io":"fake"}}`)
		if c, err := DockerCredential(ctx, "ghcr.io"); err != nil || c.Username != "bob" || c.Password != "s" {
			t.Errorf("helper: %+v %v", c, err)
		}
	})

	t.Run("store with a token", func(t *testing.T) {
		fakeHelper(t, "store", `{"Username":"<token>","Secret":"rt"}`, "")
		writeConfig(t, `{"credsStore":"store","auths":{"registry.example.com":{}}}`)
		if c, err := DockerCredential(ctx, "registry.example.com"); err != nil || c.IdentityToken != "rt" {
			t.Errorf("store: %+v %v", c, err)
		}
	})

	t.Run("store with nothing stored", func(t *testing.T) {
		fakeHelper(t, "empty", "", "credentials not found in native keychain")
		writeConfig(t, `{"credsStore":"empty"}`)
		if c, err := DockerCredential(ctx, "ghcr.io"); err != nil || !c.empty() {
			t.Errorf("not found is anonymous: %+v %v", c, err)
		}
	})

	t.Run("broken helper", func(t *testing.T) {
		fakeHelper(t, "broken", "", "keychain locked")
		writeConfig(t, `{"credHelpers":{"ghcr.io":"broken"}}`)
		if _, err := DockerCredential(ctx, "ghcr.io"); err == nil || !strings.Contains(err.Error(), "docker-credential-broken") {
			t.Errorf("broken helper: %v", err)
		}
		fakeHelper(t, "garbled", "not json", "")
		writeConfig(t, `{"credHelpers":{"ghcr.io":"garbled"}}`)
		if _, err := DockerCredential(ctx, "ghcr.io"); err == nil || !strings.Contains(err.Error(), "unreadable") {
			t.Errorf("garbled helper: %v", err)
		}
	})

	t.Run("bad files", func(t *testing.T) {
		writeConfig(t, `{"auths":{"ghcr.io":{"auth":"%%%"}}}`)
		if _, err := DockerCredential(ctx, "ghcr.io"); err == nil || !strings.Contains(err.Error(), "base64") {
			t.Errorf("bad base64: %v", err)
		}
		writeConfig(t, `{`)
		if _, err := DockerCredential(ctx, "ghcr.io"); err == nil {
			t.Error("unparseable config passed")
		}
	})

	t.Run("podman file", func(t *testing.T) {
		t.Setenv("DOCKER_CONFIG", t.TempDir()) // holds no config.json
		f := filepath.Join(t.TempDir(), "auth.json")
		if err := os.WriteFile(f, []byte(`{"auths":{"quay.io":{"auth":"`+auth+`"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("REGISTRY_AUTH_FILE", f)
		if c, err := DockerCredential(ctx, "quay.io"); err != nil || c.Username != "alice" {
			t.Errorf("REGISTRY_AUTH_FILE: %+v %v", c, err)
		}
	})

	t.Run("none", func(t *testing.T) {
		t.Setenv("DOCKER_CONFIG", t.TempDir())
		t.Setenv("REGISTRY_AUTH_FILE", "")
		t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
		if c, err := DockerCredential(ctx, "quay.io"); err != nil || !c.empty() {
			t.Errorf("no files: %+v %v", c, err)
		}
	})
}
