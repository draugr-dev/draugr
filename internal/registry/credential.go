package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Credential is what a registry is authenticated with. The zero value is anonymous.
type Credential struct {
	Username, Password string
	// IdentityToken is a refresh token, exchanged for an access token at the registry's realm.
	IdentityToken string
}

func (c Credential) empty() bool { return c.Username == "" && c.IdentityToken == "" }

// dockerConfig is the part of a Docker config.json that holds credentials.
type dockerConfig struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
	CredsStore  string            `json:"credsStore"`
	CredHelpers map[string]string `json:"credHelpers"`
}

// configPaths are the files a credential is read from, in the order the scanners read them:
// Docker's own configuration, then Podman's when Docker has none.
func configPaths() []string {
	var out []string
	if dir := os.Getenv("DOCKER_CONFIG"); dir != "" {
		out = append(out, filepath.Join(dir, "config.json"))
	} else if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".docker", "config.json"))
	}
	if f := os.Getenv("REGISTRY_AUTH_FILE"); f != "" {
		out = append(out, f)
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		out = append(out, filepath.Join(dir, "containers", "auth.json"))
	}
	return out
}

// DockerCredential returns the credential this machine holds for a registry host: from a
// credential helper named for the host, the configured credential store, or an entry in the file
// itself, in that order. A zero Credential with no error means none is configured.
func DockerCredential(ctx context.Context, host string) (Credential, error) {
	for _, path := range configPaths() {
		data, err := os.ReadFile(path) // #nosec G304 -- the user's own container configuration
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Credential{}, err
		}
		var cfg dockerConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return Credential{}, fmt.Errorf("%s: %w", path, err)
		}
		return cfg.credential(ctx, host)
	}
	return Credential{}, nil
}

// credential looks host up in one configuration file.
func (cfg dockerConfig) credential(ctx context.Context, host string) (Credential, error) {
	keys := serverKeys(host)
	for _, k := range keys {
		if helper := cfg.CredHelpers[k]; helper != "" {
			return fromHelper(ctx, helper, k)
		}
	}
	if cfg.CredsStore != "" {
		for key := range cfg.Auths {
			if matches(key, keys) {
				return fromHelper(ctx, cfg.CredsStore, key)
			}
		}
		// A store holding a credential the file does not list is still asked, under the name
		// `docker login` would have stored it by.
		if c, err := fromHelper(ctx, cfg.CredsStore, keys[0]); err != nil || !c.empty() {
			return c, err
		}
	}
	for key, a := range cfg.Auths {
		if !matches(key, keys) {
			continue
		}
		c := Credential{Username: a.Username, Password: a.Password, IdentityToken: a.IdentityToken}
		if a.Auth != "" {
			raw, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				return Credential{}, fmt.Errorf("the entry for %s is not base64", key)
			}
			c.Username, c.Password, _ = strings.Cut(string(raw), ":")
		}
		return c, nil
	}
	return Credential{}, nil
}

// serverKeys are the names a registry's credential may be stored under, the canonical one first.
// Docker Hub's is the URL of its first registry, which `docker login` still writes.
func serverKeys(host string) []string {
	if host == dockerHub {
		return []string{"https://index.docker.io/v1/", "index.docker.io", "docker.io", dockerHub}
	}
	return []string{host}
}

// matches reports whether a key from the file names one of keys, ignoring a scheme and a path.
func matches(key string, keys []string) bool {
	k := hostOf(key)
	for _, want := range keys {
		if k == hostOf(want) {
			return true
		}
	}
	return false
}

func hostOf(s string) string {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	s, _, _ = strings.Cut(s, "/")
	return s
}

// fromHelper asks a Docker credential helper for the credential stored under server.
func fromHelper(ctx context.Context, helper, server string) (Credential, error) {
	// A name holding a separator would make exec run a path rather than look a binary up on PATH,
	// so only a bare name is accepted: the helper is always docker-credential-<name> on PATH.
	if helper == "" || strings.ContainsAny(helper, `/\`) || strings.HasPrefix(helper, ".") {
		return Credential{}, fmt.Errorf("credential helper %q: not a helper name", helper)
	}
	// The command is docker-credential-<name> from the user's own Docker configuration, the binary
	// Docker itself would run, and the name is a bare word checked above.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, "docker-credential-"+helper, "get") // #nosec G204 -- the helper the user's own Docker configuration names
	cmd.Stdin = strings.NewReader(server)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// Every helper says "not found" in its own words and on either stream, and a missing entry
		// is an anonymous request rather than a failure.
		if strings.Contains(strings.ToLower(stdout.String()+stderr.String()), "not found") {
			return Credential{}, nil
		}
		return Credential{}, fmt.Errorf("docker-credential-%s: %w", helper, err)
	}
	var out struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return Credential{}, fmt.Errorf("docker-credential-%s: unreadable answer", helper)
	}
	if out.Username == "<token>" {
		return Credential{IdentityToken: out.Secret}, nil
	}
	return Credential{Username: out.Username, Password: out.Secret}, nil
}
