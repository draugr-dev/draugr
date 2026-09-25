package sealed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// ServedAddr is where the sealed server listens inside the container. A fixed port is safe
// because every container has a network namespace of its own, with nothing else in it.
const ServedAddr = "127.0.0.1:18080"

// ServedURL is ServedAddr as a URL, for a descriptor or a tool setting that points at it.
const ServedURL = "http://" + ServedAddr

// ServedHandler serves the files under root to GET and HEAD, the way a Maven repository, a rule
// registry or a container registry answers, and appends a line to log for every request, whatever
// its method, so a scenario can assert what a scanner asked for and what it never sent.
//
// A registry client reads a manifest's type from Content-Type rather than from the document, so a
// file under /v2/<name>/manifests/ is served with the mediaType it declares and the digest a
// client checks it against.
func ServedHandler(root string, log io.Writer) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		_, _ = fmt.Fprintf(log, "%s %s\n", r.Method, r.URL.RequestURI())
		mu.Unlock()
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "the sealed server is read-only", http.StatusMethodNotAllowed)
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		if clean == "/v2" {
			// The version check every registry client makes first; 200 means no authentication.
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{}")
			return
		}
		body, err := readUnder(root, strings.TrimPrefix(clean, "/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(clean, "/v2/") && strings.Contains(clean, "/manifests/") {
			var m struct {
				MediaType string `json:"mediaType"`
			}
			_ = json.Unmarshal(body, &m)
			sum := sha256.Sum256(body)
			w.Header().Set("Content-Type", m.MediaType)
			w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
		} else if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(body) // #nosec G705 -- a fixture file served to the scan under test
		}
	})
}

// readUnder reads name inside root, refusing a path or a symlink that leads out of it.
func readUnder(root, name string) ([]byte, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return r.ReadFile(filepath.FromSlash(name))
}

// CheckRequests returns a problem for every entry of want that no line of the request log starts
// with, and for every line that starts with an entry of never.
func CheckRequests(want, never []string, log []byte) []string {
	lines := strings.Split(strings.TrimSuffix(string(log), "\n"), "\n")
	startsWith := func(prefix string) func(string) bool {
		return func(line string) bool { return strings.HasPrefix(line, prefix) }
	}
	var problems []string
	for _, w := range want {
		if !slices.ContainsFunc(lines, startsWith(w)) {
			problems = append(problems, fmt.Sprintf("the sealed server never received %q; it received:\n%s", w, log))
		}
	}
	for _, n := range never {
		for _, line := range slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return !strings.HasPrefix(l, n) }) {
			problems = append(problems, fmt.Sprintf("the sealed server received %q, which starts with %q", line, n))
		}
	}
	return problems
}

// ServeAndRun serves root on addr, logging requests to logPath, runs argv once the listener is
// up, and returns the exit code argv ended with. The server lives exactly as long as the command,
// so nothing outlives the container it started in.
func ServeAndRun(addr, root, logPath string, argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		_, _ = fmt.Fprintln(stderr, "sealed serve: no command to run")
		return 2
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the test's own log path
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sealed serve:", err)
		return 2
	}
	defer func() { _ = log.Close() }()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sealed serve:", err)
		return 2
	}
	srv := &http.Server{Handler: ServedHandler(root, log), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 G702 -- the test's own argv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		_, _ = fmt.Fprintln(stderr, "sealed serve:", err)
		return 2
	}
}
