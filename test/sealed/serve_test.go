package sealed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeServed(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServedHandler(t *testing.T) {
	root := t.TempDir()
	manifest := `{"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}`
	writeServed(t, root, "org/example/lib/1.0/lib-1.0.pom", "<project/>")
	writeServed(t, root, "v2/sealed/app/manifests/1.0", manifest)
	var log bytes.Buffer
	srv := httptest.NewServer(ServedHandler(root, &log))
	defer srv.Close()

	// answer is what the test reads of a response, taken before its body is closed.
	type answer struct {
		StatusCode    int
		ContentLength int64
		Header        http.Header
	}
	get := func(method, path string) (answer, string) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return answer{resp.StatusCode, resp.ContentLength, resp.Header}, string(b)
	}

	if resp, body := get(http.MethodGet, "/org/example/lib/1.0/lib-1.0.pom"); resp.StatusCode != 200 || body != "<project/>" {
		t.Errorf("file: %d", resp.StatusCode)
	}
	if resp, body := get(http.MethodHead, "/org/example/lib/1.0/lib-1.0.pom"); resp.StatusCode != 200 || resp.ContentLength != 10 || body != "" {
		t.Errorf("HEAD: %d, length %d", resp.StatusCode, resp.ContentLength)
	}
	if resp, body := get(http.MethodGet, "/v2/"); resp.StatusCode != 200 || body != "{}" {
		t.Errorf("registry version check: %d", resp.StatusCode)
	}
	sum := sha256.Sum256([]byte(manifest))
	resp, _ := get(http.MethodGet, "/v2/sealed/app/manifests/1.0")
	if resp.Header.Get("Content-Type") != "application/vnd.oci.image.manifest.v1+json" ||
		resp.Header.Get("Docker-Content-Digest") != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("manifest headers = %v", resp.Header)
	}
	if resp, _ := get(http.MethodGet, "/../../etc/passwd"); resp.StatusCode != 404 {
		t.Errorf("a path outside root: %d", resp.StatusCode)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	writeServed(t, filepath.Dir(outside), "secret", "outside")
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if resp, body := get(http.MethodGet, "/escape"); resp.StatusCode != 404 {
		t.Errorf("a symlink out of root: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get(http.MethodDelete, "/org/example/lib/1.0/lib-1.0.pom"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: %d", resp.StatusCode)
	}
	for _, want := range []string{"GET /org/example/lib/1.0/lib-1.0.pom\n", "HEAD /org/", "GET /v2/\n", "DELETE /org/example"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("the request log lacks %q:\n%s", want, log.String())
		}
	}
}

// TestServeHelperFetch is not a test on its own: TestServeAndRun runs this test binary as the
// command beside the server, and it fetches what the server offers.
func TestServeHelperFetch(t *testing.T) {
	url := os.Getenv("SEALED_SERVE_FETCH")
	if url == "" {
		t.Skip("run by TestServeAndRun")
	}
	resp, err := http.Get(url) // #nosec G107 G704 -- a loopback URL the parent test chose
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "served" {
		os.Exit(7)
	}
}

func TestCheckRequests(t *testing.T) {
	log := []byte("GET /c/p/default\nGET /a.pom?x=1\nDELETE /items/1\n")
	if p := CheckRequests([]string{"GET /c/p/default", "GET /a.pom"}, []string{"POST "}, log); len(p) != 0 {
		t.Errorf("problems for requests received: %v", p)
	}
	p := CheckRequests([]string{"HEAD /c/p/default"}, []string{"DELETE "}, log)
	if len(p) != 2 || !strings.Contains(p[0], `"HEAD /c/p/default"`) || !strings.Contains(p[0], "GET /a.pom") ||
		!strings.Contains(p[1], `"DELETE /items/1"`) {
		t.Errorf("problems = %v", p)
	}
	if p := CheckRequests(nil, []string{"GET "}, nil); len(p) != 0 {
		t.Errorf("an empty log: %v", p)
	}
}

func TestServeAndRun(t *testing.T) {
	root := t.TempDir()
	writeServed(t, root, "file", "served")
	logPath := filepath.Join(t.TempDir(), "requests.log")
	addr := "127.0.0.1:18979"
	t.Setenv("SEALED_SERVE_FETCH", "http://"+addr+"/file")

	var out, errOut bytes.Buffer
	code := ServeAndRun(addr, root, logPath, []string{os.Args[0], "-test.run=^TestServeHelperFetch$"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errOut.String())
	}
	log, err := os.ReadFile(logPath) // #nosec G304 -- under t.TempDir()
	if err != nil || string(log) != "GET /file\n" {
		t.Errorf("request log = %q (%v)", log, err)
	}

	t.Setenv("SEALED_SERVE_FETCH", "http://"+addr+"/missing")
	if code := ServeAndRun(addr, root, logPath, []string{os.Args[0], "-test.run=^TestServeHelperFetch$"}, io.Discard, io.Discard); code != 7 {
		t.Errorf("the command's own exit code was not passed on: %d", code)
	}

	for name, tc := range map[string]struct {
		addr, log string
		argv      []string
	}{
		"no command":       {addr, logPath, nil},
		"no such command":  {addr, logPath, []string{filepath.Join(root, "missing")}},
		"unwritable log":   {addr, filepath.Join(root, "file", "log"), []string{"true"}},
		"unusable address": {"127.0.0.1:-1", logPath, []string{"true"}},
	} {
		t.Run(name, func(t *testing.T) {
			var errOut bytes.Buffer
			if code := ServeAndRun(tc.addr, root, tc.log, tc.argv, io.Discard, &errOut); code != 2 || !strings.Contains(errOut.String(), "sealed serve") {
				t.Errorf("exit %d, stderr %q", code, errOut.String())
			}
		})
	}
}
