package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/selfupdate"
)

// stubLatest overrides the latest-version resolver seam and restores it after the test.
func stubLatest(t *testing.T, version string, err error) {
	t.Helper()
	orig := selfUpdateLatest
	selfUpdateLatest = func(context.Context, *http.Client) (string, error) { return version, err }
	t.Cleanup(func() { selfUpdateLatest = orig })
}

// stubRun overrides the update seam and restores it after the test.
func stubRun(t *testing.T, res selfupdate.Result, err error) {
	t.Helper()
	orig := selfUpdateRun
	selfUpdateRun = func(context.Context, selfupdate.Options) (selfupdate.Result, error) { return res, err }
	t.Cleanup(func() { selfUpdateRun = orig })
}

func TestConfirmed(t *testing.T) {
	for _, yes := range []string{"y\n", "Y\n", "yes\n", "  yes \n"} {
		if !confirmed(strings.NewReader(yes)) {
			t.Errorf("%q should be affirmative", yes)
		}
	}
	for _, no := range []string{"n\n", "\n", "no\n", "nope\n"} {
		if confirmed(strings.NewReader(no)) {
			t.Errorf("%q should not be affirmative", no)
		}
	}
}

func TestSelfUpdateCheck(t *testing.T) {
	// current is "dev" in tests; latest differs → "update available".
	stubLatest(t, "9.9.9", nil)
	var out bytes.Buffer
	if err := runSelfUpdate(context.Background(), &out, strings.NewReader(""), selfUpdateOptions{check: true}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "latest:  9.9.9") || !strings.Contains(s, "update is available") {
		t.Errorf("unexpected --check output:\n%s", s)
	}
}

func TestSelfUpdateCheckError(t *testing.T) {
	stubLatest(t, "", errors.New("no egress"))
	err := runSelfUpdate(context.Background(), &bytes.Buffer{}, strings.NewReader(""), selfUpdateOptions{check: true})
	if err == nil || !strings.Contains(err.Error(), "check for updates") {
		t.Fatalf("expected a check error, got %v", err)
	}
}

func TestSelfUpdateAlreadyCurrent(t *testing.T) {
	// Pinned target equal to the current version ("dev") → no prompt, no change.
	var out bytes.Buffer
	err := runSelfUpdate(context.Background(), &out, strings.NewReader(""), selfUpdateOptions{version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already at") {
		t.Errorf("expected 'already at', got: %s", out.String())
	}
}

func TestSelfUpdateAbortsWithoutConfirm(t *testing.T) {
	// Force interactive so the prompt is shown; "n" aborts.
	orig := isTTY
	isTTY = func(io.Reader) bool { return true }
	t.Cleanup(func() { isTTY = orig })

	var out bytes.Buffer
	err := runSelfUpdate(context.Background(), &out, strings.NewReader("n\n"), selfUpdateOptions{version: "9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Errorf("expected abort, got: %s", out.String())
	}
}

func TestSelfUpdateResolveLatestAndRun(t *testing.T) {
	stubLatest(t, "9.9.9", nil)
	stubRun(t, selfupdate.Result{Previous: "dev", Target: "9.9.9", Note: "cosign not installed"}, nil)
	var out bytes.Buffer
	err := runSelfUpdate(context.Background(), &out, strings.NewReader("y\n"), selfUpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "updated draugr dev → 9.9.9") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}

func TestSelfUpdateLatestResolveError(t *testing.T) {
	stubLatest(t, "", errors.New("no egress"))
	err := runSelfUpdate(context.Background(), &bytes.Buffer{}, strings.NewReader(""), selfUpdateOptions{})
	if err == nil || !strings.Contains(err.Error(), "resolve the latest") {
		t.Fatalf("expected a resolve error, got %v", err)
	}
}

func TestSelfUpdateCommandViaCobra(t *testing.T) {
	stubLatest(t, "9.9.9", nil)
	cmd := newSelfUpdateCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--check"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "9.9.9") {
		t.Errorf("output = %q", out.String())
	}
}

func TestSelfUpdateSuccess(t *testing.T) {
	stubRun(t, selfupdate.Result{Previous: "dev", Target: "9.9.9", SignatureVerified: true, Path: "/usr/local/bin/draugr"}, nil)
	var out bytes.Buffer
	// -y skips the prompt; pinned version avoids the latest lookup.
	err := runSelfUpdate(context.Background(), &out, strings.NewReader(""), selfUpdateOptions{version: "9.9.9", yes: true})
	if err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "updated draugr dev → 9.9.9") || !strings.Contains(s, "cosign verified") {
		t.Errorf("unexpected success output:\n%s", s)
	}
}
