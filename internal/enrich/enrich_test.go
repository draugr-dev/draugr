package enrich

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/depsdev"
	"github.com/draugr-dev/draugr/internal/exploitdata"
	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestLoadAddsDependencyHealthOnlyWhenEnabled(t *testing.T) {
	ctx := context.Background()
	off, err := Load(ctx, exploitdata.Settings{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	on, err := Load(ctx, exploitdata.Settings{}, &saga.DependencyHealthConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(on.Options) != len(off.Options)+1 {
		t.Errorf("options: %d enabled, %d disabled; want one more for dependency health", len(on.Options), len(off.Options))
	}
}

func TestLoadFailsOnAFeedItCannotRead(t *testing.T) {
	_, err := Load(context.Background(), exploitdata.Settings{KEV: t.TempDir() + "/missing.json", KEVFrom: "config.exploitability.kev"}, nil, nil)
	if err == nil {
		t.Fatal("a missing KEV file was accepted")
	}
}

// A lookup that fails is reported and does not fail the run: this signal never gates.
func TestAFailedLookupWarnsAndContinues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	client := depsdev.New()
	client.Endpoint = srv.URL
	src := dephealth.New(nil, "")
	var warn bytes.Buffer
	if err := resolver(client, src, &warn)(context.Background(), []string{"pkg:npm/jquery@1.8.3"}); err != nil {
		t.Fatalf("a failed lookup failed the run: %v", err)
	}
	if !strings.HasPrefix(warn.String(), "dependency health: ") || !strings.Contains(warn.String(), "ranked without it") {
		t.Errorf("warning = %q", warn.String())
	}
	if !src.Empty() {
		t.Error("a failed lookup filled the source")
	}
}

func TestDependencyHealthDetail(t *testing.T) {
	if got := DependencyHealthDetail(nil); got != "" {
		t.Errorf("no config: %q", got)
	}
	if got := DependencyHealthDetail(&saga.DependencyHealthConfig{}); got != "" {
		t.Errorf("disabled: %q", got)
	}
	if got := DependencyHealthDetail(&saga.DependencyHealthConfig{Enabled: true}); !strings.Contains(got, "api.deps.dev") {
		t.Errorf("enabled: %q, want the host named", got)
	}
}

// The descriptor's maxAge reaches the feeds scanners read for themselves, which is the only way it
// can: a scanner sees its own options and not config.exploitability.
func TestLoadSetsTheFeedAgeLimit(t *testing.T) {
	t.Cleanup(func() { scanners.SetFeedMaxAge(feeds.DefaultMaxAge) })
	for _, age := range []time.Duration{time.Hour, 72 * time.Hour} {
		if _, err := Load(context.Background(), exploitdata.Settings{MaxAge: age}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if got := scanners.FeedMaxAge(); got != age {
			t.Errorf("feed max age = %v, want %v", got, age)
		}
	}
}
