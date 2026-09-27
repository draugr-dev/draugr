package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/preflight"
	"github.com/draugr-dev/draugr/pkg/engine"
)

// Two components share one monorepo at different paths; a third reads its own repository and an
// image.
const doctorSagaReach = `project: app
release:
  version: "1.0"
config:
  controllers:
    sca:
      enabled: true
    images:
      enabled: true
components:
  - name: web
    repositories:
      - url: https://github.com/acme/mono.git
        revision: main
        paths: [services/web]
  - name: api
    repositories:
      - url: https://github.com/acme/mono.git
        revision: main
        paths: [services/api]
  - name: worker
    repositories:
      - url: https://github.com/acme/worker.git
    images:
      - image: ghcr.io/acme/worker:1
`

// reachProbes answers every check without leaving the machine, and counts what it was asked.
// Targets are checked concurrently, so the count is taken under a lock.
func reachProbes(calls map[string]int) preflight.Probes {
	var mu sync.Mutex
	count := func(k string) {
		mu.Lock()
		defer mu.Unlock()
		calls[k]++
	}
	return preflight.Probes{
		Revision: func(_ context.Context, url, _ string) (string, error) {
			count(url)
			if strings.Contains(url, "worker") {
				return "", errors.New("remote: repository not found")
			}
			return "0123456789abcdef0123456789abcdef01234567", nil
		},
		Paths: func(_ context.Context, _, rev string, paths []string) (string, error) {
			count(strings.Join(paths, ","))
			return rev, nil
		},
		Image: func(_ context.Context, ref string, _ bool) (string, error) {
			count(ref)
			return "manifest readable", nil
		},
	}
}

func TestRunDoctorChecksTargets(t *testing.T) {
	calls := map[string]int{}
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, doctorSagaReach),
		doctorRun{reach: true, probes: reachProbes(calls)}, fakeDetect("trivy", "git"), nil)
	if err == nil || err.Error() != "1 target check failed" {
		t.Fatalf("err = %v, want one failed target check", err)
	}
	got := out.String()
	for _, want := range []string{
		"TARGETS",
		"https://github.com/acme/mono.git@main", "resolves to 0123456789ab",
		"services/web", "services/api", "in the tree at 0123456789ab",
		"https://github.com/acme/worker.git", "✗ remote: repository not found",
		"ghcr.io/acme/worker:1", "✓ manifest readable",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "All required tools present") {
		t.Errorf("a failed target check still reported success:\n%s", got)
	}
	// Two components, one repository: resolved once, each scope checked once.
	if calls["https://github.com/acme/mono.git"] != 1 || calls["services/web"] != 1 || calls["services/api"] != 1 {
		t.Errorf("calls = %v", calls)
	}
}

func TestRunDoctorTargetsScopedAndJSON(t *testing.T) {
	calls := map[string]int{}
	var out bytes.Buffer
	scope := engine.Scope{Components: []string{"web", "api"}}
	err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, doctorSagaReach),
		doctorRun{json: true, reach: true, scope: scope, probes: reachProbes(calls)}, fakeDetect("trivy", "git"), nil)
	if err != nil {
		t.Fatalf("the scoped components all pass: %v", err)
	}
	var rep struct {
		Targets []preflight.Check `json:"targets"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(rep.Targets) != 3 {
		t.Fatalf("targets = %+v, want the monorepo and its two scopes", rep.Targets)
	}
	for _, c := range rep.Targets {
		if c.Status != preflight.Passed || strings.Contains(c.Target, "worker") {
			t.Errorf("target %+v", c)
		}
	}
	if calls["https://github.com/acme/worker.git"] != 0 || calls["ghcr.io/acme/worker:1"] != 0 {
		t.Errorf("a component outside --components was checked: %v", calls)
	}
}

func TestRunDoctorTargetsOffline(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, doctorSagaReach),
		doctorRun{reach: true, offline: true, probes: reachProbes(map[string]int{})}, fakeDetect("trivy", "git"), nil)
	if err != nil {
		t.Fatalf("not checked is not a failure: %v", err)
	}
	if !strings.Contains(out.String(), "not checked: --offline") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestRunDoctorTargetsBadScope(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, doctorSagaReach),
		doctorRun{reach: true, scope: engine.Scope{Components: []string{"nope"}}, probes: reachProbes(map[string]int{})},
		fakeDetect("trivy", "git"), nil)
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("an unknown component: %v", err)
	}
}
