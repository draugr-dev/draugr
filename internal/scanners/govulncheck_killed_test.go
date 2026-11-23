package scanners

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// A govulncheck run the kernel kills, here the second module of a repository holding two, fails the
// job as loudly as before, and every go.mod the job was given is listed as unread with why, under
// the component's sca entry, where every other file a scanner did not read is listed. The other
// component's repository, whose runs finished, keeps its verdict and lists nothing.
func TestGovulncheckKilledNamesEveryModuleItLeftUnread(t *testing.T) {
	useGoVulnDB(t, noCopy)
	builtWith(t, "")
	orig := lookRuntime
	t.Cleanup(func() { lookRuntime = orig })
	lookRuntime = func(name string) (string, error) { return "/usr/bin/" + name, nil }

	dirs := map[string]string{
		"one": writeTree(t, map[string]string{
			"go.mod":         "module example.com/app\n\ngo 1.22\n",
			"main.go":        goMain,
			"server/go.mod":  "module example.com/server\n\ngo 1.22\n",
			"server/main.go": goMain,
		}),
		"two": writeTree(t, map[string]string{
			"go.mod":  "module example.com/worker\n\ngo 1.22\n",
			"main.go": goMain,
		}),
	}
	killedIn := filepath.Join(dirs["one"], "server")

	origExec := execArgvInDirWithEnv
	t.Cleanup(func() { execArgvInDirWithEnv = origExec })
	execArgvInDirWithEnv = func(ctx context.Context, dir string, argv, env []string) ([]byte, error) {
		mod := argv[slices.Index(argv, "-C")+1]
		if mod == killedIn {
			// A real process ended by SIGKILL, as the kernel ends one out of memory.
			return origExec(ctx, dir, []string{"sh", "-c", "kill -KILL $$"}, env)
		}
		return []byte(govulncheckRun(goModulePath(filepath.Join(mod, "go.mod")))), nil
	}

	s := NewGovulncheck().(repoScanner)
	s.cacheVersion = func(context.Context) string { return "govulncheck@v1.9.0" }
	s.checkout = checkoutOf(dirs)
	reg := engine.NewRegistry()
	reg.RegisterController(twoScannerSCA{scaController{scanner: govulncheckScanner}})
	reg.RegisterScanner(s)
	reg.RegisterScanner(manifestScanner{goMods: map[string][]string{
		"one": {"go.mod", "server/go.mod"},
		"two": {"go.mod"},
	}})
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "one"}}},
			{Name: "worker", Repositories: []saga.Repository{{URL: "two"}}},
		},
	}
	// Still a failure of the scan, naming the kill.
	res, err := engine.New(reg, engine.WithPrioritization(scanpolicy.PrioritizerWith(nil, nil))).Run(context.Background(), model)
	if err == nil || !strings.Contains(err.Error(), "was killed by SIGKILL") {
		t.Fatalf("run: %v, want the kill", err)
	}
	if errs := res.ScanErrors["sca"]; len(errs) != 1 || !strings.Contains(errs[0], "was killed by SIGKILL") {
		t.Fatalf("scan errors = %v, want govulncheck's kill under sca", res.ScanErrors)
	}

	var unread []string
	for _, cov := range res.Inputs {
		for _, u := range cov.Unread {
			unread = append(unread, cov.Component+" "+cov.Control+" "+u.Path+": "+u.Reason)
		}
	}
	slices.Sort(unread)
	reason := "govulncheck: was killed before it finished, most likely for lack of memory, so no Go module here was analyzed"
	want := []string{"api sca go.mod: " + reason, "api sca server/go.mod: " + reason}
	if !slices.Equal(unread, want) {
		t.Errorf("unread = %q, want %q", unread, want)
	}

	for _, r := range res.Controls["sca"].Report.Results {
		if r.Component == "api" && r.Reachability != nil {
			t.Errorf("api %s carries a verdict from a job that did not finish: %+v", r.Location.URI, r.Reachability)
		}
		if r.Component == "worker" && (r.Reachability == nil || r.Reachability.State != "reachable") {
			t.Errorf("worker %s lost its verdict: %+v", r.Location.URI, r.Reachability)
		}
	}
}

// A run that exits with an error after it started names the same files with a reason that does not
// guess at memory. A failure that is not a run of the tool, a refusal before it started or a
// canceled scan, names none, and the job fails as it always did.
func TestGovulncheckUnfinishedReasonFollowsTheFailure(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":         "module example.com/app\n\ngo 1.22\n",
		"main.go":        goMain,
		"server/go.mod":  "module example.com/server\n\ngo 1.22\n",
		"server/main.go": goMain,
	})
	exitErr := exec.Command("sh", "-c", "exit 3").Run()
	got := govulncheckUnfinished(dir, fmt.Errorf("run govulncheck: %w", exitErr))
	if len(got) != 2 || got[0].Path != "go.mod" || got[1].Path != "server/go.mod" {
		t.Fatalf("inputs = %+v, want go.mod and server/go.mod", got)
	}
	for _, in := range got {
		if in.Unread != "govulncheck: did not finish, so no Go module here was analyzed" || !in.Analysis {
			t.Errorf("%s: unread %q, analysis %v", in.Path, in.Unread, in.Analysis)
		}
	}
	if got := govulncheckUnfinished(writeTree(t, map[string]string{"README.md": "x\n"}), exitErr); len(got) != 0 {
		t.Errorf("a tree with no module named %+v", got)
	}
	for _, err := range []error{context.Canceled, errors.New("govulncheck was built with go1.26.10 and cannot load go.mod")} {
		if got := govulncheckUnfinished(dir, err); len(got) != 0 {
			t.Errorf("%v: named %+v, want nothing for a failure that is not a run of the tool", err, got)
		}
	}
}
