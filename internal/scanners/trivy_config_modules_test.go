package scanners

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// trivyModulesLog is what Trivy 0.74.0 wrote to stderr scanning a tree whose infra/prod/main.tf
// calls a registry module, a git module and a local one that calls a registry module itself, with
// no network, the cause fields shortened.
const trivyModulesLog = "2026-09-25T21:46:38-05:00\tINFO\t[misconfig] Misconfiguration scanning is enabled\n" +
	"2026-09-25T21:46:39-05:00\tINFO\t[terraform scanner] Scanning root module\tfile_path=\"infra/prod\"\n" +
	"2026-09-25T21:46:39-05:00\tERROR\t[terraform evaluator] Failed to load module. Maybe try 'terraform init'?\tmodule=\"root\" loc=\"infra/prod/main.tf:7-9\" err=\"failed to download: … transport 'https' not allowed\\n\"\n" +
	"2026-09-25T21:46:39-05:00\tERROR\t[terraform evaluator] Failed to load module. Maybe try 'terraform init'?\tmodule=\"root\" loc=\"infra/prod/main.tf:1-5\" err=\"Get \\\"https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/versions\\\": proxyconnect tcp: dial tcp 127.0.0.1:0: connect: connection refused\"\n" +
	"2026-09-25T21:46:39-05:00\tERROR\t[terraform evaluator] Failed to load module. Maybe try 'terraform init'?\tmodule=\"root\" module=\"local\" loc=\"infra/mod/main.tf:1-4\" err=\"Get \\\"https://registry.terraform.io/v1/modules/terraform-aws-modules/security-group/aws/versions\\\": proxyconnect tcp: dial tcp 127.0.0.1:0: connect: connection refused\"\n" +
	"2026-09-25T21:46:39-05:00\tINFO\tDetected config files\tnum=2\n"

const prodMainTF = `module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
  name    = "prod"
}

module "eks" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-eks.git?ref=v20.8.5"
}
`

const modMainTF = `module "sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"
}
`

// Each module Trivy could not load reaches the report as an unread input, per file and named by its
// block, over two repositories whose trees differ, so neither is reported with the other's modules.
func TestAModuleTrivyCouldNotLoadIsReportedUnread(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"

	trees := map[string]struct {
		files map[string]string
		log   string
		want  []sarif.Input
	}{
		"infra-a": {
			files: map[string]string{"infra/prod/main.tf": prodMainTF, "infra/mod/main.tf": modMainTF},
			log:   trivyModulesLog,
			want: []sarif.Input{
				{Scanner: "trivy-config", Repository: "infra-a", Path: "infra/mod/main.tf", Unread: `module "sg" not loaded`},
				{Scanner: "trivy-config", Repository: "infra-a", Path: "infra/prod/main.tf", Unread: `modules "vpc", "eks" not loaded`},
			},
		},
		"infra-b": {
			files: map[string]string{"infra/mod/main.tf": modMainTF},
			log:   "x\tERROR\t[terraform evaluator] Failed to load module. Maybe try 'terraform init'?\tmodule=\"root\" loc=\"infra/mod/main.tf:1-4\" err=\"…\"\n",
			want:  []sarif.Input{{Scanner: "trivy-config", Repository: "infra-b", Path: "infra/mod/main.tf", Unread: `module "sg" not loaded`}},
		},
	}
	for repo, tree := range trees {
		dir := writeTree(t, tree.files)
		var calls []string
		s := NewTrivyConfig().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		fake := fakeTrivyMisconfig(t, &calls)
		s.runLogged = trivyConfigRun(func(ctx context.Context, d string, argv []string) ([]byte, []byte, error) {
			out, _, err := fake(ctx, d, argv)
			if argv[1] == "fs" {
				return out, []byte(tree.log), err
			}
			return out, []byte("convert logs nothing that is read"), err
		})
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rep.Inputs, tree.want) {
			t.Errorf("%s: inputs\n%+v\nwant\n%+v", repo, rep.Inputs, tree.want)
		}
		if len(rep.Results) != 3 {
			t.Errorf("%s: %d results, want the findings as they were", repo, len(rep.Results))
		}
	}
}

// A scan that loaded every module reports no inputs, so the iac control is not listed as reading
// anything either way.
func TestAScanThatLoadedEveryModuleReportsNoInputs(t *testing.T) {
	if got := trivyUnloadedModules([]byte("x\tINFO\tDetected config files\tnum=2\n"), t.TempDir()); len(got) != 0 {
		t.Errorf("inputs %+v, want none", got)
	}
}

func TestTrivyUnloadedModulesNamesWhatItCan(t *testing.T) {
	dir := writeTree(t, map[string]string{"a.tf": "resource \"x\" \"y\" {}\n"})
	line := func(loc string) string {
		return "x\tERROR\t[terraform evaluator] Failed to load module. Maybe try 'terraform init'?\tmodule=\"root\" " + loc + " err=\"…\"\n"
	}
	for name, tc := range map[string]struct {
		log  string
		want []sarif.Input
	}{
		"a line that opens no module block": {line(`loc="a.tf:1-1"`), []sarif.Input{{Path: "a.tf", Unread: "module at line 1 not loaded"}}},
		"a file that is not in the tree":    {line(`loc="gone.tf:3-4"`), []sarif.Input{{Path: "gone.tf", Unread: "module at line 3 not loaded"}}},
		"a path outside the tree":           {line(`loc="../x.tf:3-4"`), []sarif.Input{{Path: "../x.tf", Unread: "module at line 3 not loaded"}}},
		"a path under the checkout":         {line(`loc="` + dir + `/a.tf:1-1"`), []sarif.Input{{Path: "a.tf", Unread: "module at line 1 not loaded"}}},
		"no location":                       {line(""), []sarif.Input{{Path: ".", Unread: "module block not loaded"}}},
		"the same block twice":              {line(`loc="gone.tf:3-4"`) + line(`loc="gone.tf:3-4"`), []sarif.Input{{Path: "gone.tf", Unread: "module at line 3 not loaded"}}},
	} {
		if got := trivyUnloadedModules([]byte(tc.log), dir); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

// Offline, the scan runs where every module fetch fails at once. Online, it runs in the caller's
// environment unchanged.
func TestOfflineTrivyConfigCannotFetchModules(t *testing.T) {
	prior := execWithStderr
	t.Cleanup(func() { execWithStderr = prior; netpolicy.SetOffline(false) })
	var env []string
	execWithStderr = func(_ context.Context, _ string, _ []string, e []string) ([]byte, []byte, error) {
		env = e
		return []byte(trivyMisconfigSARIF), nil, nil
	}
	for _, offline := range []bool{true, false} {
		netpolicy.SetOffline(offline)
		env = nil
		if _, _, err := trivyConfigExec(t.Context(), t.TempDir(), []string{"trivy", "config"}); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"HTTPS_PROXY=http://127.0.0.1:0", "http_proxy=http://127.0.0.1:0", "NO_PROXY=", "GIT_ALLOW_PROTOCOL=file"} {
			if slices.Contains(env, want) != offline {
				t.Errorf("offline %v: env %v, %s present %v", offline, env, want, !offline)
			}
		}
	}
}

// The two logs are what Trivy 0.74.0 wrote at --debug, reduced to the lines about module calls.
//
// trivy-module-calls.log is one tree of three root modules. infra/a calls 33 local modules, the
// last of them misconfigured, and a registry module that cannot be fetched offline. infra/b calls
// three, one of them with count = 3, and finishes. nested calls one module, which calls 33.
//
// trivy-module-calls-root.log is a tree whose own directory is the root module, calling 33.
func readTrivyLog(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- a fixture under testdata, named by the test
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// segment is the part of a log from the line scanning root module dir to the next root module.
func segment(log []byte, dir string) []byte {
	var b strings.Builder
	in := false
	for line := range strings.Lines(string(log)) {
		if strings.Contains(line, "Scanning root module") {
			in = strings.Contains(line, `file_path="`+dir+`"`)
		}
		if in {
			b.WriteString(line)
		}
	}
	return []byte(b.String())
}

// A root module calling more modules than Trivy evaluated reaches the report unread, with its
// directory and both counts, over two repositories whose roots differ, so neither is reported with
// the other's counts. A root that finished is not reported, and the module Trivy could not load is
// still reported against its own file beside the root's line.
func TestModuleCallsTrivyDidNotEvaluateAreReportedUnread(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.74.0;db@2026-07-15T00:56:58Z"

	trees := map[string]struct {
		files map[string]string
		log   []byte
		want  []sarif.Input
	}{
		"infra-a": {
			files: map[string]string{"infra/a/remote.tf": "module \"vpc\" {\n  source = \"terraform-aws-modules/vpc/aws\"\n}\n"},
			log:   readTrivyLog(t, "trivy-module-calls.log"),
			want: []sarif.Input{
				{Scanner: "trivy-config", Repository: "infra-a", Path: "infra/a",
					Unread: `32 of 34 module calls checked; "zbad" skipped`},
				{Scanner: "trivy-config", Repository: "infra-a", Path: "infra/a/remote.tf", Unread: `module "vpc" not loaded`},
				{Scanner: "trivy-config", Repository: "infra-a", Path: "nested",
					Unread: `32 of 33 module calls in module.wrap checked; "zbad" skipped`},
			},
		},
		"infra-b": {
			log: readTrivyLog(t, "trivy-module-calls-root.log"),
			want: []sarif.Input{{Scanner: "trivy-config", Repository: "infra-b", Path: ".",
				Unread: `32 of 33 module calls checked; "zbad" skipped`}},
		},
		"infra-c": {
			log: segment(readTrivyLog(t, "trivy-module-calls.log"), "infra/b"),
		},
	}
	for repo, tree := range trees {
		dir := writeTree(t, tree.files)
		var calls []string
		s := NewTrivyConfig().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		fake := fakeTrivyMisconfig(t, &calls)
		s.runLogged = trivyConfigRun(func(ctx context.Context, d string, argv []string) ([]byte, []byte, error) {
			out, _, err := fake(ctx, d, argv)
			if argv[1] == "fs" {
				if !slices.Contains(argv, "--debug") {
					t.Errorf("%s: %v, want --debug, the level that logs module calls", repo, argv)
				}
				return out, tree.log, err
			}
			return out, nil, err
		})
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rep.Inputs, tree.want) {
			t.Errorf("%s: inputs\n%+v\nwant\n%+v", repo, rep.Inputs, tree.want)
		}
	}
}

func TestTrivyUnevaluatedModulesReadsOnlyALoopThatRanOut(t *testing.T) {
	dir := t.TempDir()
	line := func(msg, fields string) string {
		return "x\tDEBUG\t[terraform evaluator] " + msg + "\t" + fields + "\n"
	}
	root := func(path string) string {
		return "x\tINFO\t[terraform scanner] Scanning root module\tfile_path=\"" + path + "\"\n"
	}
	loaded := func(names ...string) string {
		var b strings.Builder
		for _, n := range names {
			b.WriteString(line("Loaded module", `module="root" name="`+n+`" file_path="m"`))
		}
		return b.String()
	}
	evaluated := func(names ...string) string {
		var b strings.Builder
		for _, n := range names {
			b.WriteString(line("Evaluating submodule", `module="root" name="`+n+`"`))
		}
		return b.String()
	}
	started := line("Starting submodules evaluation...", `module="root"`)
	ended := line("Starting post-submodule evaluation...", `module="root"`)
	finished := line("All submodules are evaluated", `module="root" loop=3`)
	for name, tc := range map[string]struct {
		log  string
		want []sarif.Input
	}{
		"every call evaluated in the last round": {root("a") + loaded("x", "y") + started + evaluated("x", "y") + ended, nil},
		"a loop that finished":                   {root("a") + loaded("x", "y") + started + evaluated("x") + finished + ended, nil},
		"a loop that never ended":                {root("a") + loaded("x", "y") + started + evaluated("x"), nil},
		"no root line": {loaded("x", "y") + started + evaluated("x") + ended,
			[]sarif.Input{{Path: ".", Unread: `1 of 2 module calls checked; "y" skipped`}}},
		"several left, one loaded twice": {root("a") + loaded("x", "y", "z", "y") + started + evaluated("x") + ended,
			[]sarif.Input{{Path: "a", Unread: `1 of 3 module calls checked; "y", "z" skipped`}}},
		"a root named by its absolute path": {root(dir+"/infra/a") + loaded("x", "y") + started + evaluated("x") + ended,
			[]sarif.Input{{Path: "infra/a", Unread: `1 of 2 module calls checked; "y" skipped`}}},
		"a loop that ran out in a module two calls down": {root("a") +
			line("Loaded module", `module="root" module="app" module="db" name="x" file_path="m"`) +
			line("Loaded module", `module="root" module="app" module="db" name="y" file_path="m"`) +
			line("Starting submodules evaluation...", `module="root" module="app" module="db"`) +
			line("Evaluating submodule", `module="root" module="app" module="db" name="x"`) +
			line("Starting post-submodule evaluation...", `module="root" module="app" module="db"`),
			[]sarif.Input{{Path: "a", Unread: `1 of 2 module calls in module.app.module.db checked; "y" skipped`}}},
	} {
		if got := trivyUnevaluatedModules([]byte(tc.log), dir); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

// A root module that is the scanned directory shares its path with a module Trivy could not place,
// and the two reasons arrive on one input rather than one replacing the other.
func TestTwoReasonsForOnePathAreKeptTogether(t *testing.T) {
	log := readTrivyLog(t, "trivy-module-calls-root.log")
	log = append(log, "x\tERROR\t[terraform evaluator] Failed to load module. Maybe try 'terraform init'?\tmodule=\"root\" err=\"…\"\n"...)
	out, unread, err := trivyConfigRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return []byte(trivyMisconfigSARIF), log, nil
	})(context.Background(), t.TempDir(), []string{"trivy", "config", "--debug", "/tree"})
	if err != nil || string(out) != trivyMisconfigSARIF {
		t.Fatalf("out %q err %v", out, err)
	}
	want := []sarif.Input{{Path: ".",
		Unread: `module block not loaded, 32 of 34 module calls checked; "zbad" skipped`}}
	if !slices.Equal(unread, want) {
		t.Errorf("inputs %+v, want %+v", unread, want)
	}
}

// At debug level Trivy logs a module it did not find in `.terraform/modules` before fetching it,
// and that module was loaded.
func TestAModuleTrivyFetchedAfterMissingTheCacheIsNotUnread(t *testing.T) {
	log := "x\tDEBUG\t[terraform evaluator] Failed to load module from .terraform cache\tmodule=\"root\" module_source=\"./m\" err=\"…\"\n"
	if got := trivyUnloadedModules([]byte(log), t.TempDir()); len(got) != 0 {
		t.Errorf("inputs %+v, want none", got)
	}
}

func TestTrivyLogEntry(t *testing.T) {
	for line, want := range map[string]struct {
		msg    string
		fields [][2]string
	}{
		"no fields":              {"", nil},
		"x\tINFO\tplain message": {"plain message", nil},
		"x\tINFO\t[c] message\ta=\"b \\\"c\\\"\" n=3": {"message", [][2]string{{"a", `b "c"`}, {"n", "3"}}},
		"x\tINFO\t[unclosed message\tk=\"bad\\q\"":    {"[unclosed message", [][2]string{{"k", `"bad\q"`}}},
	} {
		msg, fields := trivyLogEntry(line)
		if msg != want.msg || !slices.Equal(fields, want.fields) {
			t.Errorf("%q: %q %v, want %q %v", line, msg, fields, want.msg, want.fields)
		}
	}
}
