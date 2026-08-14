package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDetect(t *testing.T) {
	tool := Tool{Binary: "trivy", VersionArgs: []string{"--version"}, InstallHint: "hint"}

	tests := []struct {
		name        string
		tool        Tool
		lookPath    LookPathFunc
		run         RunFunc
		wantFound   bool
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "found with parsed version",
			tool:        tool,
			lookPath:    func(string) (string, error) { return "/usr/bin/trivy", nil },
			run:         func(context.Context, []string) ([]byte, error) { return []byte("Version: 0.58.1\n"), nil },
			wantFound:   true,
			wantVersion: "0.58.1",
		},
		{
			name:      "missing on PATH",
			tool:      tool,
			lookPath:  func(string) (string, error) { return "", errors.New("not found") },
			run:       func(context.Context, []string) ([]byte, error) { return nil, errors.New("unreached") },
			wantFound: false,
		},
		{
			name:        "found, no version args",
			tool:        Tool{Binary: "git"},
			lookPath:    func(string) (string, error) { return "/usr/bin/git", nil },
			wantFound:   true,
			wantVersion: "",
		},
		{
			name:      "found, version probe errors",
			tool:      tool,
			lookPath:  func(string) (string, error) { return "/usr/bin/trivy", nil },
			run:       func(context.Context, []string) ([]byte, error) { return nil, errors.New("boom") },
			wantFound: true,
			wantErr:   true,
		},
		{
			name:        "found, version unparseable",
			tool:        tool,
			lookPath:    func(string) (string, error) { return "/usr/bin/trivy", nil },
			run:         func(context.Context, []string) ([]byte, error) { return []byte("no digits here"), nil },
			wantFound:   true,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := Detect(context.Background(), tt.tool, tt.lookPath, tt.run)
			if st.Found != tt.wantFound {
				t.Errorf("Found = %v, want %v", st.Found, tt.wantFound)
			}
			if st.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", st.Version, tt.wantVersion)
			}
			if (st.Err != nil) != tt.wantErr {
				t.Errorf("Err = %v, wantErr %v", st.Err, tt.wantErr)
			}
		})
	}
}

func TestDetectDefaultsRunGit(t *testing.T) {
	// With nil lookPath/run, Detect uses the real environment. git is present in CI and
	// dev; assert we at least resolve it (version parsing is covered above with fakes).
	st := Detect(context.Background(), Catalog()["git"], nil, nil)
	if !st.Found {
		t.Skip("git not on PATH in this environment")
	}
	if st.Path == "" {
		t.Error("found git but Path is empty")
	}
}

func TestCatalogAndAll(t *testing.T) {
	cat := Catalog()
	for _, bin := range []string{"trivy", "gitleaks", "semgrep", "git"} {
		tl, ok := cat[bin]
		if !ok {
			t.Fatalf("catalog missing %q", bin)
		}
		if tl.Binary != bin {
			t.Errorf("%q: Binary = %q", bin, tl.Binary)
		}
		if tl.InstallHint == "" {
			t.Errorf("%q: empty InstallHint", bin)
		}
	}

	all := All()
	if len(all) != len(cat) {
		t.Fatalf("All() len = %d, want %d", len(all), len(cat))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Binary > all[i].Binary {
			t.Errorf("All() not sorted: %q before %q", all[i-1].Binary, all[i].Binary)
		}
	}
}

func TestGrypeDBOK(t *testing.T) {
	// Grype's own verdict is the only one worth reading: a database file can exist, be readable,
	// and still be one Grype will refuse to scan with because it is too old or its schema belongs
	// to a version of the tool that is no longer served.
	cases := []struct {
		name, out  string
		wantOK     bool
		wantDetail string
	}{
		{
			name:       "usable",
			out:        `{"schemaVersion":"v6.1.9","built":"2026-08-14T06:39:10Z","valid":true}`,
			wantOK:     true,
			wantDetail: "built 2026-08-14T06:39:10Z",
		},
		{
			name: "present but not valid",
			out:  `{"schemaVersion":"v5.0.0","built":"2026-01-01T00:00:00Z","valid":false}`,
		},
		{name: "no database", out: `{"path":"/x/vulnerability.db","valid":false,"error":"database does not exist"}`},
		{name: "not json", out: "database does not exist"},
		{name: "empty", out: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, detail := GrypeDBOK([]byte(c.out))
			if ok != c.wantOK || detail != c.wantDetail {
				t.Errorf("GrypeDBOK() = (%v, %q), want (%v, %q)", ok, detail, c.wantOK, c.wantDetail)
			}
		})
	}
}

func TestNucleiTemplatesOK(t *testing.T) {
	// Nuclei exits 0 whether or not it has templates, printing the same line with the version
	// blank when it has none. The blank is the only signal there is.
	cases := []struct {
		name, out  string
		wantOK     bool
		wantDetail string
	}{
		{
			name:       "installed",
			out:        "[INF] Public nuclei-templates version: v10.4.6 (/home/u/nuclei-templates)\n",
			wantOK:     true,
			wantDetail: "v10.4.6 (/home/u/nuclei-templates)",
		},
		{
			name:       "absent",
			out:        "[INF] Public nuclei-templates version:  (/home/u/nuclei-templates)\n",
			wantOK:     false,
			wantDetail: "/home/u/nuclei-templates",
		},
		{name: "unrecognised output", out: "something else entirely"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, detail := NucleiTemplatesOK([]byte(c.out))
			if ok != c.wantOK || detail != c.wantDetail {
				t.Errorf("got (%v, %q), want (%v, %q)", ok, detail, c.wantOK, c.wantDetail)
			}
		})
	}
}

func TestDetectProbesForAToolsData(t *testing.T) {
	// Being on PATH is not the same as being able to run: Nuclei without templates exits
	// non-zero at scan time complaining about the descriptor.
	tool := Tool{
		Binary:      "nuclei",
		VersionArgs: []string{"-version"},
		DataArgs:    []string{"-templates-version"},
		DataOK:      NucleiTemplatesOK,
	}
	run := func(_ context.Context, argv []string) ([]byte, error) {
		if argv[1] == "-templates-version" {
			return []byte("Public nuclei-templates version:  (/t)\n"), nil
		}
		return []byte("3.11.0"), nil
	}
	st := Detect(context.Background(), tool, func(string) (string, error) { return "/bin/nuclei", nil }, run)
	if !st.Found {
		t.Fatal("the binary is there")
	}
	if !st.DataChecked || st.DataFound {
		t.Errorf("data should be checked and absent, got checked=%v found=%v", st.DataChecked, st.DataFound)
	}
}

func TestDetectSkipsTheDataProbeWhenNoneIsDeclared(t *testing.T) {
	tool := Tool{Binary: "trivy", VersionArgs: []string{"--version"}}
	run := func(context.Context, []string) ([]byte, error) { return []byte("0.69.3"), nil }
	st := Detect(context.Background(), tool, func(string) (string, error) { return "/bin/trivy", nil }, run)
	if st.DataChecked {
		t.Error("a tool with no data files must not be probed for any")
	}
}

func TestDetectFindsDataOnDisk(t *testing.T) {
	// kube-bench only admits its cfg/ is missing by attempting a benchmark, and doctor must not
	// run a scan to find out whether a scan would work.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := Tool{
		Binary:      "kube-bench",
		VersionArgs: []string{"version"},
		DataFiles:   []string{filepath.Join(dir, "nope.yaml"), cfg},
	}
	run := func(context.Context, []string) ([]byte, error) { return []byte("0.15.6"), nil }
	st := Detect(context.Background(), tool, func(string) (string, error) { return "/bin/kb", nil }, run)
	if !st.DataChecked || !st.DataFound {
		t.Fatalf("checked=%v found=%v — the second path exists", st.DataChecked, st.DataFound)
	}
	if st.DataDetail != cfg {
		t.Errorf("detail = %q, want the path that matched", st.DataDetail)
	}
}

func TestDetectReportsDataMissingOnDisk(t *testing.T) {
	tool := Tool{
		Binary:      "kube-bench",
		VersionArgs: []string{"version"},
		DataFiles:   []string{filepath.Join(t.TempDir(), "absent.yaml")},
	}
	run := func(context.Context, []string) ([]byte, error) { return []byte("0.15.6"), nil }
	st := Detect(context.Background(), tool, func(string) (string, error) { return "/bin/kb", nil }, run)
	if !st.DataChecked || st.DataFound {
		t.Errorf("checked=%v found=%v — nothing is there", st.DataChecked, st.DataFound)
	}
}

func TestExpandHomeResolvesATilde(t *testing.T) {
	// A catalog entry names a path under the user's home without knowing whose home it is.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory here")
	}
	if got := expandHome("~/x/y"); got != filepath.Join(home, "x", "y") {
		t.Errorf("got %q", got)
	}
	if got := expandHome("/etc/absolute"); got != "/etc/absolute" {
		t.Errorf("an absolute path is left alone, got %q", got)
	}
}

func TestDetectFindsDataBesideTheBinary(t *testing.T) {
	// A tarball extract leaves cfg/ next to the binary. A fixed list of system paths would miss
	// the commonest install and report a working tool as broken.
	dir := t.TempDir()
	bin := filepath.Join(dir, "kube-bench")
	if err := os.WriteFile(bin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "cfg"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cfg", "config.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tool := Tool{
		Binary:      "kube-bench",
		VersionArgs: []string{"version"},
		DataFiles:   []string{"/nowhere/config.yaml", "{bindir}/cfg/config.yaml"},
	}
	run := func(context.Context, []string) ([]byte, error) { return []byte("0.15.6"), nil }
	st := Detect(context.Background(), tool, func(string) (string, error) { return bin, nil }, run)
	if !st.DataFound {
		t.Errorf("cfg beside the binary should count: %+v", st)
	}
}
