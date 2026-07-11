package scanners

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

func TestTrivyInfo(t *testing.T) {
	info := NewTrivy().Info()
	if info.Name != "trivy" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "images" {
		t.Errorf("controls = %v", info.Controls)
	}
}

func TestTrivyArgv(t *testing.T) {
	argv, err := trivyArgv(plugin.ImageTarget{Ref: "repo/app:1.0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"trivy", "image", "--quiet", "--format", "sarif", "repo/app:1.0"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

func TestTrivyArgvPrefersRefThenDigest(t *testing.T) {
	argv, _ := trivyArgv(plugin.ImageTarget{Digest: "sha256:abc"}, nil)
	if argv[len(argv)-1] != "sha256:abc" {
		t.Errorf("should fall back to digest, got %v", argv)
	}
}

func TestTrivyArgvErrors(t *testing.T) {
	if _, err := trivyArgv(plugin.RepositoryTarget{URL: "u"}, nil); err == nil {
		t.Error("non-image target should error")
	}
	if _, err := trivyArgv(plugin.ImageTarget{}, nil); err == nil {
		t.Error("image target with no ref/digest should error")
	}
}

func TestTrivyFSInfo(t *testing.T) {
	info := NewTrivyFS().Info()
	if info.Name != "trivy-fs" {
		t.Errorf("name = %q", info.Name)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "sca" {
		t.Errorf("controls = %v", info.Controls)
	}
}

func TestTrivyFSArgs(t *testing.T) {
	argv := trivyFSArgs("/work/repo", nil)
	want := []string{"trivy", "fs", "--quiet", "--scanners", "vuln", "--format", "sarif", "/work/repo"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v", argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}
