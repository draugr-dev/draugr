package sealed

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A stored base carries neither the run's work directory nor its commits, and restoring it for
// another run puts that run's back.
func TestStoreBaseRoundTrips(t *testing.T) {
	commits := []string{strings.Repeat("a", 40), strings.Repeat("b", 40)}
	raw := []byte(`{"repository":"/tmp/w1/scenario","revision":"` + commits[0] + `","parent":"` + commits[1] + `"}`)
	stored := StoreBase(raw, "/tmp/w1", commits)
	if string(stored) != `{"repository":"<work>/scenario","revision":"<commit:0>","parent":"<commit:1>"}` {
		t.Fatalf("stored = %s", stored)
	}
	other := []string{strings.Repeat("c", 40), strings.Repeat("d", 40)}
	if got := string(RestoreBase(stored, "/tmp/w2", other)); got != `{"repository":"/tmp/w2/scenario","revision":"`+other[0]+`","parent":"`+other[1]+`"}` {
		t.Errorf("restored = %s", got)
	}
	unread := string(UnreadBase(stored, "/tmp/w2", other))
	if strings.Contains(unread, other[0]) || !strings.Contains(unread, `"revision":"`+strings.Repeat("0", 39)+`1"`) {
		t.Errorf("unread = %s", unread)
	}
}

func TestBaseRelease(t *testing.T) {
	if got, err := BaseRelease([]byte(`{"runs":[{"tool":{"driver":{"name":"Draugr","version":"0.189.3"}}}]}`)); err != nil || got != "0.189.3" {
		t.Errorf("release = %q, %v", got, err)
	}
	for _, raw := range []string{`{"runs":[]}`, `{"runs":[{"tool":{"driver":{"name":"Draugr"}}}]}`, `not json`} {
		if _, err := BaseRelease([]byte(raw)); err == nil {
			t.Errorf("%s: no error", raw)
		}
	}
}

// A scenario's base comes from one of the two newest releases in CHANGELOG.md. A release pull
// request promotes the changelog, so the second release after a base was written fails here until
// the base is written again by the newer of the two:
//
//	DRAUGR_BIN=<the release's draugr> go test -tags integration -run 'TestSealedScenarios/<name>' \
//	  ./test/integration/ -write-sealed-base
//
// and every other pull request passes. A base older than that compares the head with a release no
// pipeline upgrading today still runs. The file must also be from the release it claims.
func TestEachSealedBaseIsFromARecentRelease(t *testing.T) {
	changelog, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	var recent []string
	for _, m := range regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindAllSubmatch(changelog, 2) {
		recent = append(recent, string(m[1]))
	}
	if len(recent) == 0 {
		t.Fatal("CHANGELOG.md names no release")
	}
	dirs, err := filepath.Glob("../integration/testdata/ecosystems/*/expected.yaml")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	bases := 0
	for _, d := range dirs {
		s, err := LoadScenario(filepath.Dir(d))
		if err != nil {
			t.Fatal(err)
		}
		if s.Expected.Base == nil {
			continue
		}
		bases++
		if !slices.Contains(recent, s.Expected.Base.Release) {
			t.Errorf("%s: base.release is %s, and the newest releases are %s: write the base again with the newest release",
				s.Name, s.Expected.Base.Release, strings.Join(recent, " and "))
		}
		raw, err := os.ReadFile(filepath.Join(s.Dir, BaseFile)) // #nosec G304 -- a checked-in scenario file
		if err != nil {
			t.Errorf("%s: %v", s.Name, err)
			continue
		}
		if got, err := BaseRelease(raw); err != nil || got != s.Expected.Base.Release {
			t.Errorf("%s: %s is from %q (%v), and base.release says %s", s.Name, BaseFile, got, err, s.Expected.Base.Release)
		}
	}
	if bases == 0 {
		t.Error("no scenario compares with a base from an earlier release")
	}
}
