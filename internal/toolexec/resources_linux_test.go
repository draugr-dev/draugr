package toolexec

import (
	"os"
	"path/filepath"
	"testing"
)

// cgroupTree writes a cgroup v2 membership file naming group, and a memory.max for each directory
// in limits, under a fresh root. It returns the membership file and the root.
func cgroupTree(t *testing.T, membership string, limits map[string]string) (string, string) {
	t.Helper()
	root := t.TempDir()
	for dir, v := range limits {
		d := filepath.Join(root, dir)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "memory.max"), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	self := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(self, []byte(membership), 0o600); err != nil {
		t.Fatal(err)
	}
	return self, root
}

func TestCgroupMemoryLimitIsTheLowestOnThePathToTheRoot(t *testing.T) {
	cases := []struct {
		name       string
		membership string
		limits     map[string]string
		want       uint64
	}{
		{"a limit on the scope", "0::/user.slice/run.scope\n",
			map[string]string{"user.slice": "max", "user.slice/run.scope": "1073741824"}, 1 << 30},
		{"a lower limit on a parent holds the child", "0::/a/b\n",
			map[string]string{"a": "2147483648", "a/b": "4294967296"}, 2 << 30},
		{"no limit anywhere", "0::/a/b\n",
			map[string]string{"a": "max", "a/b": "max"}, 0},
		{"no memory.max files", "0::/a\n", nil, 0},
		{"the root group", "0::/\n", map[string]string{".": "3221225472"}, 3 << 30},
		{"cgroup v1 only", "12:memory:/a\n", map[string]string{"a": "1073741824"}, 0},
		{"an unreadable limit", "0::/a\n", map[string]string{"a": "lots"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			self, root := cgroupTree(t, c.membership, c.limits)
			if got := cgroupMemoryLimit(self, root); got != c.want {
				t.Errorf("cgroupMemoryLimit = %d, want %d", got, c.want)
			}
		})
	}
	if got := cgroupMemoryLimit(filepath.Join(t.TempDir(), "absent"), t.TempDir()); got != 0 {
		t.Errorf("with no membership file, cgroupMemoryLimit = %d, want 0", got)
	}
}

func TestLowerOfTreatsZeroAsUnknown(t *testing.T) {
	for _, c := range []struct{ a, b, want uint64 }{
		{0, 0, 0}, {0, 5, 5}, {5, 0, 5}, {3, 5, 3}, {5, 3, 3},
	} {
		if got := lowerOf(c.a, c.b); got != c.want {
			t.Errorf("lowerOf(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestTotalMemoryIsWithinTheMachines(t *testing.T) {
	if totalMemory() == 0 {
		t.Fatal("totalMemory() = 0 on Linux")
	}
}
