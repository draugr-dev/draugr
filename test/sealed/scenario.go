package sealed

import (
	"crypto/rand"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FixtureSuffix marks a dependency manifest stored under another name. A requirements.txt,
// go.mod or package-lock.json anywhere in this repository is read by the forge's dependency graph
// and reported as a dependency of Draugr, vulnerabilities included; stored with the suffix it is
// a file nothing parses, and Prepare restores its name in the copy a scan reads.
const FixtureSuffix = ".fixture"

// Scenario is one directory under ecosystems/: a repository to scan, the descriptor to scan it
// with, and what the scan must produce.
type Scenario struct {
	// Name is the directory name, which is also the component and the repository's directory.
	Name string
	// Dir is the scenario directory.
	Dir string
	// Expected is the parsed expected.yaml.
	Expected Expected
}

// LoadScenario reads the scenario in dir.
func LoadScenario(dir string) (Scenario, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "expected.yaml")) // #nosec G304 -- under testdata
	if err != nil {
		return Scenario{}, err
	}
	var exp Expected
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&exp); err != nil {
		return Scenario{}, fmt.Errorf("%s/expected.yaml: %w", filepath.Base(dir), err)
	}
	return Scenario{Name: filepath.Base(dir), Dir: dir, Expected: exp}, nil
}

// Prepare copies the scenario's repository to work/<name>, restores the names of its manifests,
// writes the secrets the scenario asks for, and commits the result. It returns the repository
// directory.
//
// The secrets are generated here and never committed to this repository: a credential-shaped
// string in a public tree is refused by push protection and reported by every scanner that reads
// it, including the one being tested.
func (s Scenario) Prepare(work string) (string, error) {
	dst := filepath.Join(work, s.Name)
	src := filepath.Join(s.Dir, "repo")
	// Into a fresh directory only: a copy laid over an earlier one keeps whatever the earlier one
	// had that this one does not, and the scan reads both.
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("%s already exists", dst)
	}
	// Collected first and copied after, so nothing is read from inside the walk.
	var files []string
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	for _, path := range files {
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return "", err
		}
		target := filepath.Join(dst, strings.TrimSuffix(rel, FixtureSuffix))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return "", err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a file under the scenario's own directory
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil { // #nosec G703 -- under the test's work directory
			return "", err
		}
	}
	for _, sec := range s.Expected.Secrets {
		path := filepath.Join(dst, filepath.FromSlash(sec.File))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return "", err
		}
		key, err := AWSAccessKeyID()
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID="+key+"\n"), 0o600); err != nil {
			return "", err
		}
	}
	for _, args := range [][]string{
		{"init", "--quiet", "--initial-branch", "main"},
		{"add", "--all"},
		{"commit", "--quiet", "--message", "fixture"},
	} {
		cmd := exec.Command("git", args...) // #nosec G204 -- literal arguments above
		cmd.Dir = dst
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Draugr fixture", "GIT_AUTHOR_EMAIL=fixture@draugr.dev",
			"GIT_COMMITTER_NAME=Draugr fixture", "GIT_COMMITTER_EMAIL=fixture@draugr.dev",
			"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, out)
		}
	}
	return dst, nil
}

// awsKeyAlphabet is the character set of the random part of an AWS access key id.
const awsKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// AWSAccessKeyID returns a random string in the shape of an AWS access key id, which no AWS
// account issued. Regenerated until its entropy clears the threshold secret scanners apply, so a
// low-entropy draw cannot make a scenario fail by chance.
func AWSAccessKeyID() (string, error) {
	for {
		var b strings.Builder
		b.WriteString("AKIA")
		for range 16 {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(awsKeyAlphabet))))
			if err != nil {
				return "", err
			}
			b.WriteByte(awsKeyAlphabet[n.Int64()])
		}
		if key := b.String(); entropy(key) >= 3.5 {
			return key, nil
		}
	}
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}
