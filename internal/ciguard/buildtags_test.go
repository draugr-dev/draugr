package ciguard

import (
	"go/build/constraint"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// exemptTags are resolved by the toolchain itself, so they need no entry anywhere: the linter and
// `go vet` already build for a real platform and a real Go release. A repository build tag —
// something a person invented to hold a set of files back — is the opposite, and is invisible
// until named.
//
// A platform tag arriving here fails the test rather than being guessed at. The message says to
// add it, which costs one line and keeps the alternative (a tag silently treated as exempt
// because it looked like a GOOS) from ever happening.
var exemptTags = []string{"cgo", "race", "unix", "linux", "darwin", "windows", "amd64", "arm64"}

// TestLintAndVetSeeEveryBuildTag keeps a tagged file from becoming a file nothing reads.
//
// A file behind a build tag is not compiled by `go vet ./...`, not compiled by `go test ./...`,
// and not opened by golangci-lint unless the tag is named in the configuration. All three then
// report success, which is indistinguishable from having found nothing wrong: a tagged file can
// reach the default branch in a state where it does not compile.
//
// So every tag the tree uses has to be named in both places that decide what gets read —
// `.golangci.yml` for the linter, and the second `go vet` pass in scripts/gate.sh.
func TestLintAndVetSeeEveryBuildTag(t *testing.T) {
	t.Parallel()

	used := buildTagsInTree(t)
	if len(used) == 0 {
		t.Fatal("no build tags found anywhere — this test walks the tree, so finding none means " +
			"it is walking the wrong one and would pass whatever the configuration said")
	}

	linted := lintBuildTags(t)
	gate := readRepoFile(t, "scripts/gate.sh")

	for _, tag := range used {
		if !slices.Contains(linted, tag) {
			t.Errorf("the %q build tag is used in the tree but .golangci.yml does not list it under "+
				"run.build-tags — the linter will skip those files and report success for them", tag)
		}
		if !strings.Contains(gate, "-tags "+tag) {
			t.Errorf("the %q build tag is used in the tree but scripts/gate.sh never runs `go vet "+
				"-tags %s` — a file behind it can fail to compile and still pass the gate", tag, tag)
		}
	}
}

// buildTagsInTree returns the repository's own build tags, sorted and deduplicated.
func buildTagsInTree(t *testing.T) []string {
	t.Helper()
	var tags []string
	root := repoPath("")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skipped rather than walked: neither is ours to configure, and .git is large enough
			// to make the difference noticeable.
			if name := d.Name(); name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		// #nosec G304,G122 -- the path comes from walking this repository's own checked-out source
		// during a test. There is no attacker between the walk and the read: reaching the tree at
		// all already means being able to edit the files this test is reading.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !constraint.IsGoBuild(line) {
				// Build constraints come before the package clause, so nothing after it can be one.
				if strings.HasPrefix(line, "package ") {
					break
				}
				continue
			}
			expr, err := constraint.Parse(line)
			if err != nil {
				t.Errorf("%s: unparseable build constraint %q: %v", path, line, err)
				continue
			}
			for _, tag := range constraintTags(expr) {
				if !slices.Contains(exemptTags, tag) && !slices.Contains(tags, tag) {
					tags = append(tags, tag)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the tree: %v", err)
	}
	slices.Sort(tags)
	return tags
}

// constraintTags collects every tag named in a build expression.
//
// Walked rather than evaluated: constraint.Expr.Eval short-circuits, so `a && b` with a false
// first operand never asks about the second — and a tag it never asks about is a tag this test
// would never see.
func constraintTags(expr constraint.Expr) []string {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		return []string{e.Tag}
	case *constraint.NotExpr:
		return constraintTags(e.X)
	case *constraint.AndExpr:
		return append(constraintTags(e.X), constraintTags(e.Y)...)
	case *constraint.OrExpr:
		return append(constraintTags(e.X), constraintTags(e.Y)...)
	}
	return nil
}

// lintBuildTags returns the tags golangci-lint is configured to build with.
func lintBuildTags(t *testing.T) []string {
	t.Helper()
	var cfg struct {
		Run struct {
			BuildTags []string `yaml:"build-tags"`
		} `yaml:"run"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".golangci.yml")), &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	return cfg.Run.BuildTags
}

func repoPath(rel string) string { return filepath.Join("..", "..", rel) }

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(repoPath(rel)) // #nosec G304 -- a fixed path within this repository
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}
