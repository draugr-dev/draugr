package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The tree pass skips a file whose name holds an archive extension anywhere, text or not (see
// gitleaks_unread.go). Gitleaks's git mode checks the name only for a change git marks binary, and
// reads a text file's lines under its path whatever it is called. So the text files the tree pass
// skipped are committed at their own paths to a scratch repository, and Gitleaks reads that one
// commit in git mode, with the tree pass's configuration and the checkout's .gitleaksignore. Path
// allowlists, rules scoped to a path, .gitleaksignore entries and redaction then apply at the real
// path, and with the scratch commit taken off, a finding is the one the tree pass would have made
// had it read the file.
//
// `gitleaks stdin` would read the content too, but it gives a finding no path, so none of those
// would apply and its fingerprint would match no entry a developer wrote.

// gitleaksBinarySniff is how much of a file is read to tell text from binary: a NUL byte within it
// makes the file binary, the test git applies, so a file read here is one git commits as text.
const gitleaksBinarySniff = 8000

// gitleaksAtCommit is the clause Gitleaks adds to a finding's message in git mode, naming the
// commit. The scratch commit means nothing to a reader.
var gitleaksAtCommit = regexp.MustCompile(` at commit [0-9a-f]{7,64}`)

// gitleaksNamedText splits the inputs the tree pass left unread for an archive's name into the
// files under dir that hold text, by their paths, and the rest, which stay unread.
func gitleaksNamedText(dir string, unread []sarif.Input) (text []string, rest []sarif.Input) {
	for _, in := range unread {
		if in.Unread == gitleaksArchiveReason && filepath.IsLocal(in.Path) && isTextFile(filepath.Join(dir, in.Path)) {
			text = append(text, in.Path)
			continue
		}
		rest = append(rest, in)
	}
	return text, rest
}

// isTextFile reports whether path is a regular file with no NUL byte in its first
// gitleaksBinarySniff bytes.
func isTextFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path) // #nosec G304 -- a file inside the checkout that Gitleaks named
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, gitleaksBinarySniff)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false
	}
	return !bytes.Contains(head[:n], []byte{0})
}

// gitleaksScratchArgs is the tree pass's argv for a git-mode run over the scratch repository: the
// same report, configuration and flags, without the trace level the tree pass needs only to name
// what it skipped.
func gitleaksScratchArgs(argv []string) []string {
	out := slices.Clone(argv)
	if len(out) > 1 {
		out[1] = "git"
	}
	if i := slices.Index(out, gitleaksTraceArgs[0]); i >= 0 && i+1 < len(out) && out[i+1] == gitleaksTraceArgs[1] {
		out = slices.Delete(out, i, i+2)
	}
	return out
}

// gitleaksReadNamed reads the text files at paths under dir in git mode, from a scratch repository
// holding only them, and returns the results as the tree pass would have reported them.
//
// The scratch repository holds copies of files that may hold a credential. It is made in the
// system's temporary directory, outside the checkout, readable by this user only, and removed
// however the run ends.
func gitleaksReadNamed(ctx context.Context, dir string, argv, paths []string,
	run func(ctx context.Context, dir string, argv []string) ([]byte, error),
) ([]json.RawMessage, error) {
	scratch, err := os.MkdirTemp("", "draugr-gitleaks-named-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	for _, p := range paths {
		if err := copyFileInto(scratch, dir, p); err != nil {
			return nil, err
		}
	}
	if err := scratchCommit(ctx, scratch); err != nil {
		return nil, err
	}
	// After the commit, so it is read as the list of findings to set aside and never as a file
	// to search.
	if gitleaksIgnoreFile(dir) {
		if err := copyFileInto(scratch, dir, ".gitleaksignore"); err != nil {
			return nil, err
		}
	}

	out, err := runToReport(ctx, scratch, gitleaksScratchArgs(argv), run)
	if err != nil {
		return nil, err
	}
	return gitleaksAsTree(out)
}

// copyFileInto copies the file at rel under src to the same path under dst. rel must stay inside
// both.
func copyFileInto(dst, src, rel string) error {
	if !filepath.IsLocal(rel) {
		return fmt.Errorf("%s is not a path inside the checkout", rel)
	}
	data, err := os.ReadFile(filepath.Join(src, rel)) // #nosec G304 -- a local path inside the checkout
	if err != nil {
		return err
	}
	to := filepath.Join(dst, rel)
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	return os.WriteFile(to, data, 0o600) // #nosec G703 -- rel is checked local above, so to stays inside dst
}

// scratchCommit commits everything in dir to a new repository there. The user's and the system's
// git configuration are left out, and the identity given inline, so no hook, signing setup or
// template of theirs runs or fails the scan.
func scratchCommit(ctx context.Context, dir string) error {
	for _, args := range [][]string{
		{"init", "--quiet", "--template="},
		{"add", "--all"},
		{"commit", "--quiet", "--no-verify", "--message", "scratch"},
	} {
		argv := append([]string{
			"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
			"-c", "user.name=draugr", "-c", "user.email=draugr@localhost",
		}, args...)
		cmd := exec.CommandContext(ctx, "git", argv...) // #nosec G204 -- fixed git subcommands
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %w: %s", args[0], err, bytes.TrimSpace(out))
		}
	}
	return nil
}

// gitleaksAsTree returns the results of a git-mode Gitleaks SARIF report as the tree pass reports
// them: the commit, its author, date and message blank, and the message without the commit.
func gitleaksAsTree(report []byte) ([]json.RawMessage, error) {
	var doc struct {
		Runs []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil, fmt.Errorf("read the report of the scratch run: %w", err)
	}
	var out []json.RawMessage
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			if fp, ok := r["partialFingerprints"].(map[string]any); ok {
				for k := range fp {
					fp[k] = ""
				}
			}
			if msg, ok := r["message"].(map[string]any); ok {
				if text, ok := msg["text"].(string); ok {
					msg["text"] = gitleaksAtCommit.ReplaceAllString(text, "")
				}
			}
			raw, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			out = append(out, raw)
		}
	}
	return out, nil
}
