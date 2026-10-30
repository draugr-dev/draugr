package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/config"
)

// fakeEditorScript stands in for an editor. On its nth run it keeps a copy of what it was given as
// seen.n and its file name as name.n, then replaces the file with reply.n, or applies the sed
// script edit.n to it, or leaves it as it was, and exits with the number in exit.
const fakeEditorScript = `#!/bin/sh
dir=$(dirname "$0")
n=$(cat "$dir/count" 2>/dev/null || echo 0)
n=$((n+1))
echo "$n" > "$dir/count"
cp "$1" "$dir/seen.$n"
basename "$1" > "$dir/name.$n"
if [ -f "$dir/reply.$n" ]; then cp "$dir/reply.$n" "$1"; fi
if [ -f "$dir/edit.$n" ]; then sed -f "$dir/edit.$n" "$1" > "$1.new" && mv "$1.new" "$1"; fi
exit $(cat "$dir/exit" 2>/dev/null || echo 0)
`

// fakeEditor installs the script as $EDITOR, with each of files written beside it, and lets
// `config edit` run as though it had a terminal. It returns the script's directory.
func fakeEditor(t *testing.T, files map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in editor is a shell script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "editor")
	if err := os.WriteFile(script, []byte(fakeEditorScript), 0o700); err != nil { // #nosec G306 -- it is run
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script)
	t.Setenv(config.EnvVar, "")
	prev := editorAttached
	editorAttached = func(io.Reader, io.Writer) bool { return true }
	t.Cleanup(func() { editorAttached = prev })
	return dir
}

// read is a file's content, or "" when it does not exist.
func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a path the test built
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

const brokenEdit = "output:\n  veiw: actions\ncache:\n  ttl: 5\n"

func TestConfigEditOpensTheStarterWhenThereIsNoFile(t *testing.T) {
	ed := fakeEditor(t, map[string]string{"reply.1": "output:\n  view: actions\n"})
	dir := t.TempDir()
	out, err := runConfig(t, dir, "edit")
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(ed, "seen.1")); got != starterFile() {
		t.Errorf("the editor was given:\n%s\nwant the starter `config init` writes", got)
	}
	// Named as the file it stands for, so an editor that picks a schema by name still does.
	if got := strings.TrimSpace(read(t, filepath.Join(ed, "name.1"))); got != config.FileName {
		t.Errorf("the editor opened %q", got)
	}
	want := "./draugr.config.yaml does not exist; editing the starter `draugr config init` writes\n" +
		"wrote ./draugr.config.yaml\n"
	if out != want {
		t.Errorf("output:\n%s\nwant:\n%s", out, want)
	}
	if got := read(t, filepath.Join(dir, config.FileName)); got != "output:\n  view: actions\n" {
		t.Errorf("wrote:\n%s", got)
	}
}

// A save the check refuses is neither lost nor written. The editor reopens with the problems at the
// top, and they leave with the next save even when a replace-all rewrote one of them.
func TestConfigEditReopensAnInvalidSaveWithItsProblems(t *testing.T) {
	ed := fakeEditor(t, map[string]string{
		"reply.1": brokenEdit,
		"edit.2":  "s/veiw/view/g\ns/ttl: 5$/ttl: 5h/\n",
	})
	dir := t.TempDir()
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte("output:\n  view: findings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfig(t, dir, "edit")
	if err != nil {
		t.Fatal(err)
	}
	want := "# that edit would add a problem to the file, so nothing was written:\n" +
		"#   output: \"veiw\" is not a setting Draugr has, did you mean \"view\"?\n" +
		"#   cache.ttl: expected a duration such as 12h, got 5\n" +
		"# Save again once fixed. Saving it unchanged, or empty, cancels. These lines are removed.\n" +
		brokenEdit
	if got := read(t, filepath.Join(ed, "seen.2")); got != want {
		t.Errorf("reopened with:\n%s\nwant:\n%s", got, want)
	}
	if got := read(t, path); got != "output:\n  view: actions\ncache:\n  ttl: 5h\n" {
		t.Errorf("wrote:\n%s", got)
	}
	if out != "wrote ./draugr.config.yaml\n" {
		t.Errorf("output: %q", out)
	}
}

func TestConfigEditCancelsAnUnchangedOrEmptySave(t *testing.T) {
	const original = "output:\n  view: findings\n"
	for name, files := range map[string]map[string]string{
		"unchanged":                 nil,
		"empty":                     {"reply.1": "\n"},
		"reopened, saved unchanged": {"reply.1": brokenEdit},
		"reverted to the original":  {"reply.1": brokenEdit, "reply.2": original},
	} {
		t.Run(name, func(t *testing.T) {
			fakeEditor(t, files)
			dir := t.TempDir()
			path := filepath.Join(dir, config.FileName)
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := runConfig(t, dir, "edit")
			if err == nil || err.Error() != "edit canceled; ./draugr.config.yaml was not changed" {
				t.Errorf("err = %v", err)
			}
			if got := read(t, path); got != original {
				t.Errorf("the file changed:\n%s", got)
			}
		})
	}
}

// A starter saved as it was is a canceled edit too, and leaves no file behind.
func TestConfigEditWritesNoFileForAStarterLeftAsItWas(t *testing.T) {
	fakeEditor(t, nil)
	dir := t.TempDir()
	if _, err := runConfig(t, dir, "edit"); err == nil || !strings.HasPrefix(err.Error(), "edit canceled") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, config.FileName)); !os.IsNotExist(err) {
		t.Errorf("a file was written: %v", err)
	}
}

func TestConfigEditNeedsATerminal(t *testing.T) {
	t.Setenv(config.EnvVar, "")
	var out bytes.Buffer
	err := runConfigEdit(strings.NewReader(""), &out, &out, filepath.Join(t.TempDir(), config.FileName))
	want := "config edit needs a terminal; `draugr config set <key> <value>` writes one key"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
}

func TestConfigEditSaysWhenTheEditorFails(t *testing.T) {
	fakeEditor(t, map[string]string{"exit": "3"})
	dir := t.TempDir()
	_, err := runConfig(t, dir, "edit")
	if err == nil || !strings.Contains(err.Error(), "exit status 3") ||
		!strings.HasSuffix(err.Error(), "./draugr.config.yaml was not changed") {
		t.Errorf("err = %v", err)
	}

	t.Setenv("EDITOR", "draugr-test-no-such-editor")
	_, err = runConfig(t, dir, "edit")
	if err == nil || !strings.Contains(err.Error(), "draugr-test-no-such-editor is not installed; set VISUAL or EDITOR") {
		t.Errorf("err = %v", err)
	}
}

func TestConfigEditPrefersVisualToEditor(t *testing.T) {
	ed := fakeEditor(t, map[string]string{"reply.1": "output:\n  top: 5\n"})
	t.Setenv("VISUAL", filepath.Join(ed, "editor"))
	t.Setenv("EDITOR", "draugr-test-no-such-editor")
	dir := t.TempDir()
	if _, err := runConfig(t, dir, "edit"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dir, config.FileName)); got != "output:\n  top: 5\n" {
		t.Errorf("wrote:\n%s", got)
	}
}

func TestTheEditorFallsBackToTheSystemOne(t *testing.T) {
	t.Setenv("VISUAL", " ")
	t.Setenv("EDITOR", "")
	want := "vi"
	if runtime.GOOS == "windows" {
		want = "notepad"
	}
	if got := editorCommand(); len(got) != 1 || got[0] != want {
		t.Errorf("editorCommand() = %q", got)
	}
	t.Setenv("EDITOR", "code --wait")
	if got := editorCommand(); strings.Join(got, "|") != "code|--wait" {
		t.Errorf("editorCommand() = %q", got)
	}
}

func TestTheProblemBlockLeavesWithTheSave(t *testing.T) {
	head := problemHead([]string{"a: one", "b: two\nand more"})
	if !strings.Contains(head, "#   b: two\n#   and more\n") {
		t.Errorf("a problem of two lines:\n%s", head)
	}
	for name, saved := range map[string]string{
		"as written":       head + "a: 1\n",
		"a line deleted":   strings.Replace(head, "#   a: one\n", "", 1) + "a: 1\n",
		"a line rewritten": strings.Replace(head, "a: one", "a: 1", 1) + "a: 1\n",
		"windows endings":  strings.ReplaceAll(head, "\n", "\r\n") + "a: 1\n",
	} {
		if got := string(withoutHead([]byte(saved), head)); got != "a: 1\n" {
			t.Errorf("%s: kept %q", name, got)
		}
	}
	// A comment of the file's own, after the block, stays.
	own := head + "#   kept\na: 1\n"
	if got := string(withoutHead([]byte(own), head)); got != "#   kept\na: 1\n" {
		t.Errorf("removed the file's own comment: %q", got)
	}
	if got := string(withoutHead([]byte("a: 1\n"), "")); got != "a: 1\n" {
		t.Errorf("no block, changed: %q", got)
	}
}
