package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// editTail closes the problems `config edit` writes at the top of a file it reopens.
const editTail = "Save again once fixed. Saving it unchanged, or empty, cancels. These lines are removed."

// problemIndent leads each problem line of that block.
const problemIndent = "#   "

// editorAttached reports whether an editor started here has a terminal to draw on. A variable, so a
// test can drive the command without one.
var editorAttached = func(in io.Reader, out io.Writer) bool { return isTTY(in) && tui.IsTerminal(out) }

func newConfigEditCommand() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Open the config file in an editor, and keep the result unless it adds a problem",
		Long: "Open the config file in $VISUAL, else $EDITOR, else vi, and write the result back when\n" +
			"it adds no problem to the file. The file is the one --config or DRAUGR_CONFIG names, else\n" +
			"./draugr.config.yaml, or ~/.draugr/config.yaml with --global.\n\n" +
			"A file that does not exist opens as the starter `draugr config init` writes. A save the\n" +
			"check refuses reopens the editor with the problems as comments at the top, which are\n" +
			"removed when it is saved again. Saving it unchanged, or empty, cancels and writes\n" +
			"nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := configPath(global)
			if err != nil {
				return err
			}
			return runConfigEdit(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), path)
		},
	}
	globalFlag(cmd, &global)
	return cmd
}

// runConfigEdit opens the file at path in an editor until a save the check accepts, or a save that
// cancels.
//
// The editor works on a copy named draugr.config.yaml in a private directory, so an editor that
// picks a schema by file name still does, and the file itself is written only through writeEdit,
// the check `config set` makes: a save that adds a problem is never written, and is reopened with
// the problems rather than discarded.
func runConfigEdit(in io.Reader, out, errOut io.Writer, path string) error {
	if !editorAttached(in, out) {
		return errors.New("config edit needs a terminal; `draugr config set <key> <value>` writes one key")
	}
	original, err := os.ReadFile(path) // #nosec G304 -- the file `config set` writes
	switch {
	case err == nil:
	case os.IsNotExist(err):
		original = []byte(starterFile())
		_, _ = fmt.Fprintf(out, "%s does not exist; editing the starter `draugr config init` writes\n", herePath(path))
	default:
		return err
	}

	dir, err := os.MkdirTemp("", "draugr-config-edit-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	scratch := filepath.Join(dir, config.FileName)

	text, problems := original, []string(nil)
	for {
		head := problemHead(problems)
		if err := os.WriteFile(scratch, append([]byte(head), text...), 0o600); err != nil { // #nosec G703 -- a file in the private directory made above
			return err
		}
		if err := runEditor(in, out, errOut, scratch); err != nil {
			return fmt.Errorf("%w; %s was not changed", err, herePath(path))
		}
		saved, err := os.ReadFile(scratch) // #nosec G304 -- the copy this command wrote
		if err != nil {
			return err
		}
		edited := withoutHead(saved, head)
		if len(bytes.TrimSpace(edited)) == 0 || bytes.Equal(edited, text) || bytes.Equal(edited, original) {
			return fmt.Errorf("edit canceled; %s was not changed", herePath(path))
		}
		err = writeEdit(out, path, func([]byte) ([]byte, error) { return edited, nil })
		var refused *editRefused
		if !errors.As(err, &refused) {
			return err
		}
		text, problems = edited, refused.added
	}
}

// problemHead is the comment block a reopened file starts with: the problems the last save would
// have added, and how to carry on. Empty when there are none.
func problemHead(problems []string) string {
	if len(problems) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# " + refusedLead + "\n")
	for _, p := range problems {
		for _, line := range strings.Split(p, "\n") {
			b.WriteString(problemIndent + line + "\n")
		}
	}
	b.WriteString("# " + editTail + "\n")
	return b.String()
}

// withoutHead removes the block head wrote from the top of saved, through its closing line.
//
// Read line by line rather than matched whole, because the block is text in somebody's editor: a
// line of it may be deleted, and a replace-all that fixes a key rewrites the problem that names it.
// A leading line is the block's while it is one of head's lines or a problem line, indented as
// problemHead indents one, and the block ends at its closing line or the first line that is neither.
func withoutHead(saved []byte, head string) []byte {
	if head == "" {
		return saved
	}
	ours := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(head, "\n"), "\n") {
		ours[line] = true
	}
	rest := saved
	for len(rest) > 0 {
		line, after, _ := bytes.Cut(rest, []byte("\n"))
		text := strings.TrimSuffix(string(line), "\r")
		if !ours[text] && !strings.HasPrefix(text, problemIndent) {
			break
		}
		rest = after
		if text == "# "+editTail {
			break
		}
	}
	return rest
}

// editorCommand is the editor to run: $VISUAL, then $EDITOR, each split on spaces so a value such
// as `code --wait` works, then the system's own.
func editorCommand() []string {
	for _, name := range []string{"VISUAL", "EDITOR"} {
		if v := strings.Fields(os.Getenv(name)); len(v) > 0 {
			return v
		}
	}
	if runtime.GOOS == "windows" {
		return []string{"notepad"}
	}
	return []string{"vi"}
}

// runEditor opens file in the editor, attached to this command's terminal, and waits for it.
func runEditor(in io.Reader, out, errOut io.Writer, file string) error {
	argv := editorCommand()
	// #nosec G204 -- the editor the person running this named in $VISUAL or $EDITOR, on their own file
	cmd := exec.Command(argv[0], append(argv[1:], file)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
	err := cmd.Run()
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("%s is not installed; set VISUAL or EDITOR to the editor to use", argv[0])
	}
	if err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	return nil
}
