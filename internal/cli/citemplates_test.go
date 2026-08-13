package cli

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The CI templates are shell inside YAML: nothing compiles them, and a flag that no longer exists
// — or never did — is discovered by a user running a pipeline. `draugr doctor --saga x` shipped in
// a template because the surrounding `|| true` swallowed the error, so the step reported success
// and simply never ran.
//
// Checks every `draugr …` invocation in every template against the real command tree.
func TestCITemplatesUseFlagsThatExist(t *testing.T) {
	templates := []string{"../../gitlab-ci/draugr.yml", "../../azure-pipelines/draugr.yml"}
	invocation := regexp.MustCompile(`\bdraugr\s+([^\n|&;]+)`)

	for _, path := range templates {
		raw, err := os.ReadFile(path) // #nosec G304 -- template path from the literal list above
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range invocation.FindAllStringSubmatch(string(raw), -1) {
			checkInvocation(t, path, strings.Fields(m[1]))
		}
	}
}

// checkInvocation resolves the subcommand an invocation names, then every flag it passes.
func checkInvocation(t *testing.T, path string, tokens []string) {
	t.Helper()
	root := newRootCommand()

	// Walk the leading words while they keep naming a subcommand. A token carrying a shell
	// substitution is an argument, not a command, and ends the walk.
	cmd := root
	i := 0
	for ; i < len(tokens); i++ {
		tok := tokens[i]
		if strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, `$"'`) {
			break
		}
		next, _, err := cmd.Find([]string{tok})
		if err != nil || next == cmd {
			break
		}
		cmd = next
	}
	if cmd == root {
		return // not a draugr subcommand — a comment, or prose mentioning the binary
	}

	for ; i < len(tokens); i++ {
		name, ok := strings.CutPrefix(tokens[i], "--")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		if name == "" || strings.ContainsAny(name, `$"'`) {
			continue
		}
		if lookupFlag(cmd, name) == nil {
			t.Errorf("%s: `draugr %s` is passed --%s, which that command does not have",
				path, cmd.CommandPath()[len("draugr "):], name)
		}
	}
}

// lookupFlag finds a flag on a command or anything it inherits from.
func lookupFlag(cmd *cobra.Command, name string) any {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f
	}
	if f := cmd.InheritedFlags().Lookup(name); f != nil {
		return f
	}
	return nil
}
