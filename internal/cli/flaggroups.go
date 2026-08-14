package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagGroup is a heading in a command's help and the flags listed under it.
//
// A group is a question the reader has — "what fails the build?", "where does output go?" — and
// the flags that answer it. Alphabetical order answers a different question, one nobody asks:
// it puts --artifact-min-priority nine lines from --min-priority when the two are one decision.
// helpFlag is Cobra's own, added when a command runs rather than when it is built. It is grouped
// by the renderer instead of by a caller, so a guard over a group list never has to name a flag
// that is absent from the command it is checking.
const helpFlag = "help"

type flagGroup struct {
	name  string
	flags []string
}

// useFlagGroups renders cmd's local flags under headings instead of one alphabetical list.
//
// Flags are still declared with cmd.Flags() as usual; this only changes how they are printed, so
// nothing about parsing, completion or precedence moves. Membership is named separately, which is
// a second place a flag has to appear — and the reason TestScanFlagsAreAllGrouped exists. Without
// it the groups become "mostly right", which is worse than alphabetical: a reader who trusts the
// grouping will believe a flag is absent because it is not under the heading they looked at.
func useFlagGroups(cmd *cobra.Command, groups []flagGroup) {
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		w := c.OutOrStderr()
		_, _ = fmt.Fprintf(w, "Usage:\n  %s\n", c.UseLine())
		if len(c.Aliases) > 0 {
			_, _ = fmt.Fprintf(w, "\nAliases:\n  %s\n", c.NameAndAliases())
		}
		if c.HasExample() {
			_, _ = fmt.Fprintf(w, "\nExamples:\n%s\n", c.Example)
		}
		// Reproduced from Cobra's default template rather than assumed absent: this helper is
		// generic, and a command that grew a subcommand would otherwise stop listing it in its
		// own help, which is a worse failure than an ungrouped flag and much harder to notice.
		if c.HasAvailableSubCommands() {
			_, _ = fmt.Fprint(w, "\nAvailable Commands:\n")
			for _, sub := range c.Commands() {
				if sub.IsAvailableCommand() || sub.Name() == "help" {
					_, _ = fmt.Fprintf(w, "  %s %s\n", rpad(sub.Name(), sub.NamePadding()), sub.Short)
				}
			}
		}
		writeGroupedFlags(w, c.LocalFlags(), groups)
		if c.HasAvailableInheritedFlags() {
			_, _ = fmt.Fprintf(w, "\nGlobal Flags:\n%s\n",
				strings.TrimRight(c.InheritedFlags().FlagUsages(), "\n"))
		}
		if c.HasAvailableSubCommands() {
			_, _ = fmt.Fprintf(w, "\nUse \"%s [command] --help\" for more information about a command.\n",
				c.CommandPath())
		}
		return nil
	})
}

// writeGroupedFlags prints each group, then anything left over.
//
// The leftovers are printed rather than dropped. A flag missing from every group is a mistake the
// guard test catches before it ships, but if one ever reaches a user, help that omits it is worse
// than help that lists it in the wrong place: the flag exists, it works, and the only way to find
// out is to read the source.
func writeGroupedFlags(w io.Writer, flags *pflag.FlagSet, groups []flagGroup) {
	grouped := map[string]bool{}
	for _, g := range groups {
		set := pflag.NewFlagSet(g.name, pflag.ContinueOnError)
		for _, name := range g.flags {
			f := flags.Lookup(name)
			if f == nil || f.Hidden {
				continue
			}
			set.AddFlag(f)
			grouped[name] = true
		}
		usage := strings.TrimRight(set.FlagUsages(), "\n")
		if usage == "" {
			continue
		}
		_, _ = fmt.Fprintf(w, "\n%s:\n%s\n", g.name, usage)
	}

	rest := pflag.NewFlagSet("other", pflag.ContinueOnError)
	flags.VisitAll(func(f *pflag.Flag) {
		if !grouped[f.Name] && !f.Hidden && f.Name != helpFlag {
			rest.AddFlag(f)
		}
	})
	if usage := strings.TrimRight(rest.FlagUsages(), "\n"); usage != "" {
		_, _ = fmt.Fprintf(w, "\nOther:\n%s\n", usage)
	}

	// --help last and on its own, because it is Cobra's rather than ours. Grouping it by hand
	// would mean naming a flag no command declares — Cobra adds it while the command runs, so it
	// is absent from a freshly built one and a guard over the group list could not see it.
	if h := pflag.NewFlagSet("help", pflag.ContinueOnError); flags.Lookup(helpFlag) != nil {
		h.AddFlag(flags.Lookup(helpFlag))
		_, _ = fmt.Fprintf(w, "\nHelp:\n%s\n", strings.TrimRight(h.FlagUsages(), "\n"))
	}
}

// ungroupedFlags names cmd's local flags that no group claims, and any a group names twice.
//
// Both are failures of the same kind — the list and the command disagreeing about what exists —
// and a test that checked only for the first would pass while a flag appeared under two headings.
func ungroupedFlags(cmd *cobra.Command, groups []flagGroup) (missing, duplicated []string) {
	claimed := map[string]int{}
	for _, g := range groups {
		for _, name := range g.flags {
			claimed[name]++
		}
	}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == helpFlag {
			return // Cobra's, and rendered on its own
		}
		switch claimed[f.Name] {
		case 0:
			missing = append(missing, f.Name)
		case 1:
		default:
			duplicated = append(duplicated, f.Name)
		}
	})
	// A group naming a flag the command does not have is the same disagreement seen from the
	// other side: a renamed flag leaves its old name behind, and the heading quietly loses it.
	for name := range claimed {
		if cmd.LocalFlags().Lookup(name) == nil {
			duplicated = append(duplicated, name+" (named by a group, but not a flag of this command)")
		}
	}
	sort.Strings(missing)
	sort.Strings(duplicated)
	return missing, duplicated
}

// rpad pads s to at least n characters, the way Cobra's own template does, so a grouped command
// listing its subcommands lines up with an ungrouped one listing theirs.
func rpad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
