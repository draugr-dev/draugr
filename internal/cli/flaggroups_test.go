package cli

import (
	"bytes"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestScanFlagsAreAllGrouped is what makes grouping worth doing rather than a tidy-up that decays.
//
// A flag added without a group lands under "Other", which reads as an afterthought, and a group
// naming a flag that was renamed silently loses it from the heading a reader looked under. Both
// leave help that is "mostly right" — worse than the alphabetical list it replaced, because a
// reader who trusts the grouping concludes a flag does not exist.
func TestScanFlagsAreAllGrouped(t *testing.T) {
	t.Parallel()
	missing, duplicated := ungroupedFlags(newScanCommand(), scanFlagGroups)
	if len(missing) > 0 {
		t.Errorf("no group claims %v — add each to scanFlagGroups, under the heading a reader "+
			"would look beneath rather than the one with room", missing)
	}
	if len(duplicated) > 0 {
		t.Errorf("scanFlagGroups and the command disagree about %v", duplicated)
	}
}

func TestScanHelpIsGrouped(t *testing.T) {
	t.Parallel()
	// Through the root command, because that is the shape a reader sees: --help is added by Cobra
	// as a command runs, and the global flags belong to the parent. A standalone command has
	// neither, so a test built on one would check help nobody is ever shown.
	cmd := scanCommandFromRoot(t)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Usage(); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	for _, g := range scanFlagGroups {
		if !strings.Contains(got, "\n"+g.name+":\n") {
			t.Errorf("help has no %q heading:\n%s", g.name, got)
		}
	}
	// Every flag still has to appear. A heading that hides one is the failure this replaces.
	for _, flag := range []string{"--fail-on", "--cache-dir", "--components", "--epss", "--report"} {
		if !strings.Contains(got, flag) {
			t.Errorf("help no longer lists %s:\n%s", flag, got)
		}
	}
	if !strings.Contains(got, "Global Flags:") {
		t.Errorf("inherited flags went missing from help:\n%s", got)
	}
	// Grouping is presentation only. If it ever swallowed a flag, parsing would still accept it
	// and the reader would have no way to find it.
	if cmd.Flags().Lookup("cache-dir") == nil {
		t.Error("grouping must not change which flags the command has")
	}
}

// TestUngroupedFlagsReportsBothDisagreements covers the guard itself, since a guard that only
// noticed one of the two ways the list can drift would pass while help was wrong.
func TestUngroupedFlagsReportsBothDisagreements(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().Bool("kept", false, "")
	cmd.Flags().Bool("orphan", false, "")

	missing, duplicated := ungroupedFlags(cmd, []flagGroup{
		{"A", []string{"kept"}},
		{"B", []string{"kept", "gone"}},
	})
	if len(missing) != 1 || missing[0] != "orphan" {
		t.Errorf("missing = %v, want [orphan]", missing)
	}
	// "kept" is in two groups; "gone" is in a group and not on the command.
	if len(duplicated) != 2 {
		t.Errorf("duplicated = %v, want the twice-claimed flag and the one that no longer exists", duplicated)
	}
}

// TestGroupedHelpKeepsSubcommands guards the generic helper against the failure that would be
// hardest to spot: a command that grows a subcommand and stops listing it in its own help.
func TestGroupedHelpKeepsSubcommands(t *testing.T) {
	t.Parallel()
	parent := &cobra.Command{Use: "parent"}
	parent.Flags().Bool("thing", false, "a thing")
	parent.AddCommand(&cobra.Command{Use: "child", Short: "does a thing", Run: func(*cobra.Command, []string) {}})
	useFlagGroups(parent, []flagGroup{{"Options", []string{"thing"}}})

	var out bytes.Buffer
	parent.SetOut(&out)
	parent.SetErr(&out)
	if err := parent.Usage(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Available Commands:", "child", "Options:", "--thing"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("grouped help dropped %q:\n%s", want, out.String())
		}
	}
}

// TestGroupedHelpStillShowsAnUngroupedFlag keeps a mistake visible rather than invisible. The
// guard above stops this reaching a user; if one ever does, help that omits the flag entirely is
// worse than help that files it under "Other".
func TestGroupedHelpStillShowsAnUngroupedFlag(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().Bool("grouped", false, "")
	cmd.Flags().Bool("forgotten", false, "")
	useFlagGroups(cmd, []flagGroup{{"Known", []string{"grouped"}}})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Usage(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "--forgotten") {
		t.Errorf("an ungrouped flag vanished from help:\n%s", out.String())
	}
}

// scanCommandFromRoot returns the scan command as it is assembled for a real invocation.
func scanCommandFromRoot(t *testing.T) *cobra.Command {
	t.Helper()
	root := newRootCommand()
	for _, c := range root.Commands() {
		if c.Name() == "scan" {
			c.InitDefaultHelpFlag()
			return c
		}
	}
	t.Fatal("the root command has no scan subcommand")
	return nil
}

// TestEveryScanFlagIsInTheReference keeps the CLI reference from falling behind the command.
//
// The reference is where people look when the help is too terse, and a flag missing from it is a
// capability that exists, works, and cannot be found by anyone who did not already know. That is
// how `--report` came to be explained in prose three sections down while absent from the table
// listing every flag.
func TestEveryScanFlagIsInTheReference(t *testing.T) {
	t.Parallel()
	doc, err := os.ReadFile("../../docs/reference/cli.md")
	if err != nil {
		t.Fatalf("read the CLI reference: %v", err)
	}
	ref := string(doc)

	cmd := scanCommandFromRoot(t)
	var undocumented []string
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Name == helpFlag {
			return
		}
		// The row may name a shorthand too (`-o, --output`), so match the long form anywhere in a
		// backticked flag name rather than at the start of one.
		if !strings.Contains(ref, "`--"+f.Name+"`") && !strings.Contains(ref, ", --"+f.Name+"`") {
			undocumented = append(undocumented, "--"+f.Name)
		}
	})
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("docs/reference/cli.md never mentions %v — a flag absent from the reference is one "+
			"nobody who did not already know about it can find", undocumented)
	}
}
