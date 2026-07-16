package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/selfupdate"
)

type selfUpdateOptions struct {
	version string
	check   bool
	yes     bool
}

// Injectable seams so the command can be tested without network I/O.
var (
	selfUpdateLatest = selfupdate.LatestVersion
	selfUpdateRun    = selfupdate.Update
)

func newSelfUpdateCommand() *cobra.Command {
	opts := &selfUpdateOptions{}
	cmd := &cobra.Command{
		Use:   "self-update",
		Short: "Update the draugr binary to the latest (or a specified) release",
		Long: "Update the running draugr binary in place to the latest published release (or a\n" +
			"specific --version), verified against the release's SHA-256 checksums and, when the\n" +
			"cosign CLI is present, its keyless signature.\n\n" +
			"For CI, pin a released version instead of self-updating.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSelfUpdate(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), *opts)
		},
	}
	cmd.Flags().StringVar(&opts.version, "version", "", "target release to install (default: latest)")
	cmd.Flags().BoolVar(&opts.check, "check", false, "report current vs latest available; make no changes")
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

func runSelfUpdate(ctx context.Context, w io.Writer, in io.Reader, opts selfUpdateOptions) error {
	cur := selfupdate.CurrentVersion()

	// --check: report current vs latest, change nothing.
	if opts.check {
		latest, err := selfUpdateLatest(ctx, nil)
		if err != nil {
			return fmt.Errorf("could not check for updates: %w", err)
		}
		_, _ = fmt.Fprintf(w, "current: %s\nlatest:  %s\n", cur, latest)
		if cur == latest {
			_, _ = fmt.Fprintln(w, "draugr is up to date.")
		} else {
			_, _ = fmt.Fprintln(w, "an update is available — run 'draugr self-update'.")
		}
		return nil
	}

	// Resolve the target for the confirmation message.
	target := strings.TrimPrefix(opts.version, "v")
	if target == "" {
		latest, err := selfUpdateLatest(ctx, nil)
		if err != nil {
			return fmt.Errorf("could not resolve the latest release: %w", err)
		}
		target = latest
	}
	if cur == target {
		_, _ = fmt.Fprintf(w, "draugr is already at %s.\n", cur)
		return nil
	}

	if !opts.yes {
		_, _ = fmt.Fprintf(w, "Update draugr %s → %s? [y/N] ", cur, target)
		if !confirmed(in) {
			_, _ = fmt.Fprintln(w, "Aborted.")
			return nil
		}
	}

	res, err := selfUpdateRun(ctx, selfupdate.Options{Version: target})
	if err != nil {
		return err
	}
	prov := "sha256 verified"
	if res.SignatureVerified {
		prov = "sha256 + cosign verified"
	} else if res.Note != "" {
		prov = "sha256 verified; " + res.Note
	}
	_, _ = fmt.Fprintf(w, "✓ updated draugr %s → %s (%s)\n  %s\n", res.Previous, res.Target, prov, res.Path)
	return nil
}

// confirmed reads a line and reports whether it is an affirmative (y/yes).
func confirmed(in io.Reader) bool {
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
