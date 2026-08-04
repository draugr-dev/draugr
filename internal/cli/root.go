// Package cli assembles the Draugr command-line interface on top of Cobra.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/observability"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/internal/version"
)

type globalOptions struct {
	logLevel  string
	logFormat string
	offline   bool
	config    string
}

// rootConfigPath is the --config value, read by the config and scan commands.
//
// A package-level value for the same reason offline is one: it is decided once at startup and
// every command that loads configuration must see the same answer. Threading it through every
// constructor would let one path forget.
var rootConfigPath string

func newRootCommand() *cobra.Command {
	opts := &globalOptions{}

	cmd := &cobra.Command{
		Use:   "draugr",
		Short: "Developer-first, descriptor-driven security and compliance qualification",
		Long: "Draugr — describe your app, and Draugr figures out which checks apply, runs\n" +
			"the right tools, and produces a pass/fail verdict with evidence.\n\n" +
			"Security controls (SAST, SCA, secrets, IaC, DAST, TLS, headers) and compliance\n" +
			"evidence (SBOMs) from the same descriptor and the same gate.",
		// `draugr version` is the command; this makes `--version` the same answer under the
		// spelling every other CLI uses. Cobra adds the flag from this field alone — without it
		// the near-universal `draugr --version` exits non-zero on "unknown flag", which a
		// container smoke test or a tool-cache probe reads as a broken binary.
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			logger, err := observability.NewLogger(cmd.ErrOrStderr(), observability.LogOptions{
				Level:  opts.logLevel,
				Format: opts.logFormat,
			})
			if err != nil {
				return err
			}
			observability.SetDefault(logger)
			// Recorded once, here, so every network call in the process reads the same answer
			// rather than each deciding for itself.
			if opts.offline {
				netpolicy.SetOffline(true)
			}
			rootConfigPath = opts.config
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&opts.logLevel, "log-level", "info",
		"log level: trace, debug, info, warn, error (trace relays scanner output)")
	cmd.PersistentFlags().StringVar(&opts.logFormat, "log-format", "console",
		"log format: console (human-readable, colorized on a terminal), json, or text")
	cmd.PersistentFlags().StringVar(&opts.config, "config", "",
		"machine/organisation settings file, used instead of the discovered ones (also DRAUGR_CONFIG)")
	cmd.PersistentFlags().BoolVar(&opts.offline, "offline", false,
		"make no network calls: skip optional fetches, and refuse rather than download (also DRAUGR_OFFLINE=1)")

	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newSchemaCommand())
	cmd.AddCommand(newInitCommand())
	cmd.AddCommand(newScanCommand())
	cmd.AddCommand(newDiffCommand())
	cmd.AddCommand(newSurveyCommand())
	cmd.AddCommand(newClassifyCommand())
	cmd.AddCommand(newValidateCommand())
	cmd.AddCommand(newDoctorCommand())
	cmd.AddCommand(newToolsCommand())
	cmd.AddCommand(newFeedsCommand())
	cmd.AddCommand(newConfigCommand())
	cmd.AddCommand(newControlsCommand())
	cmd.AddCommand(newMCPCommand())
	cmd.AddCommand(newSelfUpdateCommand())
	// Cobra's default template prints "draugr version X". Overriding it means the flag and the
	// subcommand produce the same bytes, so a script that parses one parses the other.
	cmd.SetVersionTemplate(version.String() + "\n")
	return cmd
}

// Execute builds and runs the root command using the process arguments, wiring telemetry
// around it. It returns a process exit code.
func Execute(ctx context.Context) int {
	return execute(ctx, os.Args[1:])
}

// execute runs the root command with the given args; separated from Execute so it can be
// driven in tests.
func execute(ctx context.Context, args []string) int {
	shutdownTraces, err := observability.InitTracing(ctx, "draugr", version.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "draugr: telemetry init: "+err.Error())
		return 1
	}
	defer func() { _ = shutdownTraces(context.Background()) }()

	shutdownMetrics, err := observability.InitMetrics(ctx, "draugr", version.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "draugr: telemetry init: "+err.Error())
		return 1
	}
	defer func() { _ = shutdownMetrics(context.Background()) }()

	ctx, span := otel.Tracer("draugr").Start(ctx, "cli.execute")
	defer span.End()

	// Make tools provisioned by `draugr tools install` (~/.draugr/bin) discoverable to the
	// scanners we spawn and to `doctor`, without the user editing their shell. Best-effort.
	if dir, err := tools.BinDir(); err == nil {
		_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}

	root := newRootCommand()
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		span.RecordError(err)
		fmt.Fprintln(os.Stderr, "draugr: "+err.Error())
		return 1
	}
	return 0
}
