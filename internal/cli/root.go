// Package cli assembles the Draugr command-line interface on top of Cobra.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	"github.com/draugr-dev/draugr/internal/observability"
	"github.com/draugr-dev/draugr/internal/version"
)

type globalOptions struct {
	logLevel  string
	logFormat string
}

func newRootCommand() *cobra.Command {
	opts := &globalOptions{}

	cmd := &cobra.Command{
		Use:   "draugr",
		Short: "Developer-first, descriptor-driven security scanning orchestration",
		Long: "Draugr — describe your app, and Draugr figures out which security controls\n" +
			"apply, runs the right scanners, and produces pass/fail evidence.",
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
			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&opts.logLevel, "log-level", "info",
		"log level: debug, info, warn, error")
	cmd.PersistentFlags().StringVar(&opts.logFormat, "log-format", "json",
		"log format: json, text")

	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newScanCommand())
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

	root := newRootCommand()
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		span.RecordError(err)
		fmt.Fprintln(os.Stderr, "draugr: "+err.Error())
		return 1
	}
	return 0
}
