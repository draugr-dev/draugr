package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

type initOptions struct {
	// fragment writes a Saga fragment rather than a Saga.
	fragment bool
	output   string
	force    bool
	// perDirectory writes a component for each directory holding its own dependency file.
	perDirectory bool
}

func newInitCommand() *cobra.Command {
	opts := &initOptions{}
	cmd := &cobra.Command{
		Use:   "init [dir]",
		Short: "Scaffold a draugr.saga.yaml for the current project",
		Long: "Write a starter Saga for the given directory (default: the current one). init reads the tree\n" +
			"for dependency files, copied JavaScript, Terraform, Helm, Kubernetes, Dockerfiles and OpenAPI\n" +
			"documents and enables the scanners they call for, each with a comment naming the files\n" +
			"behind it. It lists the dependency files no scanner can take packages from.\n" +
			"Edit the file, then `draugr scan`. For an instant scan with no file, use `draugr scan .`.\n\n" +
			"--per-directory writes a component for each directory that holds its own dependency file,\n" +
			"scoped with paths: and carved out of the root component with ignore:.\n\n" +
			"--fragment writes a Saga fragment instead: one component, no release and no policy,\n" +
			"for a descriptor assembled from several files. The component is named after the\n" +
			"directory; fragments naming the same component merge into one.\n\n" +
			"  draugr init services/payments --fragment\n" +
			"  draugr init services/payments --fragment -o azure.saga-fragment.yaml",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			if opts.fragment && !cmd.Flags().Changed("output") {
				opts.output = filepath.Join(dir, "draugr.saga-fragment.yaml")
			}
			return runInit(dir, *opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&opts.output, "output", "o", "draugr.saga.yaml", "path to write the Saga (- for stdout)")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "overwrite an existing file")
	cmd.Flags().BoolVar(&opts.perDirectory, "per-directory", false,
		"write a component for each directory that holds its own dependency file, scoped by paths:")
	cmd.Flags().BoolVar(&opts.fragment, "fragment", false,
		"write a Saga fragment (a component, no release or policy) instead of a Saga")
	return cmd
}

// runInit scaffolds a Saga for dir, writing it to opts.output (or stdout).
func runInit(dir string, opts initOptions, w io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	// Folded to what a project name may be, rather than taken as the directory is spelled.
	//
	// `init` in a directory called `My.Service` wrote `project: My.Service`, which Draugr rejects,
	// so the scaffold this command exists to produce failed the validation of the very next
	// command it suggests. A capital letter or a dot in a directory name is ordinary, and being
	// told to go and fix the file the tool just wrote is the worst possible first minute.
	name := projectNameFrom(filepath.Base(abs))
	tree := inventory.Read(dir)
	body := scaffoldSaga(tree, name, opts.perDirectory)
	if opts.fragment {
		body = scaffoldFragment(name)
	}
	saga := body

	if opts.output == "-" {
		_, err := io.WriteString(w, saga)
		return err
	}
	if !opts.force {
		if _, err := os.Stat(opts.output); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", opts.output)
		}
	}
	if err := os.WriteFile(opts.output, []byte(saga), 0o600); err != nil {
		return err
	}
	if opts.fragment {
		// A fragment is not scannable on its own. It has no release and no controls. Pointing at
		// `draugr scan` here would send someone to an error the tool could have avoided.
		_, _ = fmt.Fprintf(w, "✓ wrote %s\n\nNext, name it from a descriptor:\n"+
			"  fragments:\n    - path: \"**/%s\"\n\n"+
			"  draugr validate <saga> --resolved   # see the merged result\n",
			opts.output, filepath.Base(opts.output))
		return nil
	}
	writeInitSummary(w, tui.For(w), tree, opts)
	return nil
}

// scaffoldFragment writes a starter Saga fragment for one component.
//
// Much smaller than a Saga's scaffold, and necessarily so: `init` reads the tree to pre-fill
// `config.controls`, and a fragment may not carry controls. Policy stays in the descriptor
// that names it. What is left is the part worth automating anyway: the modeline, which is long
// and silently wrong if mistyped, and the component name.
//
// The name comes from the directory because it is the field that has to match across a
// component's fragments. A shared fragment and a per-cloud one agreeing on it is what makes them
// merge into one component instead of two.
func scaffoldFragment(name string) string {
	var b strings.Builder
	b.WriteString("# yaml-language-server: $schema=" + saga.FragmentSchemaURL + "\n")
	b.WriteString("# A Saga fragment: merged into any descriptor whose `fragments:` matches this file.\n")
	b.WriteString("# It may declare components and exclusions. Policy, the gate and which controls run\n")
	b.WriteString("# stays in the descriptor that names it, where a reviewer sees it.\n\n")
	b.WriteString("components:\n")
	b.WriteString("  - name: " + name + "\n")
	b.WriteString("    # exposure and criticality belong in the shared fragment: where two fragments\n")
	b.WriteString("    # describe one component, the first description of a field wins.\n")
	b.WriteString("    # exposure: internal        # public | authenticated | internal | restricted\n")
	b.WriteString("    # criticality: important    # critical | important | supporting\n")
	b.WriteString("    repositories:\n")
	b.WriteString("      - url: .\n")
	return b.String()
}

// projectNameFrom turns a directory name into one a descriptor accepts.
//
// Lowercase letters, digits and dashes, starting and ending with a letter or digit, which is what
// `pkg/saga` enforces. Anything else becomes a dash, runs of dashes collapse, and the ends are
// trimmed. A name with nothing usable left in it, which a directory of punctuation or of
// non-Latin script produces, falls back to the same placeholder an unnamed directory gets: a
// scaffold somebody renames beats one that will not load.
func projectNameFrom(dir string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(dir) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	// The rule wants a letter or digit at each end, and the trim above leaves one there or leaves
	// nothing at all.
	if name == "" {
		return "app"
	}
	return name
}
