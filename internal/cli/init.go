package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/scaffold"
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
		Long: "Write a starter draugr.saga.yaml into the given directory (default: the current one).\n" +
			"init reads the tree for dependency files, copied JavaScript, Terraform, Helm, Kubernetes,\n" +
			"Dockerfiles and OpenAPI documents and enables the scanners they call for, each with a comment\n" +
			"naming the files behind it. It lists the dependency files no scanner can take packages from.\n" +
			"Edit the file, then `draugr scan`. For an instant scan with no file, use `draugr scan .`.\n\n" +
			"--per-directory writes a component for each directory that holds its own dependency file,\n" +
			"scoped with paths: and carved out of the root component with ignore:. A JavaScript workspace\n" +
			"member stays with the workspace root, whose lockfile resolves it.\n\n" +
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
			if !cmd.Flags().Changed("output") {
				name := "draugr.saga.yaml"
				if opts.fragment {
					name = "draugr.saga-fragment.yaml"
				}
				opts.output = filepath.Join(dir, name)
			}
			return runInit(dir, *opts, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&opts.output, "output", "o", "",
		"path to write the Saga, relative to the working directory (- for stdout; default [dir]/draugr.saga.yaml)")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "overwrite an existing file")
	cmd.Flags().BoolVar(&opts.perDirectory, "per-directory", false,
		"write a component for each directory that holds its own dependency file, scoped by paths:")
	cmd.Flags().BoolVar(&opts.fragment, "fragment", false,
		"write a Saga fragment (a component, no release or policy) instead of a Saga")
	return cmd
}

// runInit scaffolds a Saga for dir, writing it to opts.output (or stdout).
func runInit(dir string, opts initOptions, w io.Writer) error {
	// Folded to what a project name may be, rather than taken as the directory is spelled.
	//
	// `init` in a directory called `My.Service` wrote `project: My.Service`, which Draugr rejects,
	// so the scaffold this command exists to produce failed the validation of the very next
	// command it suggests. A capital letter or a dot in a directory name is ordinary, and being
	// told to go and fix the file the tool just wrote is the worst possible first minute.
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	name := scaffold.NameFor(dir)
	tree := inventory.Read(dir)
	at := sagaPlace(dir, opts.output)
	body := scaffold.SagaAt(tree, name, opts.perDirectory, at.url)
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
	writeInitSummary(w, tui.For(w), tree, opts, at)
	return nil
}

// place is where a scaffolded Saga's repository url points and where its next commands run.
type place struct {
	// url is the repository every component names.
	url string
	// cd is the directory the next commands run from, empty for the working directory.
	cd string
	// path is the Saga as the next commands name it, from cd.
	path string
}

// sagaPlace decides the repository url of a Saga for dir written to output.
//
// A relative url resolves against the directory Draugr runs in, not the descriptor's. A Saga
// written inside dir, at its root or below it as `.draugr/self.saga.yaml` is, travels with the
// repository and runs from dir, so it says Here and the next commands change into dir first. A
// Saga written outside dir, or to stdout, runs from where init ran, so it names dir as given,
// which resolves from there.
func sagaPlace(dir, output string) place {
	p := place{url: givenURL(dir), path: output}
	if output == "-" {
		return p
	}
	absDir, errDir := filepath.Abs(dir)
	absOut, errOut := filepath.Abs(output)
	if errDir != nil || errOut != nil {
		return p
	}
	rel, err := filepath.Rel(absDir, absOut)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return p
	}
	p.url = scaffold.Here
	if wd, err := os.Getwd(); err == nil && wd != absDir {
		p.cd, p.path = dir, rel
	}
	return p
}

// givenURL is dir as a repository url read from the working directory: the path as typed, with a
// relative path holding a colon anchored by ./, since git reads host:path as an scp-style remote.
func givenURL(dir string) string {
	d := filepath.Clean(dir)
	if d == "." {
		return scaffold.Here
	}
	if strings.Contains(d, ":") && !filepath.IsAbs(d) && !strings.HasPrefix(d, ".") {
		return scaffold.Here + string(filepath.Separator) + d
	}
	return d
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
	b.WriteString("  - name: " + scaffold.Scalar(name) + "\n")
	b.WriteString("    # Set exposure and criticality in the root descriptor or in the fragment listed first:\n")
	b.WriteString("    # the first file to set a field wins, the root descriptor before any fragment.\n")
	b.WriteString("    # exposure: internal        # public | authenticated | internal | restricted\n")
	b.WriteString("    # criticality: important    # critical | important | supporting\n")
	b.WriteString("    repositories:\n")
	b.WriteString("      - url: " + scaffold.Here + "\n")
	return b.String()
}
