package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/surveyors"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

// newSurveyProvenanceCommand reads the signature on each image the descriptor declares and
// proposes the signers that would accept it.
//
// The only surveyor that discovers from the descriptor rather than from a system it can name, so
// it is the only one that reads --output before running instead of only writing to it. There is
// nothing else to point it at: the images are the question.
func newSurveyProvenanceCommand(opts *surveyOptions) *cobra.Command {
	var trustRoot string
	cmd := &cobra.Command{
		Use:   "provenance",
		Short: "Discover who signs the images you already declare",
		Long: "Reads the Sigstore signature on each image in the descriptor and writes the\n" +
			"`signers:` that would accept it.\n\n" +
			"Writing a signer by hand means knowing the identity a build signs with. A job\n" +
			"calling a reusable workflow is signed as that workflow's repository rather than\n" +
			"as the caller, so the obvious value is the wrong one, and it fails later as a\n" +
			"mismatch rather than as a syntax error.\n\n" +
			"What it writes is the exact identity and the exact image, never a pattern. A\n" +
			"pattern loose enough to be convenient accepts signatures from people you did not\n" +
			"mean to trust, and the schema cannot refuse one for recognizing too many.\n\n" +
			"Read the signers it proposes before you rely on them. This records what signs\n" +
			"your images today, which is a tripwire for that changing rather than proof that\n" +
			"today's answer is the right one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			images, err := declaredImages(*opts)
			if err != nil {
				return err
			}
			scope := plugin.SurveyScope{Config: plugin.Config{
				surveyors.ProvenanceImagesKey: images,
			}}
			if trustRoot != "" {
				scope.Config[surveyors.ProvenanceTrustRootKey] = trustRoot
			}
			return runSurvey(cmd.Context(), *opts, []surveyor.Request{{
				Surveyor: "provenance-signers", Scope: scope,
			}}, builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&trustRoot, "trust-root", "",
		"a Sigstore trusted-root file to read against, for an organization running its own")
	return cmd
}

// declaredImages lists every image in the descriptor being added to, deduplicated and ordered.
//
// A digest where the descriptor pins one, because that is what the signature was read against. A
// tag can be repointed afterwards, so a signer adopted from one says less than the same signer
// adopted from a digest, and the command says which it was.
func declaredImages(opts surveyOptions) ([]string, error) {
	if !opts.mergesInto() {
		return nil, fmt.Errorf("--output must name a descriptor that already exists: " +
			"this reads the images it declares, and there is nothing to read in a new one")
	}
	model, err := baseModel(opts)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, comp := range model.Components {
		for _, img := range comp.Images {
			ref := imageRef(img)
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			out = append(out, ref)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s declares no images; survey a cluster first, or add them to a "+
			"component", opts.output)
	}
	sort.Strings(out)
	return out, nil
}

// imageRef is the reference to ask the registry about.
//
// The tag is cut only after the last slash. A registry carrying a port puts a colon in the host,
// and cutting at the first one turns `registry.local:5000/acme/api:1.0` into `registry.local`,
// which is a question about a different thing that the registry answers without complaint.
func imageRef(img saga.Image) string {
	if img.Digest == "" {
		return img.Image
	}
	name := img.Image
	if at := strings.LastIndex(name, "/"); strings.Contains(name[at+1:], ":") {
		name = name[:at+1+strings.Index(name[at+1:], ":")]
	}
	if name == "" {
		return img.Digest
	}
	return name + "@" + img.Digest
}
