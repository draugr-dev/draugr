package controllers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	provenanceControl = "provenance"
	cosignScanner     = "cosign"
	notationScanner   = "notation"

	signersKey    = "signers"
	trustStoreKey = "trustStore"
	subjectKey    = "subject"
	unmatchedKey  = "unmatched"
	trustRootKey  = "trustRoot"
)

// Unmatched is what an image no signer covers is worth.
const (
	// unmatchedObserve reports the identity found and expects nothing. The default, because most
	// of what a project runs is published by somebody else and carries no signature at all.
	unmatchedObserve = "observe"
	// unmatchedWarn reports the same absence as a warning.
	unmatchedWarn = "warn"
	// unmatchedFail requires every image to be covered by a signer. The end state for a project
	// that has worked through its inventory, and the reason the ramp has somewhere to arrive.
	unmatchedFail = "fail"
)

// Provenance is the artifact-provenance control. It asks, for each image a component declares,
// whether the artifact can be shown to come from where it claims: signed, and signed by the
// identity this descriptor expects.
//
// What it does not answer is whether the artifact is safe. A signature binds an artifact to a
// builder, and a builder that has been compromised signs what it is told to. Malicious packages
// have shipped with valid attestations naming the real repository and the real workflow that
// built them. So this control never relaxes another one, and its findings say what they establish
// rather than implying more.
type Provenance struct{}

// NewProvenance returns the provenance controller.
func NewProvenance() plugin.Controller { return Provenance{} }

// Info identifies the controller (component-scoped).
func (Provenance) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            provenanceControl,
		Scope:           plugin.ScopeComponent,
		Summary:         "Check that a container image is signed by the identity this descriptor expects.",
		DefaultScanners: []string{cosignScanner, notationScanner},
		OptionSchema:    provenanceOptionSchema,
	}
}

// provenanceOptionSchema describes the signers and the two settings that govern them.
//
// A signer carries the scope it applies to rather than the control carrying a default. Something
// that applies only under a prefix is a scoped rule, and the scope belongs on the thing it scopes.
// It also keeps the control out of deciding which images are "ours", a judgment it would get wrong
// on a surveyed cluster, where every image arrives with no `builtBy` and reads as self-built.
var provenanceOptionSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "signers": {
      "type": "array",
      "description": "Who is expected to have signed what. A signer names itself, the images it covers, and the identity to check against.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["name"],
        "properties": {
          "name": {
            "type": "string",
            "description": "What to call this signer, e.g. \"our-ci\". Referenced by an image's signedBy."
          },
          "images": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Image references this signer covers, where * matches any run of characters, e.g. [\"ghcr.io/acme/*\"]. An image no signer covers is observed rather than checked."
          },
          "keyless": {
            "type": "object",
            "additionalProperties": false,
            "description": "A Sigstore keyless signature, identified by who issued the token and which workload it named.",
            "properties": {
              "issuer": {
                "type": "string",
                "description": "The OIDC issuer, e.g. \"https://token.actions.githubusercontent.com\" for GitHub Actions or your GitLab instance URL for GitLab CI."
              },
              "identity": {
                "type": "string",
                "description": "The exact signing identity, e.g. \"https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3\". A job calling a reusable workflow is signed as that workflow, not as the caller. Run the control with no signers declared and read it back from --format sarif."
              },
              "identityRegexp": {
                "type": "string",
                "description": "A Go regular expression the identity must match, for a signer covering several workflows. A pattern loose enough to match anything accepts a signature from anybody."
              }
            }
          },
          "x509": {
            "type": "object",
            "additionalProperties": false,
            "description": "A Notary Project signature, identified by the certificate it carries and the roots that certificate must chain to. What Azure Pipelines produces with a key in Azure Key Vault, and what an in-house PKI produces.",
            "properties": {
              "trustStore": {
                "type": "string",
                "description": "Path to a PEM file of root certificates the signing certificate must chain to, relative to where Draugr runs."
              },
              "subject": {
                "type": "string",
                "description": "The certificate subject to require, as a comma-separated distinguished name, e.g. \"C=US, ST=WA, O=Acme, CN=Acme Release Signing\". Run notation inspect on the image to read the exact string."
              }
            }
          },
          "github": {
            "type": "object",
            "additionalProperties": false,
            "description": "A GitHub Actions signer written as its parts. Expands to the keyless issuer and identity, which draugr validate prints.",
            "properties": {
              "repository": {
                "type": "string",
                "description": "The repository whose workflow signs, as owner/name. A job calling a reusable workflow is signed as that workflow's repository, not as the caller's."
              },
              "workflow": {
                "type": "string",
                "description": "The workflow file, e.g. \".github/workflows/release.yml\"."
              },
              "ref": {
                "type": "string",
                "description": "The git ref the workflow ran at, e.g. \"refs/heads/main\" or \"refs/tags/v3\"."
              }
            }
          }
        }
      }
    },
    "unmatched": {
      "type": "string",
      "description": "What an image no signer covers is worth. Defaults to observe.",
      "anyOf": [
        {"const": "observe", "description": "Report the identity found and expect nothing. Most of what a project runs is published by somebody else, so this is where a policy starts rather than where it ends."},
        {"const": "warn", "description": "Report an image no signer covers as a warning, without failing the gate on it."},
        {"const": "fail", "description": "Require every image to be covered by a signer. The end state, once the inventory has been worked through."}
      ]
    },
    "trustRoot": {
      "type": "string",
      "description": "Path to a Sigstore trusted-root JSON file, for a runner that cannot reach the transparency log. Without one, a runner with no egress reports an error rather than a pass."
    }
  }
}`)

// signer is one resolved expectation: who should have signed, and how to recognize them.
type signer struct {
	Name     string
	Images   []string
	Issuer   string
	Identity string
	Regexp   string
	// TrustStore is a PEM file of root certificates a Notary Project signature must chain to, and
	// Subject the certificate subject it must carry. Both set, or neither: this is the X.509 trust
	// model rather than the keyless one, and a signer belongs to exactly one.
	TrustStore string
	Subject    string
	// Display is the identity a shorthand stands for, written the way it appears in a
	// certificate rather than as the pattern cosign is given.
	//
	// Only for explaining. A reader comparing what they meant against a regular expression is
	// reading backslashes instead of an identity, which is the opposite of what printing the
	// expansion is for.
	Display string
}

// githubIssuer is the OIDC issuer every GitHub Actions workflow authenticates to.
const githubIssuer = "https://token.actions.githubusercontent.com"

// Plan produces one verification job per image declared on the component.
func (Provenance) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	signers, err := provenanceSigners(model, comp)
	if err != nil {
		return nil, err
	}
	settings := provenanceSettings(model, comp)
	selections := resolveScanners(model, comp, provenanceControl, []string{cosignScanner, notationScanner})

	jobs := make([]plugin.ScanJob, 0, len(comp.Images))
	for _, img := range comp.Images {
		expected, err := signerFor(signers, img)
		if err != nil {
			return nil, err
		}
		// One scanner per image, chosen by the trust model the signer belongs to. Both are
		// defaults, so a descriptor can still switch either off and have it stay off; what it
		// cannot do is run a Sigstore verifier against a Notary signature, which would report
		// every X.509-signed image as unsigned.
		want := scannerForSigner(expected)
		for _, sel := range selections {
			if sel.Name != want {
				continue
			}
			cfg := plugin.Config{}
			for k, v := range sel.Config {
				cfg[k] = v
			}
			// The expectation is the control's, so every scanner serving it judges by the same
			// one. Resolved here rather than in the scanner: which signer covers an image is a
			// reading of the descriptor, and a reading that two scanners did separately is two
			// readings.
			//
			// Written on every job, including the empty case. The scanner's block is refused these
			// keys, and overwriting them as well means a descriptor that reached one anyway cannot
			// decide what is verified: an identity pattern loose enough to match anything would
			// otherwise turn the control green without changing the signer it appears to obey.
			var e signer
			if expected != nil {
				e = *expected
			}
			// Every key the scanner reads, written on every job, and none that it does not. All
			// of them, because a key left absent could be supplied from the scanner's own block;
			// none of the others, because a scanner's schema is closed and a key it has no use
			// for would fail the job rather than be ignored.
			cfg["signer"] = e.Name
			switch want {
			case notationScanner:
				cfg[trustStoreKey], cfg[subjectKey] = e.TrustStore, e.Subject
			default:
				cfg["issuer"], cfg["identity"], cfg["identityRegexp"] = e.Issuer, e.Identity, e.Regexp
				cfg[unmatchedKey] = settings.unmatched
				cfg[trustRootKey] = settings.trustRoot
			}
			jobs = append(jobs, plugin.ScanJob{
				Scanner: sel.Name,
				Target:  plugin.ImageTarget{Ref: img.Image, Digest: img.Digest},
				Config:  cfg,
			})
		}
	}
	return jobs, nil
}

// Aggregate merges the scan reports and summarizes findings by severity.
//
// It also collapses what each job said about itself into one account of the run. How an image was
// named is a fact about the strength of the check rather than about the artifact, so it belongs
// with what the control was measured against and not among the findings. Emitting it as a finding
// would put "pin this digest" directly beneath an unexpected-identity row, where the digest is
// the artifact somebody else built and following the advice pins it for good.
func (Provenance) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	merged.Provenance = provenanceAccount(reports)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: provenanceControl,
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}

// provenanceAccount turns one entry per image into one line for the run: who was expected, and
// how many images were named in a way that pins them.
//
// Counted over the reports rather than the merged one, which drops duplicates: four images
// checked against the same signer are one entry after merging and four facts before it.
func provenanceAccount(reports []sarif.Report) []sarif.Provenance {
	signers := map[string]bool{}
	verifiers := map[string]bool{}
	var images, byDigest, unsigned, verified, observedCount int
	var observed []string
	for _, rep := range reports {
		for _, p := range rep.Provenance {
			if p.Tool == "" {
				continue
			}
			verifiers[p.Tool] = true
			images++
			for _, f := range p.Fields {
				switch {
				case f.Key == "signer" && f.Value != "" && f.Value != "no signer declared":
					signers[f.Value] = true
					verified++
				case f.Key == "pinned" && f.Value == "digest":
					byDigest++
				case f.Key == "observed" && strings.HasSuffix(f.Value, "\tunsigned"):
					unsigned++
				case f.Key == "observed":
					observedCount++
					observed = append(observed, f.Value)
				}
			}
		}
	}
	if images == 0 {
		return nil
	}

	// The shape the other controls in this block use: what was covered, over what, and the one
	// qualifier that changes how much the coverage is worth. `coverage` and `scope` are the
	// infrastructure control's own keys, carrying the same meaning here.
	//
	// Counts, not lists. The things worth saying grow with the descriptor: an identity is about
	// ninety-five characters and a project can declare a dozen signers over twenty images. Written
	// out, three of them filled the line and the rest were cut, so the account reported less than
	// it had at exactly the sizes where it mattered. A count says the same thing at any size.
	fields := []sarif.Field{
		{Key: "coverage", Value: describeCoverage(images, verified, observedCount, unsigned)},
		{Key: "scope", Value: describeScope(len(signers))},
	}
	// Said whether or not anything failed. A green verdict over images named by tag is a weaker
	// statement than it looks, and this is the line that says so. Stated as what is pinned rather
	// than what is not, so the number a reader is working to move is the number that grows.
	//
	// Not said where nothing was verified. Pinning qualifies a verification, and a run with no
	// policy has none to qualify.
	if verified > 0 {
		fields = append(fields, sarif.Field{Key: "pinning", Value: describePinning(byDigest, images)})
	}
	// Every verifier that ran, not the one this control reaches for most. A descriptor whose
	// signers use two trust models is checked by two tools, and a row naming only one credits it
	// with work it did not do while leaving the other unaccounted for.
	names := make([]string, 0, len(verifiers))
	for name := range verifiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return []sarif.Provenance{{Tool: strings.Join(names, ", "), Fields: fields, Detail: observedIdentities(observed)}}
}

// observedIdentities is who signed each image this descriptor has not named a signer for, in full.
//
// The answer to "what do I put in `identity`", which is a question somebody has while writing a
// descriptor rather than while reading a terminal. It goes in Detail, so a run over an inventory
// of any size carries every one of them to a consumer and none of them to the console row.
//
// The identity whole, scheme and host included, because this is the value to copy and a shortened
// one does not verify anything.
func observedIdentities(observed []string) []sarif.Field {
	sort.Strings(observed)
	out := make([]sarif.Field, 0, len(observed))
	for _, o := range observed {
		ref, subject, issuer := splitObserved(o)
		if subject == "" || subject == "unsigned" {
			continue
		}
		// Both halves, under their own keys. An identity is only an expectation together with who
		// issued it: the same string from a different issuer is a different signer, and a
		// descriptor naming one without the other does not describe a check. They are also the
		// two fields a `keyless:` signer is written from, so this is the shape of the answer.
		out = append(out, sarif.Field{Key: ref + " identity", Value: subject})
		if issuer != "" {
			out = append(out, sarif.Field{Key: ref + " issuer", Value: issuer})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// splitObserved unpacks what the scanner recorded about one image's signature: the reference, the
// identity on it, and who issued that identity. An unsigned image records only the first two, the
// second being the word "unsigned".
func splitObserved(note string) (ref, subject, issuer string) {
	parts := strings.Split(note, "\t")
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts[0], parts[1], parts[2]
}

// describeScope is how much of a policy the run was measured against.
//
// The count rather than the names. A signer's identity answers a different question, "which one
// refused", and that one is answered on the finding, beside the image it refused.
func describeScope(signers int) string {
	if signers == 0 {
		return "no signers declared"
	}
	return plural(signers, "signer")
}

// describeCoverage says what happened to the images, in the vocabulary the control uses: an image
// is checked against a signer, observed because none covers it, or carries nothing at all.
func describeCoverage(total, verified, observed, unsigned int) string {
	head := fmt.Sprintf("%d of %s checked", verified, plural(total, "image"))
	rest := make([]string, 0, 2)
	if observed > 0 {
		rest = append(rest, fmt.Sprintf("%d observed", observed))
	}
	if unsigned > 0 {
		rest = append(rest, fmt.Sprintf("%d unsigned", unsigned))
	}
	if len(rest) == 0 {
		return head
	}
	return head + ", " + strings.Join(rest, ", ")
}

// describePinning says how many images were named in a way that pins what was verified.
//
// An image named by tag is verified against whatever that tag pointed at during the run, and the
// tag can be moved to other bytes afterwards. A digest names the bytes, so a verdict over one
// still describes the artifact somebody pulls a week later.
func describePinning(byDigest, total int) string {
	switch byDigest {
	case 0:
		return "none, all by tag"
	case total:
		return fmt.Sprintf("all %d by digest", total)
	}
	return fmt.Sprintf("%d of %d by digest", byDigest, total)
}

// plural renders a count with its noun, so a single image is not "1 images".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Validate reports the mistakes a schema cannot see: an image naming a signer nobody declared,
// two signers claiming the same image, and a signer that declares no way to be recognized.
//
// Each of them fails the same way without this, and it is the way that matters: no expectation
// resolves, the image falls through to observed, and the scan passes having verified nothing. A
// control that reports a pass it did not establish is worse than one that is not there.
func (Provenance) Validate(model saga.Model) []error {
	var problems []error
	problems = append(problems, noScannerLevelExpectation("config.controls", model.Config.Controls)...)
	for i := range model.Components {
		comp := &model.Components[i]
		problems = append(problems, noScannerLevelExpectation(
			fmt.Sprintf("components[%q].controls", comp.Name), comp.Controls)...)
		signers, err := provenanceSigners(model, comp)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		for _, img := range comp.Images {
			if _, err := signerFor(signers, img); err != nil {
				problems = append(problems, fmt.Errorf("components[%q].controls.%s: %w", comp.Name, provenanceControl, err))
			}
		}
	}
	return problems
}

// controlSetKeys are the job-config keys the control writes, which a descriptor may not.
//
// The scanner declares them because the engine holds a job's config to its scanner's schema, and
// declaring them is what makes a descriptor able to write them. So they are refused here.
//
// Not merely tidiness. `identityRegexp` matching anything accepts a signature from whoever offers
// one, and a scanner block that could set it would be a way to make the control pass without
// touching the signer that appears to govern it. Plan overwrites all of them on every job, so this
// refuses a key that would do nothing rather than one that would do harm, which is the right order
// to build the two guarantees in.
var controlSetKeys = []string{"signer", "issuer", "identity", "identityRegexp", unmatchedKey, trustRootKey}

// noScannerLevelExpectation refuses a control-set key written under a scanner's own block.
func noScannerLevelExpectation(where string, controls map[string]saga.ControllerSettings) []error {
	block, ok := asMap(controls[provenanceControl][configKeyFor(cosignScanner)])
	if !ok {
		return nil
	}
	var problems []error
	for _, key := range controlSetKeys {
		if _, written := block[key]; !written {
			continue
		}
		problems = append(problems, fmt.Errorf(
			"%s.%s.%s: %q is resolved from the signers and cannot be set on a scanner. "+
				"Write it under %s.%s.signers",
			where, provenanceControl, cosignScanner, key, where, provenanceControl))
	}
	return problems
}

// Explain states what a `github:` shorthand expanded to.
//
// The shorthand exists because the literal identity has traps that fail as a mismatch rather than
// as a syntax error, which means a wrong one looks exactly like a right one until a scan says
// otherwise. Printing what it built is what makes a generated value readable before anything
// depends on it.
func (Provenance) Explain(model saga.Model) []string {
	var out []string
	seen := map[string]bool{}
	settings := []saga.ControllerSettings{model.Config.Controls[provenanceControl]}
	for _, comp := range model.Components {
		settings = append(settings, comp.Controls[provenanceControl])
	}
	for _, s := range settings {
		for _, raw := range settingList(s, signersKey) {
			m, ok := asMap(raw)
			if !ok {
				continue
			}
			if _, isShorthand := asMap(m["github"]); !isShorthand {
				continue
			}
			parsed, err := parseSigner(raw)
			if err != nil || seen[parsed.Name] {
				continue
			}
			seen[parsed.Name] = true
			out = append(out, fmt.Sprintf("provenance: signer %q expects\n%s\nissued by %s",
				parsed.Name, parsed.Display, parsed.Issuer))
		}
	}
	return out
}

// provenanceSettings holds the two settings that are not a signer.
type provenanceOptions struct {
	unmatched string
	trustRoot string
}

// provenanceSettings reads them from the project block, with the component's winning.
func provenanceOptionsFrom(project, component saga.ControllerSettings) provenanceOptions {
	s := provenanceOptions{unmatched: unmatchedObserve}
	for _, settings := range []saga.ControllerSettings{project, component} {
		if v, ok := settings[unmatchedKey].(string); ok && v != "" {
			s.unmatched = v
		}
		if v, ok := settings[trustRootKey].(string); ok && v != "" {
			s.trustRoot = v
		}
	}
	return s
}

func provenanceSettings(model saga.Model, comp *saga.Component) provenanceOptions {
	var component saga.ControllerSettings
	if comp != nil {
		component = comp.Controls[provenanceControl]
	}
	return provenanceOptionsFrom(model.Config.Controls[provenanceControl], component)
}

// provenanceSigners reads the signers a component is judged by: the project's, plus any the
// component declares.
//
// Added to rather than replaced, the way the licenses control unions its policy lists. A component
// that declared one signer and thereby discarded the organization's would stop checking most of
// what it runs, silently, and the descriptor would still read as a policy.
func provenanceSigners(model saga.Model, comp *saga.Component) ([]signer, error) {
	var out []signer
	seen := map[string]bool{}
	add := func(settings saga.ControllerSettings, where string) error {
		for _, raw := range settingList(settings, signersKey) {
			s, err := parseSigner(raw)
			if err != nil {
				return fmt.Errorf("%s.%s: %w", where, provenanceControl, err)
			}
			if seen[s.Name] {
				return fmt.Errorf("%s.%s: two signers are called %q; a name is how an image asks for one",
					where, provenanceControl, s.Name)
			}
			seen[s.Name] = true
			out = append(out, s)
		}
		return nil
	}
	if err := add(model.Config.Controls[provenanceControl], "config.controls"); err != nil {
		return nil, err
	}
	if comp != nil {
		if err := add(comp.Controls[provenanceControl], fmt.Sprintf("components[%q].controls", comp.Name)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// settingList reads a list of raw entries from a control's settings.
func settingList(settings saga.ControllerSettings, key string) []any {
	v, ok := settings[key]
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	return list
}

// parseSigner reads one signer entry, expanding the `github` shorthand into the issuer and
// identity it stands for.
func parseSigner(raw any) (signer, error) {
	m, ok := asMap(raw)
	if !ok {
		return signer{}, fmt.Errorf("a signer is written as a block with a name, got %T", raw)
	}
	s := signer{
		Name:   stringAt(m, "name"),
		Images: stringsAt(m, "images"),
	}
	if s.Name == "" {
		return signer{}, fmt.Errorf("a signer needs a name; it is how an image asks for one")
	}
	keyless, hasKeyless := asMap(m["keyless"])
	gh, hasGitHub := asMap(m["github"])
	x509, hasX509 := asMap(m["x509"])
	declared := 0
	for _, has := range []bool{hasKeyless, hasGitHub, hasX509} {
		if has {
			declared++
		}
	}
	switch {
	case declared > 1:
		return signer{}, fmt.Errorf("signer %q declares more than one of keyless, github and x509; a signature is checked one way, so a signer belongs to one trust model",
			s.Name)
	case hasX509:
		s.TrustStore = stringAt(x509, "trustStore")
		s.Subject = stringAt(x509, "subject")
		if s.TrustStore == "" {
			return signer{}, fmt.Errorf("signer %q declares no trustStore, so there is nothing for a certificate to chain to and any certificate would do",
				s.Name)
		}
		if s.Subject == "" {
			return signer{}, fmt.Errorf("signer %q declares no subject, so any certificate from that authority would pass; an authority is who may sign, not who did",
				s.Name)
		}
	case hasKeyless:
		s.Issuer = stringAt(keyless, "issuer")
		s.Identity = stringAt(keyless, "identity")
		s.Regexp = stringAt(keyless, "identityRegexp")
		if s.Identity != "" && s.Regexp != "" {
			return signer{}, fmt.Errorf("signer %q declares both identity and identityRegexp; one signature is checked against one of them",
				s.Name)
		}
		if s.Identity == "" && s.Regexp == "" {
			return signer{}, fmt.Errorf("signer %q declares no identity, so nothing about the signature would be checked; a signature from anybody is not provenance",
				s.Name)
		}
		if s.Issuer == "" {
			return signer{}, fmt.Errorf("signer %q declares no issuer; two providers can assert the same identity, so the identity alone does not name anybody",
				s.Name)
		}
	case hasGitHub:
		expanded, err := githubSigner(s.Name, gh)
		if err != nil {
			return signer{}, err
		}
		s.Issuer, s.Regexp, s.Display = expanded.Issuer, expanded.Regexp, expanded.Display
	default:
		return signer{}, fmt.Errorf("signer %q says nothing about who signs; declare keyless, github or x509", s.Name)
	}
	return s, nil
}

// githubSigner expands the GitHub shorthand into the issuer and the identity pattern Fulcio puts
// in the certificate.
//
// The shorthand exists because the literal string has two traps and neither fails loudly. The
// identity is a URL with the workflow path inside it, so a missing or doubled separator reads
// correctly and matches nothing. And Fulcio derives the identity from the workflow that ran, so a
// job calling a shared workflow is signed as that workflow's repository rather than as the
// caller's: somebody writing their own repository here is writing the one place it is not.
func githubSigner(name string, gh map[string]any) (signer, error) {
	repo, workflow, ref := stringAt(gh, "repository"), stringAt(gh, "workflow"), stringAt(gh, "ref")
	var missing []string
	for _, f := range []struct{ key, val string }{
		{"repository", repo}, {"workflow", workflow}, {"ref", ref},
	} {
		if f.val == "" {
			missing = append(missing, f.key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return signer{}, fmt.Errorf("signer %q: github needs %s; a part left out would match every value of it",
			name, strings.Join(missing, ", "))
	}
	literal := "https://github.com/" + repo + "/" + workflow + "@" + ref
	return signer{
		Issuer:  githubIssuer,
		Regexp:  "^" + regexp.QuoteMeta(literal) + "$",
		Display: literal,
	}, nil
}

// scannerForSigner picks the verifier for a signer's trust model, and Sigstore for an image no
// signer covers: reading back an unknown signer is something only the keyless side can do, because
// an X.509 check needs a trust store nobody has named.
func scannerForSigner(s *signer) string {
	if s != nil && s.TrustStore != "" {
		return notationScanner
	}
	return cosignScanner
}

// signerFor decides which signer covers an image: the one it names, or the one whose patterns
// match it. A nil signer with no error means no expectation, which the scanner reports as
// observed rather than verified.
func signerFor(signers []signer, img saga.Image) (*signer, error) {
	if img.SignedBy != "" {
		for i := range signers {
			if signers[i].Name == img.SignedBy {
				return &signers[i], nil
			}
		}
		return nil, fmt.Errorf("image %q is signed by %q, which no signer declares (%s)",
			img.Image, img.SignedBy, declaredSigners(signers))
	}
	var matched []*signer
	for i := range signers {
		for _, pattern := range signers[i].Images {
			if saga.WildcardMatch(pattern, img.Image) {
				matched = append(matched, &signers[i])
				break
			}
		}
	}
	switch len(matched) {
	case 0:
		return nil, nil
	case 1:
		return matched[0], nil
	}
	// Two expectations on one artifact is not "check both": it is a descriptor that does not say
	// what it wants. Requiring more than one signature is a real thing to want and a different
	// one, and it should be asked for rather than arrived at through overlapping patterns.
	names := make([]string, 0, len(matched))
	for _, s := range matched {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return nil, fmt.Errorf("image %q is covered by more than one signer (%s); narrow the patterns, or name one with signedBy",
		img.Image, strings.Join(names, ", "))
}

// declaredSigners names what is available, for an error about a name that is not.
func declaredSigners(signers []signer) string {
	if len(signers) == 0 {
		return "none are declared"
	}
	names := make([]string, 0, len(signers))
	for _, s := range signers {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return "it has " + strings.Join(names, ", ")
}

// stringAt reads a string field from a decoded block.
func stringAt(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// stringsAt reads a list of strings from a decoded block, skipping anything that is not one.
func stringsAt(m map[string]any, key string) []string {
	list, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
