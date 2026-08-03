package tools

import (
	"os/exec"
	"path/filepath"
)

// Attestation is what Draugr can say about the build of a tool a scan used.
//
// A scan runs whatever is on PATH, which is right: an operator may have an experimental build, a
// fork, or a distribution package with a vendor suffix, and each is a case where they know
// something Draugr does not. But a report that cannot say *which* build produced its findings
// cannot be reproduced, so the answer is to record it rather than to refuse it.
type Attestation struct {
	// Tool is the executable's name, e.g. "trivy".
	Tool string
	// Path is where it was found. Empty when it was not.
	Path string
	// Version is what the tool reports, when Draugr can read it.
	Version string
	// Attested reports that Draugr installed this exact binary and can vouch for its provenance:
	// the file is the one it wrote, unchanged, at the version it recorded.
	Attested bool
	// Reason says why not, for a reader deciding whether that matters to them.
	Reason string
}

// Attest reports what Draugr knows about the build of a tool.
//
// Attested means all three: the binary sits in Draugr's own directory, the install manifest has a
// record for it, and the file's hash still matches what was recorded. Anything else is used and
// labelled — a binary somewhere else on PATH, one Draugr never installed, or one that has changed
// since it did.
//
// The hash check is the one that earns its place. Without it "attested" would mean "in the right
// directory", which is a claim about a path rather than about a file.
func Attest(tool, path, version, binDir string) Attestation {
	a := Attestation{Tool: tool, Path: path, Version: version}
	switch {
	case path == "":
		a.Reason = "not found"
		return a
	case binDir == "" || filepath.Dir(path) != binDir:
		a.Reason = "found on PATH; Draugr did not install it"
		return a
	}

	rec, ok := loadManifest(binDir)[tool]
	if !ok {
		a.Reason = "in Draugr's directory but absent from its install record"
		return a
	}
	sum, err := fileSHA256(path)
	if err != nil {
		a.Reason = "could not be read to verify"
		return a
	}
	if sum != rec.BinarySHA256 {
		// Modified, replaced, or reinstalled by something else. Either way Draugr can no longer
		// say this is the file it fetched, which is the whole content of the claim.
		a.Reason = "changed since Draugr installed it"
		return a
	}
	if version == "" {
		a.Version = rec.Version
	}
	a.Attested = true
	return a
}

// AttestFound looks a tool up on PATH and attests to what it finds.
func AttestFound(tool, version string) Attestation {
	binDir, err := BinDir()
	if err != nil {
		binDir = ""
	}
	path, err := exec.LookPath(tool)
	if err != nil {
		path = ""
	}
	return Attest(tool, path, version, binDir)
}
