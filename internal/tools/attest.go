package tools

import (
	"os/exec"
	"path/filepath"
)

// Level is how strongly Draugr can vouch for a binary, strongest first.
//
// Not a boolean, because the claims are genuinely different. An unsigned checksums file proves a
// download was not corrupted or truncated and that the host served consistent content; it does
// not prove the upstream published it. That is weaker than a signature and much stronger than
// nothing, and collapsing the two throws away a difference a reader may care about.
type Level string

// The levels, strongest first.
const (
	// LevelPinned: installed at the version Draugr ships, matching a SHA-256 recorded in this
	// binary. The only level that needs no network to verify.
	LevelPinned Level = "pinned"
	// LevelSigned: installed at another version, matching checksums signed by the upstream's
	// Sigstore identity.
	LevelSigned Level = "signed"
	// LevelChecksum: installed, matching an unsigned checksums file fetched from the upstream.
	LevelChecksum Level = "checksum"
	// LevelUnverified: installed with nothing published to check it against.
	LevelUnverified Level = "unverified"
	// LevelExternal: not installed by Draugr. Found on PATH, and used — the operator brought it,
	// and they know something Draugr does not.
	LevelExternal Level = "external"
)

// Describe renders a level for a reader who has not read this file.
func (l Level) Describe() string {
	switch l {
	case LevelPinned:
		return "installed by Draugr, checksum recorded in this build"
	case LevelSigned:
		return "installed by Draugr, upstream signature verified"
	case LevelChecksum:
		return "installed by Draugr, upstream checksum matched but not signed"
	case LevelUnverified:
		return "installed by Draugr, nothing published to verify it against"
	default:
		return "found on PATH; Draugr did not install it"
	}
}

// DescribeFor renders a level for one named tool.
//
// "Draugr did not install it" is true of everything external and misleading for some of it: a tool
// Draugr cannot provision was never a candidate, and reporting an omission invites somebody to go
// and fix it with a command that will not work. So the line differs by whether Draugr could have
// installed this one — which now includes the tools it obtains as Python packages.
func DescribeFor(l Level, tool string) string {
	if l != LevelExternal && l != "" {
		return l.Describe()
	}
	if !Provisionable(tool) {
		return "found on PATH; Draugr does not distribute it"
	}
	return "found on PATH; Draugr did not install it — `draugr tools install " + tool + "` provisions a pinned build"
}

// Provisionable reports whether `draugr tools install` can obtain this tool, by either method.
func Provisionable(tool string) bool {
	if _, ok := Spec(tool); ok {
		return true
	}
	if _, ok := PythonTool(tool); ok {
		return true
	}
	_, ok := NodeTool(tool)
	return ok
}

// Vouched reports whether Draugr installed this binary at all, at any level.
func (l Level) Vouched() bool { return l != LevelExternal && l != "" }

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
	// Level is how strongly Draugr can vouch for this binary.
	Level Level
	// Reason says why the level is what it is, when it is not the strongest.
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
	a := Attestation{Tool: tool, Path: path, Version: version, Level: LevelExternal}
	switch {
	case path == "":
		a.Reason = "not found"
		return a
	case binDir == "" || filepath.Dir(path) != binDir:
		a.Reason = LevelExternal.Describe()
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
	// How it was verified is decided at install time and recorded, because that is the only
	// moment the evidence exists — the checksums file and the signature are not kept.
	a.Level = rec.Verified
	if a.Level == "" {
		// Installed before levels were recorded. It matches what Draugr wrote, and the strongest
		// honest thing to say about it is that much.
		a.Level = LevelPinned
	}
	if a.Level != LevelPinned && a.Level != LevelSigned {
		a.Reason = a.Level.Describe()
	}
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
