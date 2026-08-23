package saga

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"gopkg.in/yaml.v3"
)

// digestOf is the content digest of a descriptor file or of a serialized model, in the form every
// other digest in a report takes.
func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// digestFile is the digest of a file as it is on disk.
//
// Deliberately the bytes before ${{ VAR }} substitution: this answers "is this the same file",
// which is a question about what somebody committed and reviewed. What the substitution produced
// is a different question, and Resolved.Digest answers it.
func digestFile(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- the loader has already read this path
	if err != nil {
		// The file was read moments ago to parse it. Losing the digest is not a reason to fail a
		// scan, and an absent digest reads as absent rather than as a wrong one.
		return ""
	}
	return digestOf(data)
}

// Digest identifies the descriptor that actually ran: root and fragments merged, environment
// substituted, serialized canonically.
//
// This is the fact worth having, and no single file carries it. Two runs with identical
// descriptors and different fragments produce different digests; two runs whose descriptors differ
// only in comments or key order produce the same one. Neither is true of a digest over the root
// file.
func (r *Resolved) Digest() string {
	if r == nil || r.Model == nil {
		return ""
	}
	data, err := yaml.Marshal(r.Model)
	if err != nil {
		return ""
	}
	return digestOf(data)
}
