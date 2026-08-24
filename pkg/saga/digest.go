package saga

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"

	"gopkg.in/yaml.v3"
)

// digestOf is the content digest of a descriptor file or of a serialized model, in the form every
// other digest in a report takes. Empty input has no digest rather than the digest of nothing,
// which is a real and entirely wrong sha256.
func digestOf(data []byte) string {
	if len(data) == 0 {
		return ""
	}
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
	return digestOf([]byte(r.Effective()))
}

// Effective is the descriptor that actually ran: root and fragments merged, environment
// substituted, serialized canonically.
//
// The same bytes Digest is taken over, which is the point of returning them. A digest is only worth
// something to somebody who can reproduce it, and a reader holding this can — rather than being
// asked to trust that a number describes a file they cannot see.
//
// It is the merged form, so it is not any file in the repository. Reading it answers "what did this
// run actually apply", which is a different question from "what is committed" and the one somebody
// asks when a finding was suppressed and they cannot see why.
func (r *Resolved) Effective() string {
	if r == nil || r.Model == nil {
		return ""
	}
	// Two spaces, which is what every descriptor anybody writes uses and what the reference shows.
	// yaml.Marshal defaults to four, so the text a reader is shown would not look like the file
	// they have open — and this is the copy they are asked to compare against it.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(r.Model); err != nil {
		return ""
	}
	if err := enc.Close(); err != nil {
		return ""
	}
	return buf.String()
}
