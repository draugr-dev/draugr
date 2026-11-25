package git

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"strings"
)

// ContentDigest names content in sixteen hex characters: the first eight bytes of its SHA-256.
func ContentDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// unreadable stands in a directory's listing for a file under it that could not be read, so the
// listing still changes when the file does appear or disappear.
const unreadable = "unreadable"

// PathDigest names what is at path in sixteen hex characters, and false where nothing is there.
//
// A file is named by its content. A directory is named by its listing: every file under it, by its
// path from the directory with forward slashes, in sorted order, each with its own digest, so a
// file added, removed, renamed or edited anywhere under it changes the name. A link is followed, as
// the tool that reads the file follows it.
//
// Only digests are kept, never the content: what is named may be a ruleset or an ignore file in a
// repository whose report is uploaded where others read it.
func PathDigest(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	if !info.IsDir() {
		b, err := os.ReadFile(path) // #nosec G304 -- a path a descriptor or a checkout names, read to digest it
		if err != nil {
			return ContentDigest([]byte(unreadable)), true
		}
		return ContentDigest(b), true
	}
	// Read through a root opened on the directory, so a link under it that leads out of it is read
	// as unreadable rather than followed to a file elsewhere on the machine.
	root, err := os.OpenRoot(path)
	if err != nil {
		return ContentDigest([]byte(unreadable)), true
	}
	defer func() { _ = root.Close() }()
	fsys := root.FS()
	var listing strings.Builder
	// WalkDir visits in lexical order, which is the sorted order the listing needs.
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		digest := ContentDigest([]byte(unreadable))
		if b, err := fs.ReadFile(fsys, p); err == nil {
			digest = ContentDigest(b)
		}
		listing.WriteString(p + "\x00" + digest + "\n")
		return nil
	})
	return ContentDigest([]byte(listing.String())), true
}
