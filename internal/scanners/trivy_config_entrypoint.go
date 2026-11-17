package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy's DS-0002 reports a Dockerfile with no `USER` as an image that runs as root, which it reads
// from the Dockerfile alone. Many images that need root to start do so deliberately: the entrypoint
// script chowns a mounted volume or creates a user from PUID and PGID, and then hands the
// application to that user with `exec su-exec app "$@"`. Adding a `USER`, which is what the check asks
// for, breaks that script.
//
// So the scan reads the script the final stage starts, when the same Dockerfile copies it in from
// the repository, records the line that hands over as the finding's privilegeDrop, and replaces
// Trivy's sentence asking for a USER with one naming that line. Only where
// every path a start as root takes through the script ends in that hand-over, or in an exit, and
// runs nothing as root before it but the setup commands entrypointSetup lists. Anything the reading
// cannot follow leaves the finding without the record, as Trivy reported it.
//
// Here rather than in a later pass because the scanner holds the checkout, and the script is read at
// the revision the Dockerfile was. The record moves the finding inside its band and nothing else.

// trivyRootUserRules are the ids Trivy reports "Image user should not be 'root'" under: DS-0002 in
// the releases that write ids in that form, DS002 before them.
var trivyRootUserRules = map[string]bool{"DS-0002": true, "DS002": true}

// maxEntrypointBytes bounds the files read for the evidence. An entrypoint script is a page of
// shell; a larger file is left unread rather than read whole.
const maxEntrypointBytes = 256 << 10

// withEntrypointDrops adds privilegeDrop to the properties of each DS-0002 result of Trivy's SARIF
// whose Dockerfile's entrypoint script drops root, read from the checkout at dir. SARIF with no such
// result is returned unchanged.
func withEntrypointDrops(sarifOut []byte, dir string) ([]byte, error) {
	if len(sarifOut) == 0 || !bytes.Contains(sarifOut, []byte("DS")) {
		return sarifOut, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(sarifOut, &doc); err != nil {
		return nil, fmt.Errorf("read the SARIF it wrote: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		// No checkout to read is no evidence, and the findings stand as Trivy reported them.
		return sarifOut, nil
	}
	defer func() { _ = root.Close() }()
	read := map[string]*sarif.PrivilegeDrop{}
	changed := false
	runs, _ := doc["runs"].([]any)
	for _, run := range runs {
		results, _ := jsonObject(run)["results"].([]any)
		for _, r := range results {
			result := jsonObject(r)
			if rule, _ := result["ruleId"].(string); !trivyRootUserRules[rule] {
				continue
			}
			locations, _ := result["locations"].([]any)
			if len(locations) == 0 {
				continue
			}
			art := jsonObject(jsonObject(jsonObject(locations[0])["physicalLocation"])["artifactLocation"])
			uri, _ := art["uri"].(string)
			file := checkoutRelative(dir, uri)
			if file == "" {
				continue
			}
			drop, seen := read[file]
			if !seen {
				drop = entrypointDrop(root, file)
				read[file] = drop
			}
			if drop == nil {
				continue
			}
			props := jsonObject(result["properties"])
			if props == nil {
				props = map[string]any{}
				result["properties"] = props
			}
			props["privilegeDrop"] = drop
			// In place of Trivy's sentence, which asks for a USER the script's own start would break.
			// The sentence is the finding's detail, and its identity is the rule's title.
			props["detail"] = privilegeDropSentence(drop)
			changed = true
		}
	}
	if !changed {
		return sarifOut, nil
	}
	return json.Marshal(doc)
}

// privilegeDropSentence is what a DS-0002 finding with an entrypoint that drops root says about its
// image: "entrypoint.sh:11 starts the application as another user with su-exec, so adding USER may
// break it".
func privilegeDropSentence(d *sarif.PrivilegeDrop) string {
	return fmt.Sprintf("%s:%d starts the application as another user with %s, so adding USER may break it",
		d.File, d.Line, d.Command)
}

// checkoutRelative is uri as a slash-separated path inside the checkout at dir, or "" for one outside
// it.
func checkoutRelative(dir, uri string) string {
	p := filepath.FromSlash(uri)
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return ""
		}
		p = rel
	}
	if !filepath.IsLocal(p) {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// entrypointDrop reads the Dockerfile at file in root and the script its final stage starts, and
// returns where that script drops root, or nil where it does not or cannot be followed.
func entrypointDrop(root *os.Root, file string) *sarif.PrivilegeDrop {
	src, ok := readBounded(root, file)
	if !ok {
		return nil
	}
	stage, ok := finalStage(src)
	if !ok {
		return nil
	}
	image, ok := stage.script()
	if !ok {
		return nil
	}
	// The build context is not in the Dockerfile. It is usually the Dockerfile's own directory and
	// sometimes the repository root, so each is tried, and where both hold a script for the path
	// both have to drop root.
	var found *sarif.PrivilegeDrop
	for _, ctx := range buildContexts(file) {
		script, ok := stage.copiedFrom(root, ctx, image)
		if !ok {
			continue
		}
		body, ok := readBounded(root, script)
		if !ok {
			return nil
		}
		drop, ok := scriptDrop(body)
		if !ok {
			return nil
		}
		if found == nil {
			found = &sarif.PrivilegeDrop{Command: drop.command, User: drop.user, File: script, Line: drop.line}
		}
	}
	return found
}

// buildContexts are the directories a Dockerfile's COPY may read from: its own directory, then the
// repository root.
func buildContexts(dockerfile string) []string {
	dir := path.Dir(dockerfile)
	if dir == "." {
		return []string{"."}
	}
	return []string{dir, "."}
}

// readBounded reads the regular file at name in root, refusing one larger than maxEntrypointBytes.
func readBounded(root *os.Root, name string) (string, bool) {
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxEntrypointBytes {
		return "", false
	}
	b, err := root.ReadFile(name)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// dockerInstruction is one instruction of a Dockerfile, its continuation lines joined.
type dockerInstruction struct {
	name string // upper case
	args string
}

// dockerHeredoc matches a BuildKit heredoc in an instruction, whose body lines are not instructions.
var dockerHeredoc = regexp.MustCompile(`<<-?\s*["']?[A-Za-z_]`)

// dockerInstructions splits a Dockerfile into instructions. False for one this reading does not
// follow: a parser directive changing the escape character, or a heredoc.
func dockerInstructions(src string) ([]dockerInstruction, bool) {
	var out []dockerInstruction
	var cur *dockerInstruction
	directives := true
	for _, raw := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(trimmed, "#") {
			if directives && cur == nil {
				key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(trimmed, "#")), "=")
				if ok && strings.EqualFold(strings.TrimSpace(key), "escape") && strings.TrimSpace(value) != `\` {
					return nil, false
				}
			}
			continue
		}
		if trimmed == "" {
			continue
		}
		directives = false
		cont := strings.HasSuffix(trimmed, `\`)
		text := strings.TrimSuffix(trimmed, `\`)
		if cur == nil {
			fields := strings.Fields(text)
			cur = &dockerInstruction{name: strings.ToUpper(fields[0]),
				args: strings.TrimSpace(strings.TrimPrefix(text, fields[0]))}
		} else {
			cur.args = strings.TrimSpace(cur.args + " " + text)
		}
		if !cont {
			if dockerHeredoc.MatchString(cur.args) {
				return nil, false
			}
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out, true
}

// dockerStage is the instructions of a Dockerfile's final stage.
type dockerStage struct {
	instructions []dockerInstruction
}

// finalStage is the instructions after the Dockerfile's last FROM. False where there is no FROM or
// the file cannot be read as instructions.
func finalStage(src string) (dockerStage, bool) {
	ins, ok := dockerInstructions(src)
	if !ok {
		return dockerStage{}, false
	}
	last := -1
	for i, in := range ins {
		if in.name == "FROM" {
			last = i
		}
	}
	if last < 0 {
		return dockerStage{}, false
	}
	return dockerStage{instructions: ins[last+1:]}, true
}

// script is the path in the image of the script the stage starts: the first word of its last
// ENTRYPOINT, or of its last CMD where it sets no ENTRYPOINT. False where the stage sets neither, the
// command is looked up on PATH, or its words cannot be read without a shell.
//
// Only the final stage's own instructions: an entrypoint it inherits from its base, an earlier stage
// included, names a script this Dockerfile may not have copied.
func (s dockerStage) script() (string, bool) {
	var entrypoint, cmd *dockerInstruction
	shell := false
	workdir, known := "/", true
	for i, in := range s.instructions {
		switch in.name {
		case "ENTRYPOINT":
			entrypoint = &s.instructions[i]
		case "CMD":
			cmd = &s.instructions[i]
		case "SHELL":
			shell = true
		case "WORKDIR":
			workdir, known = joinWorkdir(workdir, known, in.args)
		}
	}
	start := entrypoint
	if start == nil {
		start = cmd
	}
	if start == nil {
		return "", false
	}
	words, ok := execWords(start.args)
	if !ok {
		// The shell form runs through `/bin/sh -c`. Plain words are still read as the command they
		// name; anything a shell would expand is not.
		if shell {
			return "", false
		}
		words = strings.Fields(start.args)
		for _, w := range words {
			if !plainShellWord.MatchString(w) {
				return "", false
			}
		}
	}
	if len(words) == 0 || !strings.Contains(words[0], "/") || strings.Contains(words[0], "$") {
		return "", false
	}
	if path.IsAbs(words[0]) {
		return path.Clean(words[0]), true
	}
	if !known {
		return "", false
	}
	return path.Join(workdir, words[0]), true
}

// plainShellWord is a word `/bin/sh -c` passes through unchanged.
var plainShellWord = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+,-]+$`)

// execWords reads the JSON array of an instruction's exec form. False for the shell form.
func execWords(args string) ([]string, bool) {
	if !strings.HasPrefix(args, "[") {
		return nil, false
	}
	var words []string
	if err := json.Unmarshal([]byte(args), &words); err != nil {
		return nil, false
	}
	return words, true
}

// joinWorkdir applies a WORKDIR instruction to the directory before it. known is false once a
// WORKDIR names a variable, which this reading does not expand.
func joinWorkdir(workdir string, known bool, arg string) (string, bool) {
	arg = strings.Trim(strings.TrimSpace(arg), `"`)
	if strings.Contains(arg, "$") || arg == "" {
		return workdir, false
	}
	if path.IsAbs(arg) {
		return path.Clean(arg), true
	}
	return path.Join(workdir, arg), known
}

// placement is what one COPY or ADD does to the path the entrypoint names.
type placement int

const (
	// notPlaced: it writes nothing at the path.
	notPlaced placement = iota
	// placed: it writes a file of the build context there.
	placed
	// unknown: it may write the path, and what it writes is not a file this reading can name, such as
	// one from another stage or a source with a variable or a wildcard.
	unknown
)

// copiedFrom is the repository path of the file the stage's last COPY or ADD placing a file at image
// put there, reading the build context as ctx. False where no instruction copies one from the
// context, where the last one that may write the path is not such a copy, or where a RUN after it
// does more to the file than change its mode or owner.
func (s dockerStage) copiedFrom(root *os.Root, ctx, image string) (string, bool) {
	workdir, known := "/", true
	from, at := "", -1
	for i, in := range s.instructions {
		switch in.name {
		case "WORKDIR":
			workdir, known = joinWorkdir(workdir, known, in.args)
		case "COPY", "ADD":
			switch src, p := copyPlaces(root, ctx, in, workdir, known, image); p {
			case placed:
				from, at = src, i
			case unknown:
				from, at = "", i
			case notPlaced:
			}
		}
	}
	if at < 0 || from == "" {
		return "", false
	}
	for _, in := range s.instructions[at+1:] {
		if in.name == "RUN" && !onlyModeChanges(in.args, image) {
			return "", false
		}
	}
	return from, true
}

// copyPlaces reports what a COPY or ADD instruction does to the path image, reading the build
// context as ctx, and for placed, the repository path of the file it places there.
func copyPlaces(root *os.Root, ctx string, in dockerInstruction, workdir string, known bool, image string) (string, placement) {
	words, ok := execWords(in.args)
	if !ok {
		words = strings.Fields(in.args)
	}
	external := false
	for len(words) > 0 && strings.HasPrefix(words[0], "--") {
		external = external || strings.HasPrefix(words[0], "--from")
		words = words[1:]
	}
	if len(words) < 2 {
		return "", unknown
	}
	srcs, dest := words[:len(words)-1], words[len(words)-1]
	if strings.Contains(dest, "$") || (!path.IsAbs(dest) && !known) {
		return "", unknown
	}
	asDir := strings.HasSuffix(dest, "/") || len(srcs) > 1
	if !path.IsAbs(dest) {
		dest = path.Join(workdir, dest)
	}
	dest = path.Clean(dest)
	inside, under := strings.CutPrefix(image, strings.TrimSuffix(dest, "/")+"/")
	if image != dest && !under {
		return "", notPlaced
	}
	for _, src := range srcs {
		if external || strings.ContainsAny(src, "$*?[") || strings.Contains(src, "://") {
			return "", unknown
		}
		// The context is the root of what a COPY can read: Docker reads "../x" as "x".
		rel := path.Join(ctx, strings.TrimPrefix(path.Clean("/"+src), "/"))
		info, err := root.Stat(rel)
		switch {
		case err != nil:
			continue
		case info.IsDir():
			// A directory's contents go into dest.
			if p := path.Join(rel, inside); under && isRegular(root, p) {
				return p, placed
			}
		case !asDir && image == dest:
			return rel, placed
		case path.Join(dest, path.Base(src)) == image:
			// Into a directory: a destination ending in "/", several sources, or a directory already in
			// the image such as /usr/local/bin.
			return rel, placed
		}
	}
	return "", notPlaced
}

// isRegular reports whether name in root is a regular file.
func isRegular(root *os.Root, name string) bool {
	info, err := root.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

// runCommands splits a RUN instruction's shell into its commands, roughly: enough to see which
// command names a file.
var runCommands = regexp.MustCompile(`&&|\|\||;|\|`)

// onlyModeChanges reports whether a RUN instruction leaves the file at image as it was copied: it
// does not name the file, or names it only in chmod, chown or chgrp commands.
func onlyModeChanges(run, image string) bool {
	base := path.Base(image)
	if !strings.Contains(run, base) {
		return true
	}
	for _, part := range runCommands.Split(run, -1) {
		fields := strings.Fields(part)
		if len(fields) == 0 || !strings.Contains(part, base) {
			continue
		}
		switch path.Base(fields[0]) {
		case "chmod", "chown", "chgrp":
		default:
			return false
		}
	}
	return true
}
