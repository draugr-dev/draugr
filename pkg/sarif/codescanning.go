package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// CodeScanningLocationKey is the result property a code-scanning document keeps a location in when
// the location is not a file code scanning can place: a host's URL, a cluster object, anything with a
// scheme other than file. An image reference is not copied there, because the result's `image`
// property already holds it.
const CodeScanningLocationKey = "draugr/location"

// Declaration is a line in the scanned repository that declares what a finding is about.
type Declaration struct {
	// Path is the file, relative to the repository's root and slash-separated.
	Path string
	// Line is the line in Path, counted from 1.
	Line int
}

// DeclaredImage names an image the way a finding on it does: the component it belongs to, and the
// reference the finding carries, in its `image` property or as its location.
type DeclaredImage struct {
	Component, Ref string
}

// Declarations is where each image a run scanned is declared in the repository, for the images
// declared there. An image a survey found, or one declared in a file outside the repository, has no
// entry.
type Declarations map[DeclaredImage]Declaration

// ForCodeScanning returns doc, a SARIF log, with every location GitHub code scanning refuses taken
// out, and the number of results that were left with no location at all.
//
// Code scanning reads an artifact location as a file in the repository: a path relative to its root,
// or a `file:` URI. A finding about something other than a file, an image, a host, carries the thing
// it is about as its location, and code scanning parses `python:3.8-slim` as a URI whose scheme is
// `python`, which it does not know, and refuses the whole upload over it. Every finding in the file
// is then missing from the Security tab, the ones on files included.
//
// So, in the copy:
//
//   - a result another scanner's finding is counted under is left out, so code scanning opens one
//     alert per flaw, as the gate counts it (see countedOnly);
//   - a relative path is kept, and declared against %SRCROOT% where it was not;
//   - a `file:` URI is kept, and an absolute path is written as one;
//   - anything else is removed, the result's image reference included when it was written as a path,
//     and kept in the result's properties: under `image` where it is the image, which is already
//     there, and under CodeScanningLocationKey otherwise;
//   - a result left with no location, whose component declared the image it is about on a line
//     declared lists, is placed on that line. Matched on the result's `image` property, or on the
//     location removed from it where it has none. A placed result with no partialFingerprints is
//     given its own fingerprint under FindingHashKey, which tells apart the findings sharing the line.
//
// The line that names an image is the one a reader changes to move to a newer image, and it is in
// the repository, so code scanning can show the finding there.
//
// A result left with no location is still uploaded, with its rule, message and properties. GitHub
// documents that it needs a location to display a result, which is why the count is returned: the
// caller says how many will not appear.
//
// The locations of the run's notifications are held to the same rule and dropped rather than kept
// elsewhere, since a notification has no property a reader would look in.
//
// Every other value is kept as written. A document with nothing to change is returned unchanged.
//
// The file Draugr writes for itself, results.sarif, keeps the reference as the finding's location,
// because `draugr diff`, `draugr explain` and the platforms that read it take a finding's identity
// from it. This is for the copy that goes to code scanning.
func ForCodeScanning(doc []byte, declared Declarations) (out []byte, unplaced int, err error) {
	var log map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	// Numbers stay as written: a fingerprint, a line or a score read into a float64 and written back
	// can come out spelled differently.
	dec.UseNumber()
	if err := dec.Decode(&log); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrNotSARIF, err)
	}
	// A log whose runs or results are not lists is refused rather than passed on unchanged, since
	// nothing in it could be held to what code scanning accepts, the copies of counted findings
	// included.
	runs, ok := log["runs"].([]any)
	if !ok {
		return nil, 0, fmt.Errorf("%w: runs is %T, not a list", ErrNotSARIF, log["runs"])
	}
	changed := false
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			continue
		}
		relative := false
		results, ok := run["results"].([]any)
		if raw, present := run["results"]; present && !ok {
			return nil, 0, fmt.Errorf("%w: a run's results is %T, not a list", ErrNotSARIF, raw)
		}
		kept, err := countedOnly(results)
		if err != nil {
			return nil, 0, err
		}
		if len(kept) != len(results) {
			results = kept
			run["results"] = kept
			changed = true
		}
		for _, res := range results {
			result, ok := res.(map[string]any)
			if !ok {
				continue
			}
			c, rel, none := placeResult(result, declared)
			changed = changed || c
			relative = relative || rel
			if none {
				unplaced++
			}
		}
		invocations, _ := run["invocations"].([]any)
		for _, inv := range invocations {
			invocation, ok := inv.(map[string]any)
			if !ok {
				continue
			}
			notes, _ := invocation["toolExecutionNotifications"].([]any)
			for _, n := range notes {
				note, ok := n.(map[string]any)
				if !ok {
					continue
				}
				locations, _ := note["locations"].([]any)
				kept, c, rel, _ := placeLocations(locations, "")
				if !c {
					continue
				}
				changed = true
				relative = relative || rel
				if len(kept) == 0 {
					delete(note, "locations")
				} else {
					note["locations"] = kept
				}
			}
		}
		// A relative path needs its base declared, which a document with none had no reason to do.
		if relative {
			bases, _ := run["originalUriBaseIds"].(map[string]any)
			if _, ok := bases[uriBaseID]; !ok {
				if bases == nil {
					bases = map[string]any{}
				}
				bases[uriBaseID] = map[string]any{"description": map[string]any{"text": "The root of the scanned source tree."}}
				run["originalUriBaseIds"] = bases
				changed = true
			}
		}
	}
	if !changed {
		return doc, unplaced, nil
	}
	out, err = json.Marshal(log)
	if err != nil {
		return nil, 0, err
	}
	return out, unplaced, nil
}

// countedOnly is results less the copies of a flaw another scanner's finding is counted under, those
// whose properties.correlation.countedUnder is set.
//
// Code scanning opens an alert for every result and reads nothing in the property bag, so a flaw two
// scanners reported would otherwise be two alerts under two rule ids, and the Security tab would count
// what the gate counts once. Leaving the copy out, rather than marking it with a SARIF suppression,
// keeps code scanning from presenting a second scanner's agreement as somebody's decision to accept
// the flaw. The counted result's correlation.alsoFoundBy still names the other scanners and what each
// said, and results.sarif keeps the copies. The run's rules are kept as written, so every kept
// result's ruleIndex still points where it did.
//
// A correlation it cannot read is an error rather than a result kept, since keeping it would upload
// the copy it may be.
func countedOnly(results []any) ([]any, error) {
	kept := make([]any, 0, len(results))
	for _, res := range results {
		result, _ := res.(map[string]any)
		props, _ := result["properties"].(map[string]any)
		raw, ok := props["correlation"]
		if !ok {
			kept = append(kept, res)
			continue
		}
		correlation, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: a result's correlation is %T, not an object", ErrNotSARIF, raw)
		}
		under, ok := correlation["countedUnder"]
		if !ok {
			kept = append(kept, res)
			continue
		}
		name, ok := under.(string)
		if !ok {
			return nil, fmt.Errorf("%w: a result's correlation.countedUnder is %T, not a string", ErrNotSARIF, under)
		}
		if name != "" {
			continue
		}
		kept = append(kept, res)
	}
	return kept, nil
}

// placeResult holds one result's locations to what code scanning accepts, placing a result left
// with none on the line declared names for its image. It reports whether it changed anything,
// whether a kept or placed location is relative, and whether the result had a location and now has
// none.
func placeResult(result map[string]any, declared Declarations) (changed, relative, none bool) {
	locations, _ := result["locations"].([]any)
	if len(locations) == 0 {
		return false, false, false
	}
	props, _ := result["properties"].(map[string]any)
	image, _ := props["image"].(string)
	kept, changed, relative, dropped := placeLocations(locations, image)
	if !changed {
		return false, relative, false
	}
	switch d, ok := declaredFor(props, image, dropped, declared); {
	case len(kept) > 0:
		result["locations"] = kept
	case ok:
		result["locations"] = []any{map[string]any{"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": d.Path, "uriBaseId": uriBaseID},
			"region":           map[string]any{"startLine": d.Line},
		}}}
		relative = true
		// Every finding of one rule in the image now shares this line, and nothing else in the result
		// tells code scanning they are different findings; the finding's own identity does. A result
		// that already carries fingerprints keeps them.
		if fp, _ := props["fingerprint"].(string); fp != "" {
			if _, has := result["partialFingerprints"]; !has {
				result["partialFingerprints"] = map[string]any{FindingHashKey: fp}
			}
		}
	default:
		delete(result, "locations")
		none = true
	}
	for _, uri := range dropped {
		if uri == image {
			continue
		}
		if props == nil {
			props = map[string]any{}
			result["properties"] = props
		}
		// The first is the one code scanning would have read; SARIF orders a result's locations.
		if _, set := props[CodeScanningLocationKey]; !set {
			props[CodeScanningLocationKey] = uri
		}
	}
	return true, relative, none
}

// declaredFor returns the line declared names for the image a result is about: the one in its
// `image` property, or else the first location removed from it, which is how a finding that carries
// no image property names its image. Matched within the result's component, since two components
// can declare one image on two lines. A declaration whose path code scanning would refuse, or with
// no line, is not one.
func declaredFor(props map[string]any, image string, dropped []string, declared Declarations) (Declaration, bool) {
	if len(declared) == 0 {
		return Declaration{}, false
	}
	ref := image
	if ref == "" && len(dropped) > 0 {
		ref = dropped[0]
	}
	component, _ := props["component"].(string)
	d, ok := declared[DeclaredImage{Component: component, Ref: ref}]
	if !ok || ref == "" || d.Line < 1 || !isRelativeURI(d.Path) || d.Path == "" {
		return Declaration{}, false
	}
	return d, true
}

// placeLocations returns the locations code scanning accepts, rewritten where they need it, whether
// that differs from what it was given, whether a kept one is relative, and the URIs it removed.
// image is the result's image reference, which is never a path in the repository however it is
// spelled.
func placeLocations(locations []any, image string) (kept []any, changed, relative bool, dropped []string) {
	kept = make([]any, 0, len(locations))
	for _, l := range locations {
		loc, ok := l.(map[string]any)
		if !ok {
			kept = append(kept, l)
			continue
		}
		physical, _ := loc["physicalLocation"].(map[string]any)
		artifact, _ := physical["artifactLocation"].(map[string]any)
		uri, _ := artifact["uri"].(string)
		if uri == "" {
			kept = append(kept, l)
			continue
		}
		base, _ := artifact["uriBaseId"].(string)
		placed, placedBase, ok := CodeScanningURI(uri, base)
		if !ok || (image != "" && uri == image) {
			changed = true
			dropped = append(dropped, uri)
			continue
		}
		if placed != uri || placedBase != base {
			changed = true
			artifact["uri"] = placed
			if placedBase == "" {
				delete(artifact, "uriBaseId")
			} else {
				artifact["uriBaseId"] = placedBase
			}
		}
		relative = relative || placedBase == uriBaseID
		kept = append(kept, l)
	}
	return kept, changed, relative, dropped
}

// CodeScanningURI says how a location's URI, and the base it is declared against, go to code
// scanning: as they are, rewritten, or not at all (ok false).
//
// Accepted are a path relative to the repository's root, declared against %SRCROOT%, and a `file:`
// URI. An absolute path becomes a `file:` URI. Anything else names something code scanning cannot
// place: a URI with another scheme, or an image reference such as `python:3.8-slim`, which parses as
// one.
func CodeScanningURI(uri, base string) (out, outBase string, ok bool) {
	switch {
	case isRelativeURI(uri):
		if base == "" {
			base = uriBaseID
		}
		return uri, base, true
	case hasFileScheme(uri):
		return uri, "", true
	case strings.HasPrefix(uri, "/") && !strings.HasPrefix(uri, "//"):
		return "file://" + escapedPath(uri), "", true
	}
	return "", "", false
}

// CodeScanningRefuses lists the artifact locations in doc, anywhere in it, that code scanning does
// not accept: every `artifactLocation.uri` that is neither a relative reference declared against
// %SRCROOT% nor a `file:` URI. Empty for a document code scanning can take.
//
// It reads the document as a URI parser does rather than by ForCodeScanning's rules, so a test
// holding the one to the other checks the rewrite rather than restating it.
func CodeScanningRefuses(doc []byte) ([]string, error) {
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSARIF, err)
	}
	var refused []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				if art, ok := child.(map[string]any); ok && k == "artifactLocation" {
					uri, _ := art["uri"].(string)
					base, _ := art["uriBaseId"].(string)
					if uri != "" && !codeScanningAccepts(uri, base) {
						refused = append(refused, uri)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(v)
	return refused, nil
}

// codeScanningAccepts is the rule CodeScanningRefuses applies to one location.
func codeScanningAccepts(uri, base string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Scheme, "file") {
		return true
	}
	return u.Scheme == "" && u.Host == "" && !strings.HasPrefix(uri, "/") && base == uriBaseID
}

// hasFileScheme reports whether uri is a `file:` URI. Schemes are case-insensitive.
func hasFileScheme(uri string) bool {
	return len(uri) >= len("file:") && strings.EqualFold(uri[:len("file:")], "file:")
}
