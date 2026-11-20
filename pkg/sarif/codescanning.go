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
//   - a relative path is kept, and declared against %SRCROOT% where it was not;
//   - a `file:` URI is kept, and an absolute path is written as one;
//   - anything else is removed, the result's image reference included when it was written as a path,
//     and kept in the result's properties: under `image` where it is the image, which is already
//     there, and under CodeScanningLocationKey otherwise.
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
func ForCodeScanning(doc []byte) (out []byte, unplaced int, err error) {
	var log map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	// Numbers stay as written: a fingerprint, a line or a score read into a float64 and written back
	// can come out spelled differently.
	dec.UseNumber()
	if err := dec.Decode(&log); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrNotSARIF, err)
	}
	runs, _ := log["runs"].([]any)
	changed := false
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			continue
		}
		relative := false
		results, _ := run["results"].([]any)
		for _, res := range results {
			result, ok := res.(map[string]any)
			if !ok {
				continue
			}
			c, rel, none := placeResult(result)
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

// placeResult holds one result's locations to what code scanning accepts. It reports whether it
// changed anything, whether a kept location is relative, and whether the result had a location and
// now has none.
func placeResult(result map[string]any) (changed, relative, none bool) {
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
	if len(kept) == 0 {
		delete(result, "locations")
		none = true
	} else {
		result["locations"] = kept
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
