package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
)

// FromForeignSARIF reads a SARIF 2.1.0 file another tool wrote, for import.
//
// It is a reader apart from FromSARIF because the two files are not the same kind of evidence.
// FromSARIF reads Draugr's own results.sarif back, and so trusts the property names Draugr writes:
// `priority`, `aside`, `nonShipping`, a rating, a suppression's origin. In a file somebody else
// wrote, each of those would be a claim Draugr never made about a finding it never ranked, and a
// tool, or a hand-edited file, could set a finding aside or forge a descriptor's acceptance just by
// naming the property. This reader reads none of them. From a property bag it takes
// `security-severity`, the score SARIF producers agree on, as a number or as a string; `package`,
// where it is an object in the shape Draugr writes; `purls`; and `tags`. Each is a fact about the
// finding rather than a decision about it. A file that has to set more of Draugr's properties is a
// converter's, read by pkg/converter only where the descriptor declares the converter, and even
// then never one that sets a finding aside or lowers it.
//
// A dependency finding's package, the version that fixes it and the advisory's other identifiers are
// read from wherever the file states them, which differs by tool: see packageOf and statedAliases.
//
// It also reads the parts of SARIF that Draugr never writes and other tools do: a rule named only by
// its index, a location given as an index into the run's artifacts, and a URI relative to a base the
// run declares. Paths come back relative to the checkout, so exclusions and repository links match
// them.
//
// roots are the local directories of the checkouts the file describes, absolute. A path the file
// gives that is inside none of them, and that no base the file declares makes relative, is kept as
// written and returned in outside, so the caller can say which findings Draugr could not place.
//
// The same reader backs `draugr doctor`, so a file doctor passes is one the scan reads.
func FromForeignSARIF(data []byte, roots []string) (rep Report, outside []string, err error) {
	var log foreignLog
	if err := json.Unmarshal(data, &log); err != nil {
		return Report{}, nil, fmt.Errorf("%w: %w", ErrNotSARIF, err)
	}
	if log.Version == "" && log.Runs == nil {
		return Report{}, nil, fmt.Errorf(`%w: it has neither a "version" nor a "runs" member`, ErrNotSARIF)
	}
	if log.Version == "" {
		return Report{}, nil, fmt.Errorf("states no SARIF version, and Draugr reads %s", Version)
	}
	if log.Version != Version {
		return Report{}, nil, fmt.Errorf("states SARIF version %q, and Draugr reads %s", log.Version, Version)
	}
	if len(log.Runs) == 0 {
		return Report{}, nil, fmt.Errorf("holds no runs, so it says nothing about what was scanned")
	}
	seen := map[string]bool{}
	for i, run := range log.Runs {
		if i == 0 {
			rep.Tool = run.Tool.Driver.Name
		}
		fr := newForeignRun(run, roots)
		for _, rule := range run.Tool.Driver.Rules {
			rep.addRule(rule.ID, Rule{
				Name:             rule.Name,
				ShortDescription: rule.ShortDescription.text(),
				FullDescription:  rule.FullDescription.text(),
				Help:             rule.Help.text(),
				HelpURI:          rule.HelpURI,
			})
		}
		for j, sr := range run.Results {
			res, out, err := fr.result(sr)
			if err != nil {
				return Report{}, nil, fmt.Errorf("run %d, result %d: %w", i+1, j+1, err)
			}
			if out != "" && !seen[out] {
				seen[out] = true
				outside = append(outside, out)
			}
			rep.Results = append(rep.Results, res)
		}
	}
	return rep, outside, nil
}

// The wire types below are what FromForeignSARIF reads, and nothing more. They are separate from
// the ones FromSARIF reads so that a property Draugr writes is never read from somebody else's file.

type foreignLog struct {
	Version string       `json:"version"`
	Runs    []foreignRun `json:"runs"`
}

type foreignRun struct {
	Tool struct {
		Driver struct {
			Name  string        `json:"name"`
			Rules []foreignRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results   []foreignResult `json:"results"`
	Artifacts []struct {
		Location   foreignArtifactLocation `json:"location"`
		Properties *foreignProperties      `json:"properties"`
	} `json:"artifacts"`
	OriginalURIBaseIDs map[string]foreignArtifactLocation `json:"originalUriBaseIds"`
}

type foreignRule struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	ShortDescription     *sarifMessage `json:"shortDescription"`
	FullDescription      *sarifMessage `json:"fullDescription"`
	Help                 *foreignText  `json:"help"`
	HelpURI              string        `json:"helpUri"`
	DefaultConfiguration *struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	// DeprecatedIDs are the ids the rule was known by before, which name the same rule and so the
	// same flaw.
	DeprecatedIDs looseStrings       `json:"deprecatedIds"`
	Properties    *foreignProperties `json:"properties"`
}

// foreignText is a SARIF multiformat message: the plain text, and the Markdown some tools fill with
// more than the text holds.
type foreignText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

func (m *foreignText) text() string {
	if m == nil {
		return ""
	}
	return m.Text
}

func (m *foreignText) markdown() string {
	if m == nil {
		return ""
	}
	return m.Markdown
}

// foreignProperties is the property-bag members read from another tool's file.
type foreignProperties struct {
	SecuritySeverity looseScore   `json:"security-severity"`
	Package          loosePackage `json:"package"`
	// PURLs are the package URLs of the dependency a rule or a result is about.
	PURLs looseStrings `json:"purls"`
	// Tags are SARIF's own property for the labels a tool attaches to a rule or a result, among which
	// some tools list an advisory's other identifiers.
	Tags looseStrings `json:"tags"`
}

// looseStrings is an array of strings. Anything else under the name, a string or an object, is none
// rather than a reason to refuse the file, as for loosePackage.
type looseStrings []string

func (l *looseStrings) UnmarshalJSON(b []byte) error {
	var s []string
	if json.Unmarshal(b, &s) == nil {
		*l = s
	}
	return nil
}

// loosePackage is a `package` property in the shape Draugr writes, an object. Another tool may use
// the name for something else, a string or a list, and that is no package rather than a reason to
// refuse the file.
type loosePackage struct{ pkg *Package }

func (l *loosePackage) UnmarshalJSON(b []byte) error {
	var p Package
	if json.Unmarshal(b, &p) == nil && p.Name != "" {
		l.pkg = &p
	}
	return nil
}

type foreignResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Rule      *struct {
		ID    string `json:"id"`
		Index *int   `json:"index"`
	} `json:"rule"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Locations           []struct {
		PhysicalLocation struct {
			ArtifactLocation foreignArtifactLocation `json:"artifactLocation"`
			Region           *sarifRegion            `json:"region"`
		} `json:"physicalLocation"`
		LogicalLocations looseLogicalLocations `json:"logicalLocations"`
	} `json:"locations"`
	Fixes        looseFixes `json:"fixes"`
	Suppressions []struct {
		Kind          string `json:"kind"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	} `json:"suppressions"`
	Properties *foreignProperties `json:"properties"`
}

type foreignArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
	Index     *int   `json:"index"`
}

// looseScore is a `security-severity` written either way producers write it: SARIF's property bags
// hold strings by convention, and some tools write the number itself. Anything else, a word or an
// empty string, is no score, as it is for FromSARIF.
type looseScore struct {
	value float64
	ok    bool
}

func (s *looseScore) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var text string
		if err := json.Unmarshal(b, &text); err != nil {
			return err
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(text), 64); err == nil {
			s.value, s.ok = v, true
		}
		return nil
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		// An object or an array where a score belongs is no score, not a reason to refuse the file.
		return nil
	}
	s.value, s.ok = v, true
	return nil
}

func (p *foreignProperties) score() (float64, bool) {
	if p == nil {
		return 0, false
	}
	return p.SecuritySeverity.value, p.SecuritySeverity.ok
}

// foreignRunReader converts one run's results, holding what each inherits from its run.
type foreignRunReader struct {
	run         foreignRun
	roots       []string
	ruleLevel   map[string]Level
	ruleScore   map[string]float64
	ruleSummary map[string]string
	// rules are the run's rules by id, the first where two share one, for what a result reads from
	// its rule beyond these: the package and fix the rule states, and the identifiers it lists.
	rules map[string]*foreignRule
}

func newForeignRun(run foreignRun, roots []string) foreignRunReader {
	fr := foreignRunReader{
		run:         run,
		roots:       roots,
		ruleLevel:   map[string]Level{},
		ruleScore:   map[string]float64{},
		ruleSummary: map[string]string{},
		rules:       map[string]*foreignRule{},
	}
	for i, rule := range run.Tool.Driver.Rules {
		if _, seen := fr.rules[rule.ID]; !seen {
			fr.rules[rule.ID] = &run.Tool.Driver.Rules[i]
		}
		if rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
			fr.ruleLevel[rule.ID] = Level(rule.DefaultConfiguration.Level)
		}
		if score, ok := rule.Properties.score(); ok {
			fr.ruleScore[rule.ID] = score
		}
		if sum := rule.ShortDescription.text(); sum != "" {
			fr.ruleSummary[rule.ID] = sum
		}
	}
	return fr
}

// result converts one result, and returns the path as written where it lies outside every root.
func (fr foreignRunReader) result(sr foreignResult) (Result, string, error) {
	ruleID, err := fr.ruleID(sr)
	if err != nil {
		return Result{}, "", err
	}
	// Resolution order per SARIF 2.1.0: the result's own level, then its rule's
	// defaultConfiguration.level, then "warning".
	level := Level(sr.Level)
	if level == "" {
		if rl, ok := fr.ruleLevel[ruleID]; ok {
			level = rl
		} else {
			level = LevelWarning
		}
	}
	res := Result{
		Tool:                fr.run.Tool.Driver.Name,
		RuleID:              ruleID,
		Level:               level,
		Message:             readableMessage(sr.Message.Text, fr.ruleSummary[ruleID]),
		Detail:              occurrenceLine(sr.Message.Text),
		PartialFingerprints: sr.PartialFingerprints,
	}
	var outside string
	if len(sr.Locations) > 0 {
		loc := sr.Locations[0].PhysicalLocation
		uri, inside, err := fr.locate(loc.ArtifactLocation)
		if err != nil {
			return Result{}, "", err
		}
		res.Location.URI = uri
		if !inside {
			outside = uri
		}
		if loc.Region != nil {
			res.Location.StartLine = loc.Region.StartLine
		}
	}
	rule := fr.rules[ruleID]
	res.Package = fr.packageOf(sr, rule, res.Location.URI)
	res.Aliases = statedAliases(sr, rule, ruleID)
	if score, ok := sr.Properties.score(); ok {
		res.Score, res.HasScore = score, true
	} else if score, ok := fr.ruleScore[ruleID]; ok {
		res.Score, res.HasScore = score, true
	}
	// The tool's suppression, as the tool's: its kind says which of the scanner's two it is, and
	// nothing in the file's property bag can make it a decision somebody recorded with Draugr.
	//
	// A finding is set aside only where every suppression on it stands. SARIF's status records the
	// team's decision about the request (3.35.3): rejected is a decision not to suppress, and
	// underReview is no decision yet. A file listing one of those beside an accepted entry disagrees
	// with itself, and a disagreement leaves the finding counting, with the request said in its
	// detail. Reading every entry means the order a tool lists them in decides nothing.
	declined := ""
	for _, sup := range sr.Suppressions {
		if !suppressionStands(sup.Status) && declined == "" {
			declined = "the file's suppression is " + sup.Status
		}
	}
	if len(sr.Suppressions) > 0 && declined == "" {
		first := sr.Suppressions[0]
		res.Suppression = &Suppression{Kind: first.Kind, Justification: first.Justification, Origin: scannersOwn(first.Kind)}
	}
	if declined != "" {
		res.Detail = strings.TrimPrefix(res.Detail+" · "+declined, " · ")
	}
	return res, outside, nil
}

// ruleID is the rule a result names: by id, by the id of its rule reference, or by index into the
// run's rules. An index that names no rule is an error, because the file then says nothing about
// which check failed.
func (fr foreignRunReader) ruleID(sr foreignResult) (string, error) {
	if sr.RuleID != "" {
		return sr.RuleID, nil
	}
	index, field := sr.RuleIndex, "ruleIndex"
	if sr.Rule != nil {
		if sr.Rule.ID != "" {
			return sr.Rule.ID, nil
		}
		if index == nil {
			index, field = sr.Rule.Index, "rule.index"
		}
	}
	if index == nil {
		return "", nil
	}
	rules := fr.run.Tool.Driver.Rules
	if *index < 0 || *index >= len(rules) {
		return "", fmt.Errorf("%s %d is not an entry of tool.driver.rules, %s", field, *index, entries(len(rules), "rule"))
	}
	return rules[*index].ID, nil
}

// maxBaseDepth bounds how many bases a URI may be resolved through. SARIF lets a base be relative
// to another; a chain longer than this is a loop in all but name.
const maxBaseDepth = 8

// locate turns an artifact location into a path relative to the checkout, and says whether it
// is inside it.
//
// The location may stand for an entry in the run's artifacts, and its URI may be relative to a base
// the run declares in originalUriBaseIds. A base that is itself relative to another is followed to
// the end. What comes out is one of three things:
//
//   - a relative path, with no base or with a base the run does not define (CodeQL's %SRCROOT% often
//     goes undefined): relative to the root of what the tool scanned, which is the checkout;
//   - a path relative to a base whose absolute URI is outside every root, such as the directory the
//     tool ran in on a build machine: the part relative to that base, for the same reason;
//   - an absolute path or file URI: relative to the root it is inside, or kept as written and
//     reported as outside.
func (fr foreignRunReader) locate(al foreignArtifactLocation) (string, bool, error) {
	if al.Index != nil {
		if *al.Index < 0 || *al.Index >= len(fr.run.Artifacts) {
			// Checkmarx writes an index beside the URI and lists no artifacts. The URI says where the
			// finding is; only a location with nothing but the index is left saying nothing.
			if al.URI != "" {
				al.Index = nil
				return fr.locate(al)
			}
			return "", false, fmt.Errorf("artifactLocation.index %d has no uri beside it and is not an entry of artifacts, %s; add a uri",
				*al.Index, entries(len(fr.run.Artifacts), "artifact"))
		}
		listed := fr.run.Artifacts[*al.Index].Location
		if al.URI == "" {
			al.URI = listed.URI
		}
		if al.URIBaseID == "" {
			al.URIBaseID = listed.URIBaseID
		}
	}
	written := al.URI
	rel := al.URI
	base := al.URIBaseID
	for depth := 0; base != "" && !isAbsoluteURI(rel); depth++ {
		if depth == maxBaseDepth {
			return "", false, fmt.Errorf("%q resolves through more than %d entries of originalUriBaseIds, "+
				"which usually means two refer to each other", written, maxBaseDepth)
		}
		def, ok := fr.run.OriginalURIBaseIDs[base]
		if !ok || def.URI == "" {
			break // an undefined base is the root of what was scanned
		}
		if isAbsoluteURI(def.URI) {
			abs, ok := filePath(def.URI)
			if !ok {
				return written, false, nil
			}
			full := filepath.Join(abs, filepath.FromSlash(unescape(rel)))
			if p, ok := fr.underRoot(full); ok {
				return p, true, nil
			}
			// A base that is not this machine's checkout: the tool scanned a copy elsewhere, and the
			// path below it is the path in the repository.
			return cleanRelative(rel)
		}
		rel = strings.TrimSuffix(def.URI, "/") + "/" + rel
		base = def.URIBaseID
	}
	if isAbsoluteURI(rel) {
		abs, ok := filePath(rel)
		if !ok {
			return written, false, nil
		}
		if p, ok := fr.underRoot(abs); ok {
			return p, true, nil
		}
		return written, false, nil
	}
	return cleanRelative(rel)
}

// entries says how many entries a SARIF array has and which indexes are valid, which a reader needs
// because the indexes count from 0 and the run and result numbers in the message from 1.
func entries(n int, noun string) string {
	switch n {
	case 0:
		return "which has no " + english.Noun(0, noun)
	case 1:
		return "which has " + english.Count(1, noun) + " (index 0)"
	default:
		return fmt.Sprintf("which has %s (0 to %d)", english.Count(n, noun), n-1)
	}
}

// cleanRelative normalizes a relative URI into a slash path. One that climbs out of the root it is
// relative to is outside it.
func cleanRelative(rel string) (string, bool, error) {
	p := path.Clean(strings.TrimPrefix(unescape(rel), "./"))
	if p == ".." || strings.HasPrefix(p, "../") {
		return rel, false, nil
	}
	return p, true, nil
}

// underRoot makes an absolute path relative to the root it lies in.
func (fr foreignRunReader) underRoot(abs string) (string, bool) {
	abs = filepath.Clean(abs)
	for _, root := range fr.roots {
		rel, err := filepath.Rel(filepath.Clean(root), abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return filepath.ToSlash(rel), true
	}
	return "", false
}

// isAbsoluteURI reports a URI with a scheme, or an absolute path, which no base applies to.
func isAbsoluteURI(uri string) bool {
	if strings.HasPrefix(uri, "/") {
		return true
	}
	if u, err := url.Parse(uri); err == nil && u.Scheme != "" && len(u.Scheme) > 1 {
		return true
	}
	// A Windows drive path, C:\src or C:/src, parses as a one-letter scheme.
	return len(uri) >= 3 && uri[1] == ':' && (uri[2] == '\\' || uri[2] == '/')
}

// filePath is the local path a file URI or an absolute path names, and false for any other scheme,
// which names nothing on this machine.
func filePath(uri string) (string, bool) {
	if strings.HasPrefix(uri, "/") {
		return filepath.FromSlash(unescape(uri)), true
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" {
		return "", false
	}
	return filepath.FromSlash(u.Path), true
}

// unescape decodes a URI's percent-escapes, leaving it as it was where it has a bad one.
func unescape(s string) string {
	if p, err := url.PathUnescape(s); err == nil {
		return p
	}
	return s
}

// suppressionStands reports whether a SARIF suppression with this status asks for its result to be
// set aside: accepted, or no status, which SARIF leaves optional and which tools write when the
// suppression is simply in force. rejected and underReview do not.
func suppressionStands(status string) bool {
	switch strings.ToLower(status) {
	case "", "accepted":
		return true
	}
	return false
}
