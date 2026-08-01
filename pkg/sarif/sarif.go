package sarif

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Version is the SARIF specification version Draugr emits.
const Version = "2.1.0"

const schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

// The types below mirror the subset of the SARIF 2.1.0 JSON structure that Draugr
// produces and consumes.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
	// OriginalURIBaseIDs declares what Draugr's relative result paths are relative to. Required
	// by the SARIF spec whenever relative URI references are used; it's what lets an editor's
	// viewer resolve a finding onto a file in the open workspace instead of asking the reader.
	OriginalURIBaseIDs map[string]sarifArtifact `json:"originalUriBaseIds,omitempty"`
	// Properties carries what the scanners said about the run itself. SARIF defines a property
	// bag on a run for exactly this, so the benchmark a report was measured against travels to
	// any consumer that reads SARIF rather than only to Draugr's own reporters.
	Properties *sarifRunProperties `json:"properties,omitempty"`
}

// sarifRunProperties is Draugr's run-level property bag.
type sarifRunProperties struct {
	Provenance []sarifProvenance `json:"draugr/provenance,omitempty"`
}

// sarifProvenance mirrors Provenance in the property bag. Written as an object per tool rather
// than flattened, for the same reason the type is a slice: two scanners have two answers.
type sarifProvenance struct {
	Tool    string            `json:"tool"`
	Version string            `json:"version,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// runProperties renders provenance into the bag, or nil when there is nothing to say.
//
// The fields become an object here, unlike the ordered slice they are internally: JSON object
// keys have no order a consumer can rely on, so pretending otherwise would be a promise the
// format cannot keep. Order is a rendering concern, and this is not the rendering.
func runProperties(entries []Provenance) *sarifRunProperties {
	if len(entries) == 0 {
		return nil
	}
	out := make([]sarifProvenance, 0, len(entries))
	for _, p := range entries {
		sp := sarifProvenance{Tool: p.Tool, Version: p.Version}
		if len(p.Fields) > 0 {
			sp.Fields = make(map[string]string, len(p.Fields))
			for _, f := range p.Fields {
				sp.Fields[f.Key] = f.Value
			}
		}
		out = append(out, sp)
	}
	return &sarifRunProperties{Provenance: out}
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// The descriptive fields. GitHub code scanning renders shortDescription, fullDescription and
	// help beside a result; SARIF viewers additionally link helpUri. Draugr doesn't author these
	// — it relays what the scanner published, which is the difference between a reader seeing
	// "DS-0002" and seeing what DS-0002 means.
	ShortDescription     *sarifMessage    `json:"shortDescription,omitempty"`
	FullDescription      *sarifMessage    `json:"fullDescription,omitempty"`
	Help                 *sarifMessage    `json:"help,omitempty"`
	HelpURI              string           `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           *sarifProperties `json:"properties,omitempty"`
}

// text returns m's text, tolerating a nil message so callers can read optional fields inline.
func (m *sarifMessage) text() string {
	if m == nil {
		return ""
	}
	return m.Text
}

// message wraps s as a SARIF message, or nil when there's nothing to say.
func message(s string) *sarifMessage {
	if s == "" {
		return nil
	}
	return &sarifMessage{Text: s}
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

// sarifProperties carries the property-bag fields Draugr reads/writes. "security-severity"
// is the SARIF/GitHub convention for a numeric CVSS-style score, serialized as a string;
// "priority" is Draugr's computed action band.
type sarifProperties struct {
	SecuritySeverity string `json:"security-severity,omitempty"`
	Priority         string `json:"priority,omitempty"`
	// Tool is the originating scanner (e.g. "trivy", "semgrep"). Draugr reports as a single
	// "Draugr" SARIF tool; this preserves per-finding attribution to the scanner that found it.
	Tool string `json:"tool,omitempty"`
	// Component is the part of the application the finding belongs to. A location alone is
	// ambiguous once a descriptor has more than one component, and it is what makes the priority
	// checkable — the band comes from that component's declared classification.
	Component string `json:"component,omitempty"`
	// Tags are rule-level labels. Draugr tags each rule with "scanner:<name>" so consumers
	// (e.g. GitHub code scanning) surface which underlying scanner produced a finding.
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId,omitempty"`
	Level        string             `json:"level,omitempty"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
	Properties   *sarifProperties   `json:"properties,omitempty"`
}

// sarifSuppression marks a result the author or tool has suppressed (e.g. Semgrep's
// in-source `nosem` comments). A result with any suppression is not an active finding.
type sarifSuppression struct {
	Kind string `json:"kind"`
	// Justification is why. SARIF makes it optional; Draugr always writes one for the
	// suppressions it creates, because an exclusion without a stated reason is how a scanner
	// gets quietly defanged.
	Justification string `json:"justification,omitempty"`
	// Properties carries who accepted the suppression and when it lapses.
	//
	// SARIF has no field for either, and the spec's property bag is where a producer puts what
	// the schema does not model. They go here rather than being folded into the justification
	// text because a consumer should be able to read "who" as a value — the whole reason the
	// descriptor records it is so a report can be filtered and audited by it, and a name inside
	// a sentence cannot be.
	Properties *sarifSuppressionProperties `json:"properties,omitempty"`
}

// sarifSuppressionProperties holds Draugr's suppression metadata in SARIF's property bag.
type sarifSuppressionProperties struct {
	AcceptedBy string `json:"acceptedBy,omitempty"`
	Expires    string `json:"expires,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri,omitempty"`
	// URIBaseID names the entry in the run's originalURIBaseIDs that URI is relative to.
	URIBaseID string `json:"uriBaseId,omitempty"`
	// Description explains a base id to a human reader when we can't give it a concrete uri.
	Description *sarifMessage `json:"description,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// driverName is the single SARIF tool Draugr reports as. Draugr is an orchestrator that
// normalizes many scanners into one report, so it presents as one tool; each finding keeps its
// originating scanner in properties.tool. This gives consumers (e.g. GitHub code scanning) a
// single "Draugr" analysis tool instead of one per underlying scanner.
const driverName = "Draugr"

// MarshalOptions tunes how a report is serialized. The zero value is the default: indented,
// with everything a person or an editor might want.
type MarshalOptions struct {
	// Compact drops what only a human reads — indentation, and the rule prose relayed from
	// the scanner — while keeping the report valid SARIF.
	//
	// It exists for a consumer that is going to *act* on the report rather than read it,
	// typically an agent paying for every byte of context. Rule descriptions and remediation
	// text are the bulk of a Draugr report (61% of it, measured on this repo), and a reader
	// that can follow a link doesn't need them inlined. So helpUri survives compaction and the
	// prose doesn't: keep the pointer, drop the paragraphs.
	Compact bool
}

// MarshalSARIF serializes the report to standard SARIF 2.1.0 JSON as a single "Draugr" run,
// with each result's originating scanner recorded in its property bag ("tool").
func (r Report) MarshalSARIF() ([]byte, error) {
	return r.MarshalSARIFWith(MarshalOptions{})
}

// MarshalSARIFWith is MarshalSARIF with explicit options.
func (r Report) MarshalSARIFWith(opts MarshalOptions) ([]byte, error) {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: driverName}}, Results: []sarifResult{}}
	run.Properties = runProperties(r.Provenance)
	// Track which scanner(s) produced each ruleId so the emitted rules[] can carry a
	// "scanner:<name>" tag — the only place GitHub code scanning surfaces the underlying tool.
	ruleScanners := map[string]map[string]bool{}
	var ruleOrder []string
	for _, res := range r.Results {
		tool := res.Tool
		if tool == "" {
			tool = r.Tool
		}
		if res.RuleID != "" {
			if ruleScanners[res.RuleID] == nil {
				ruleScanners[res.RuleID] = map[string]bool{}
				ruleOrder = append(ruleOrder, res.RuleID)
			}
			if tool != "" {
				ruleScanners[res.RuleID][tool] = true
			}
		}
		sr := sarifResult{
			RuleID:  res.RuleID,
			Level:   string(res.Level),
			Message: sarifMessage{Text: res.Message},
		}
		// A suppressed finding is still emitted, marked. Deleting it would leave no trace that
		// anything was excluded; this way the evidence survives and only the verdict changes.
		// GitHub code scanning reads this and files the alert as closed-as-suppressed.
		if s := res.Suppression; s != nil {
			sup := sarifSuppression{Kind: s.Kind, Justification: s.Justification}
			if s.AcceptedBy != "" || s.Expires != "" {
				sup.Properties = &sarifSuppressionProperties{AcceptedBy: s.AcceptedBy, Expires: s.Expires}
			}
			sr.Suppressions = []sarifSuppression{sup}
		}
		if res.Location.URI != "" {
			art := sarifArtifact{URI: res.Location.URI}
			// Only a repo-relative path needs a base to resolve against; an absolute URI
			// (a container image ref, a host) already stands on its own.
			if isRelativeURI(res.Location.URI) {
				art.URIBaseID = uriBaseID
				run.OriginalURIBaseIDs = originalURIBaseIDs()
			}
			loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: art}}
			if res.Location.StartLine > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: res.Location.StartLine}
			}
			sr.Locations = append(sr.Locations, loc)
		}
		if tool != "" || res.HasScore || res.Priority != "" {
			sr.Properties = &sarifProperties{Tool: tool, Priority: res.Priority, Component: res.Component}
			if res.HasScore {
				sr.Properties.SecuritySeverity = strconv.FormatFloat(res.Score, 'f', -1, 64)
			}
		}
		run.Results = append(run.Results, sr)
	}
	// Emit one rule per ruleId, tagged with its originating scanner(s). GitHub matches a
	// result to its rule by ruleId and shows the rule's tags on the alert.
	for _, id := range ruleOrder {
		scanners := make([]string, 0, len(ruleScanners[id]))
		for s := range ruleScanners[id] {
			scanners = append(scanners, s)
		}
		sort.Strings(scanners)
		tags := make([]string, 0, len(scanners))
		for _, s := range scanners {
			tags = append(tags, "scanner:"+s)
		}
		rule := r.Rules[id]
		out := sarifRule{ID: id, HelpURI: r.HelpURI(id)}
		if !opts.Compact {
			out.Name = rule.Name
			out.ShortDescription = message(clampDescription(rule.ShortDescription))
			out.FullDescription = message(clampDescription(rule.FullDescription))
			out.Help = message(rule.Help)
		}
		if len(tags) > 0 {
			out.Properties = &sarifProperties{Tags: tags}
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, out)
	}
	log := sarifLog{Schema: schemaURL, Version: Version, Runs: []sarifRun{run}}
	if opts.Compact {
		return json.Marshal(log)
	}
	return json.MarshalIndent(log, "", "  ")
}

// uriBaseID names the root Draugr's relative paths are relative to. Scanners run against a
// checkout, and finding paths are rewritten repo-relative so they stay stable across runs; this
// tells a consumer what to join them onto. "%SRCROOT%" is the conventional spelling, and the one
// GitHub's own documentation uses.
const uriBaseID = "%SRCROOT%"

// originalURIBaseIDs describes the base without claiming a concrete path. Draugr scans a
// throwaway checkout, so the directory it used is meaningless to whoever reads the report later
// — the consumer's own workspace root is the right base, and only the consumer knows it.
func originalURIBaseIDs() map[string]sarifArtifact {
	return map[string]sarifArtifact{
		uriBaseID: {Description: message("The root of the scanned source tree.")},
	}
}

// isRelativeURI reports whether uri is a path that needs a base to resolve against, as opposed
// to something that already identifies its subject on its own.
//
// The test is deliberately blunt: a relative path, and no colon anywhere. A colon is what
// separates the things that aren't source paths — a scheme ("https:", "pkg:"), an image tag
// ("library/alpine:3.18"), a Windows drive. Source paths that contain one are rare, and the cost
// of missing one is only that we don't declare a base for it, which is where we started.
func isRelativeURI(uri string) bool {
	return !strings.HasPrefix(uri, "/") && !strings.Contains(uri, ":")
}

// descriptionLimit is GitHub code scanning's documented cap on rule description length. Longer
// text is the scanner's, not ours, so we clip rather than drop it.
const descriptionLimit = 1024

func clampDescription(s string) string {
	if len(s) <= descriptionLimit {
		return s
	}
	// Cut on a rune boundary — a description is arbitrary scanner text and may be non-ASCII.
	const ellipsis = "…"
	cut := descriptionLimit - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + ellipsis
}

// parseSecuritySeverity reads the numeric "security-severity" score (a string per SARIF)
// from a property bag, reporting whether a valid score was present.
func parseSecuritySeverity(p *sarifProperties) (float64, bool) {
	if p == nil || p.SecuritySeverity == "" {
		return 0, false
	}
	score, err := strconv.ParseFloat(p.SecuritySeverity, 64)
	if err != nil {
		return 0, false
	}
	return score, true
}

// FromSARIF parses standard SARIF 2.1.0 JSON into a Report, flattening all runs and
// setting each result's Tool from its run's driver name.
func FromSARIF(data []byte) (Report, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return Report{}, err
	}
	var out Report
	for i, run := range log.Runs {
		if i == 0 {
			out.Tool = run.Tool.Driver.Name
		}
		// SARIF lets a result omit its level and inherit it from the rule's
		// defaultConfiguration. Some tools (e.g. Semgrep) rely on this. Index the rules so
		// we can resolve a result's severity from its ruleId.
		ruleLevel := make(map[string]Level, len(run.Tool.Driver.Rules))
		// Rules also carry a numeric "security-severity" (CVSS-style) that results inherit
		// by ruleId, the way many tools (e.g. Trivy) express severity.
		ruleScore := make(map[string]float64, len(run.Tool.Driver.Rules))
		// And a one-line summary, used to rescue results whose message is a field dump
		// rather than a sentence. See readableMessage.
		ruleSummary := make(map[string]string, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			if rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
				ruleLevel[rule.ID] = Level(rule.DefaultConfiguration.Level)
			}
			if score, ok := parseSecuritySeverity(rule.Properties); ok {
				ruleScore[rule.ID] = score
			}
			if sum := rule.ShortDescription.text(); sum != "" {
				ruleSummary[rule.ID] = sum
			}
			// Keep what the scanner said about the rule. It's the only description of a
			// finding that isn't specific to one occurrence of it, and every downstream
			// reader — terminal, editor, pull request — is better off for having it.
			out.addRule(rule.ID, Rule{
				Name:             rule.Name,
				ShortDescription: rule.ShortDescription.text(),
				FullDescription:  rule.FullDescription.text(),
				Help:             rule.Help.text(),
				HelpURI:          rule.HelpURI,
			})
		}
		for _, sr := range run.Results {
			// Skip results the tool reports as suppressed (e.g. Semgrep in-source `nosem`
			// comments). Per SARIF, a result with any suppression is not an active finding.
			if len(sr.Suppressions) > 0 {
				continue
			}
			level := Level(sr.Level)
			if level == "" {
				// Resolution order per SARIF 2.1.0: the result's own level, then its rule's
				// defaultConfiguration.level, then "warning". Some tools (e.g. Gitleaks) omit
				// it entirely and fall through to the default.
				if rl, ok := ruleLevel[sr.RuleID]; ok {
					level = rl
				} else {
					level = LevelWarning
				}
			}
			// Prefer the per-result originating tool (properties.tool, written when Draugr
			// emits a single "Draugr" run) over the run's driver name, so round-tripping
			// Draugr's own SARIF preserves each finding's scanner.
			tool := run.Tool.Driver.Name
			if sr.Properties != nil && sr.Properties.Tool != "" {
				tool = sr.Properties.Tool
			}
			res := Result{
				Tool:    tool,
				RuleID:  sr.RuleID,
				Level:   level,
				Message: readableMessage(sr.Message.Text, ruleSummary[sr.RuleID]),
			}
			if len(sr.Locations) > 0 {
				res.Location.URI = sr.Locations[0].PhysicalLocation.ArtifactLocation.URI
				if region := sr.Locations[0].PhysicalLocation.Region; region != nil {
					res.Location.StartLine = region.StartLine
				}
			}
			// A numeric score on the result overrides the rule's; otherwise inherit it.
			if score, ok := parseSecuritySeverity(sr.Properties); ok {
				res.Score, res.HasScore = score, true
			} else if score, ok := ruleScore[sr.RuleID]; ok {
				res.Score, res.HasScore = score, true
			}
			if sr.Properties != nil && sr.Properties.Priority != "" {
				res.Priority = sr.Properties.Priority
			}
			out.Results = append(out.Results, res)
		}
	}
	return out, nil
}

// fieldDump matches the opening of a message that is a list of fields rather than a sentence —
// "Package: Flask", "Artifact: app/Dockerfile". Trivy writes its finding messages this way.
var fieldDump = regexp.MustCompile(`^[A-Z][A-Za-z ]{0,30}:[ \t]`)

// readableMessage picks the text a reader can act on, given the rule's one-line summary.
//
// Most scanners write a sentence. Trivy writes a multi-line field dump — artifact, package,
// installed version, severity, fixed version, link. Every consumer suffers for it differently:
// a terminal has those fields in its own columns already and clamps the line before reaching
// the part that says what is wrong, and an editor's Problems panel shows the *first* line, so a
// manifest with fourteen findings becomes fourteen rows reading "Artifact: deploy/pod.yaml".
// The advisory title lives in the rule's shortDescription instead: "python-flask: Denial of
// Service via crafted JSON file".
//
// Applied here, at the point a tool's SARIF becomes Draugr's model, so every downstream reader
// gets it — the terminal, the SARIF handed to an editor, code-scanning annotations, and MCP
// clients. Nothing is lost by preferring the summary: the scanner's own detail survives on the
// rule as FullDescription and Help, which is what a viewer shows beside a selected finding.
//
// Detected structurally rather than by scanner name, so any tool that dumps fields gets the
// same treatment: several lines, the first of which opens "Word: ". A message that is already
// prose is left alone, which matters because some scanners publish a shortDescription that only
// restates the rule id.
func readableMessage(msg, summary string) string {
	if summary == "" {
		return msg
	}
	if !strings.Contains(msg, "\n") || !fieldDump.MatchString(msg) {
		return msg
	}
	return summary
}
