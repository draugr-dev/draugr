package scanners

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// An imported file's result carries no numeric security-severity more often than not, and its SARIF
// level tops out at high, so a file rated by level alone never yields a critical finding. Most tools
// state their own rating somewhere else in the file. Each rater below reads one tool's, by a table
// taken from the tool's own documentation or source, cited beside it, and records the row that
// applied on the finding as its Rating.
//
// A rater reads the runs whose tool.driver.name is its tool's, and no other: another tool writing a
// property of the same name has not said it means the same thing by it. A result carrying a numeric
// score keeps it. A result the table has no row for keeps its level.

// importRater rates the results of one tool's runs.
type importRater struct {
	// source names the rating in the provenance's severity field.
	source string
	// rate is the rating a result's fields give, or nil where the tool's table has no row for them.
	rate func(ratedResult) *sarif.Rating
}

// importRaters are the tools whose own rating Draugr reads, by tool.driver.name as their files write
// it, compared regardless of case.
var importRaters = map[string]importRater{
	"bandit":           {banditSource, func(r ratedResult) *sarif.Rating { return banditRating(r.result) }},
	"gosec":            {"gosec's severity tag", gosecRating},
	"codeql":           {"problem.severity", codeqlRating},
	"dependency-check": {"dependency-check's severity", dependencyCheckRating},
	"snyk open source": {"Snyk's severity", snykRating},
	// Fortify Static Code Analyzer's own SARIF. A file Fortify on Demand's fcli writes scores every
	// result with security-severity, which is read before any table.
	"micro focus fortify static code analyzer": {"Fortify's impact and likelihood", fortifyRating},
}

// ratedResult is what one result's rating is read from.
type ratedResult struct {
	// result and rule are the property bags of the result and of the rule it names.
	result, rule map[string]any
	// summary is the rule's shortDescription text, where some tools state the rating in words.
	summary string
}

// prop is a property of the result, or else of its rule: SARIF lets a result inherit what its rule
// states, as security-severity is read.
func (r ratedResult) prop(name string) any {
	if v, ok := r.result[name]; ok && v != nil {
		return v
	}
	return r.rule[name]
}

// propText is the text a table matches of a property, as the tool wrote it.
func (r ratedResult) propText(name string) string {
	return strings.Join(ratingTexts(r.prop(name)), ", ")
}

// fields keeps the named properties as the tool wrote them, leaving out those it did not write.
func (r ratedResult) fields(names ...string) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if s := r.propText(n); s != "" {
			out[n] = s
		}
	}
	return out
}

// raterFor is the rater for a run written by tool: the descriptor's mapping where the import gives
// one, which is the team's statement about its own file and so applies to every run in it, and else
// Draugr's table for the tool.
func raterFor(tool string, mapping *saga.ImportSeverity) (importRater, bool) {
	if mapping != nil {
		return descriptorRater(*mapping), true
	}
	r, ok := importRaters[strings.ToLower(strings.TrimSpace(tool))]
	return r, ok
}

// descriptorRater rates by the mapping an import declares.
func descriptorRater(m saga.ImportSeverity) importRater {
	return importRater{
		source: m.Property + ", mapped by the descriptor",
		rate: func(r ratedResult) *sarif.Rating {
			written, severity, ok := highestMapped(r.prop(m.Property), m.SeverityOf)
			if !ok {
				return nil
			}
			return newRating(severity, r.fields(m.Property), m.Property+" "+written)
		},
	}
}

// looseBag is a SARIF property bag. Anything other than an object under the name is no bag, as the
// import's reader treats every other member it does not recognize.
type looseBag map[string]any

func (b *looseBag) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if json.Unmarshal(data, &m) == nil {
		*b = m
	}
	return nil
}

// rateImported rates each unscored result of a run whose tool Draugr has a table for, or of every run
// where the import declares a mapping, and returns the source each result was rated by, "" for one
// it did not rate.
func rateImported(rep *sarif.Report, data []byte, mapping *saga.ImportSeverity) ([]string, error) {
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription *struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						Properties looseBag `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Properties looseBag `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("read the tool's ratings: %w", err)
	}
	sources := make([]string, len(rep.Results))
	// FromForeignSARIF flattens the runs' results in order, so the i-th result read here is rep's i-th.
	i := 0
	for _, run := range log.Runs {
		rater, ok := raterFor(run.Tool.Driver.Name, mapping)
		rules := map[string]ratedResult{}
		for _, rule := range run.Tool.Driver.Rules {
			if _, seen := rules[rule.ID]; seen {
				continue
			}
			r := ratedResult{rule: rule.Properties}
			if rule.ShortDescription != nil {
				r.summary = rule.ShortDescription.Text
			}
			rules[rule.ID] = r
		}
		for _, res := range run.Results {
			if i >= len(rep.Results) {
				return sources, nil
			}
			at := &rep.Results[i]
			i++
			if !ok || at.HasScore {
				continue
			}
			r := rules[at.RuleID]
			r.result = res.Properties
			if rating := rater.rate(r); rating != nil {
				at.Rating = rating
				sources[i-1] = rater.source
			}
		}
	}
	return sources, nil
}

// ratingTexts are the texts a table matches in a property's value: a string, each string or number
// of a list, or a number as JSON writes it.
func ratingTexts(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, ratingTexts(e)...)
		}
		return out
	}
	return nil
}

// highestMapped is the most severe rating lookup gives any of a property's texts, with the text that
// gave it. A list such as a rule's tags may name more than one, and a finding is not rated lower
// than one of its own tool's words says.
func highestMapped(v any, lookup func(string) (sarif.Severity, bool)) (string, sarif.Severity, bool) {
	var written string
	var best sarif.Severity
	for _, text := range ratingTexts(v) {
		if s, ok := lookup(text); ok && s.Rank() > best.Rank() {
			written, best = text, s
		}
	}
	return written, best, best.Rank() > 0
}

// wordTable looks a word up in table regardless of case and surrounding space.
func wordTable(table map[string]sarif.Severity) func(string) (sarif.Severity, bool) {
	return func(text string) (sarif.Severity, bool) {
		s, ok := table[strings.ToLower(strings.TrimSpace(text))]
		return s, ok
	}
}

// ratingNumber is a property's value as a number, written as one or as a string holding one.
func ratingNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}

// gosecRating is the severity gosec's rule tag gives a result, the same table Draugr's own gosec
// scanner reads (gosecSeverityLevel), so an imported gosec file ranks as a gosec run by Draugr does.
//
// gosec states its rating only as a tag on the rule, `"tags": ["security", "MEDIUM"]`, and writes
// level error for MEDIUM as well as HIGH and warning for LOW (report/sarif/formatter.go,
// parseSarifRule and getSarifLevel, in github.com/securego/gosec). Read by level, a MEDIUM rule ranks
// high and a LOW one medium, a band above where gosec put each. gosec has no rung above HIGH, so
// nothing it reports is critical. Its confidence, written as the rule's precision, is not read, as
// the gosec scanner does not read it.
func gosecRating(r ratedResult) *sarif.Rating {
	written, severity, ok := highestMapped(r.prop("tags"), func(text string) (sarif.Severity, bool) {
		level, ok := gosecSeverityLevel[text]
		return sarif.Result{Level: level}.Severity(""), ok
	})
	if !ok {
		return nil
	}
	return newRating(severity, r.fields("tags"), "severity tag "+strings.ToLower(written))
}

// codeqlSeverity is the severity each of CodeQL's problem.severity values gives a query that carries
// no security-severity score.
//
// From the query metadata style guide (docs/query-metadata-style-guide.md in github.com/github/codeql):
// `error` is "likely to cause incorrect program behavior, for example a crash or vulnerability",
// `warning` "a potential problem", and `recommendation` code that "behaves correctly, but it could be
// improved". The guide maps none of them to a band; these are the bands the SARIF level CodeQL writes
// for each already gives, so the rating names CodeQL's word without moving any finding. A security
// query carries security-severity, which is read first.
var codeqlSeverity = map[string]sarif.Severity{
	"error":          sarif.SeverityHigh,
	"warning":        sarif.SeverityMedium,
	"recommendation": sarif.SeverityLow,
}

// codeqlRating is the severity a CodeQL query's problem.severity gives, written on the rule.
func codeqlRating(r ratedResult) *sarif.Rating {
	written, severity, ok := highestMapped(r.prop("problem.severity"), wordTable(codeqlSeverity))
	if !ok {
		return nil
	}
	return newRating(severity, r.fields("problem.severity"), "problem.severity "+strings.ToLower(written))
}

// cvssRating is the severity each CVSS v3 qualitative rating names, the scale of section 5 of the
// CVSS v3.1 specification (https://www.first.org/cvss/v3.1/specification-document), whose bands are
// Draugr's. None, a score of 0.0, rates nothing.
var cvssRating = map[string]sarif.Severity{
	"critical": sarif.SeverityCritical,
	"high":     sarif.SeverityHigh,
	"medium":   sarif.SeverityMedium,
	"low":      sarif.SeverityLow,
}

// dependencyCheckWords is the severity each word OWASP dependency-check writes for an advisory with
// no CVSS score gives. dependency-check normalizes a source's words to critical, high, medium, low or
// unknown (ReportTool.normalizeSeverity, in github.com/dependency-check/DependencyCheck): moderate is
// medium, and informational and info are low. Unknown rates nothing.
var dependencyCheckWords = map[string]sarif.Severity{
	"critical":      sarif.SeverityCritical,
	"high":          sarif.SeverityHigh,
	"medium":        sarif.SeverityMedium,
	"moderate":      sarif.SeverityMedium,
	"low":           sarif.SeverityLow,
	"informational": sarif.SeverityLow,
	"info":          sarif.SeverityLow,
}

// dependencyCheckRating is the rating OWASP dependency-check states for an advisory it scores no
// security-severity for, from the first of these it writes:
//
//  1. cvssv3_baseSeverity, CVSS v3's own word;
//  2. cvssv2_score, banded as every score Draugr reads is. CVSS v2 defines no critical rating, so a
//     v2 score of 9.0 or more is rated critical, the higher of the two readings, rather than the high
//     its cvssv2_severity says;
//  3. cvssv2_severity, where no v2 score is written;
//  4. severity, which version 6 writes on a result for an advisory with no CVSS score;
//  5. the rule's summary, which current versions open with the same word: "medium severity - …".
//
// The properties are written by core/src/main/resources/templates/sarifReport.vsl, on the rule in
// current versions and on the result in version 6; the summary by ReportTool.buildShortDescription.
// Current versions also write security-severity wherever there is a v3 or v4 score, and it is read
// first.
func dependencyCheckRating(r ratedResult) *sarif.Rating {
	if written, severity, ok := highestMapped(r.prop("cvssv3_baseSeverity"), wordTable(cvssRating)); ok {
		return newRating(severity, r.fields("cvssv3_baseSeverity", "cvssv3_baseScore"),
			"cvssv3_baseSeverity "+strings.ToLower(written))
	}
	if score, ok := ratingNumber(r.prop("cvssv2_score")); ok {
		return newRating(sarif.SeverityFromScore(score), r.fields("cvssv2_score", "cvssv2_severity"),
			"cvssv2_score "+strconv.FormatFloat(score, 'f', -1, 64))
	}
	if written, severity, ok := highestMapped(r.prop("cvssv2_severity"), wordTable(cvssRating)); ok {
		return newRating(severity, r.fields("cvssv2_severity"), "cvssv2_severity "+strings.ToLower(written))
	}
	if written, severity, ok := highestMapped(r.prop("severity"), wordTable(dependencyCheckWords)); ok {
		return newRating(severity, r.fields("severity"), "severity "+strings.ToLower(written))
	}
	return summaryRating(r.summary, dependencyCheckWords)
}

// summaryWord is the rating word a rule's summary opens with, as dependency-check and Snyk write it:
// "High severity - Prototype Pollution vulnerability in lodash".
var summaryWord = regexp.MustCompile(`^\s*([A-Za-z]+) severity - `)

// summaryRating is the rating the word opening a rule's summary gives, by table, or nil.
func summaryRating(summary string, table map[string]sarif.Severity) *sarif.Rating {
	m := summaryWord.FindStringSubmatch(summary)
	if m == nil {
		return nil
	}
	severity, ok := table[strings.ToLower(m[1])]
	if !ok {
		return nil
	}
	written := m[1] + " severity"
	return newRating(severity, map[string]string{"shortDescription": written}, written)
}

// snykSeverity is the severity each of Snyk's own ratings gives: low, medium, high and critical, the
// four Snyk's CLI writes, capitalized, at the head of each rule's summary
// (src/lib/formatters/open-source-sarif-output.ts, getRules, in github.com/snyk/cli).
var snykSeverity = map[string]sarif.Severity{
	"critical": sarif.SeverityCritical,
	"high":     sarif.SeverityHigh,
	"medium":   sarif.SeverityMedium,
	"low":      sarif.SeverityLow,
}

// snykRating is the rating a Snyk Open Source rule's summary states, for a result with no score.
//
// Snyk writes security-severity from the advisory's CVSS score, which is read first, and the level
// from its own rating with critical and high both written `error` (get-sarif-result.ts, getLevel). An
// advisory with no CVSS score, a license issue among them, would otherwise rank a critical as high.
func snykRating(r ratedResult) *sarif.Rating {
	return summaryRating(r.summary, snykSeverity)
}

// fortifyHigh is the value at and above which Fortify counts impact and likelihood high, each on its
// scale of 0 to 5.
const fortifyHigh = 2.5

// fortifyTolerance keeps a value Fortify computes as exactly 2.5 from falling below it in floating
// point, which would rate the finding lower than Fortify does.
const fortifyTolerance = 1e-9

// fortifyRating is Fortify's priority for a result of Fortify Static Code Analyzer, from the rule's
// Impact, Accuracy and Probability and the result's Confidence, as Fortify computes it
// (fcli-core/fcli-common-fpr/src/main/java/com/fortify/cli/common/fpr/processor/VulnFinalizer.java,
// deriveFields, in github.com/fortify/fcli):
//
//	likelihood = Accuracy × Confidence × Probability / 25
//	Impact ≥ 2.5, likelihood ≥ 2.5: Critical
//	Impact ≥ 2.5, likelihood < 2.5: High
//	Impact < 2.5, likelihood ≥ 2.5: Medium
//	Impact < 2.5, likelihood < 2.5: Low
//
// Each of Fortify's four is the severity of the same name. A result missing any of the four values
// keeps its level: Fortify fills a missing one from its own category data, which the file does not
// carry.
func fortifyRating(r ratedResult) *sarif.Rating {
	names := []string{"Impact", "Accuracy", "Probability", "Confidence"}
	values := make([]float64, len(names))
	for i, n := range names {
		v, ok := ratingNumber(r.prop(n))
		if !ok {
			return nil
		}
		values[i] = v
	}
	impact, accuracy, probability, confidence := values[0], values[1], values[2], values[3]
	product := accuracy * confidence * probability
	highImpact := impact >= fortifyHigh-fortifyTolerance
	likely := product >= 25*fortifyHigh-fortifyTolerance
	var severity sarif.Severity
	switch {
	case highImpact && likely:
		severity = sarif.SeverityCritical
	case highImpact:
		severity = sarif.SeverityHigh
	case likely:
		severity = sarif.SeverityMedium
	default:
		severity = sarif.SeverityLow
	}
	likelihood := math.Round(product/25*100) / 100
	return newRating(severity, r.fields(names...), "Impact "+r.propText("Impact"),
		"likelihood "+strconv.FormatFloat(likelihood, 'f', -1, 64))
}
