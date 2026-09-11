package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// checkReportNames rejects a report format or publisher kind this build does not have.
//
// `validate` answers "will this descriptor work", and it said yes to one that fails every run. The
// format registry lives in pkg/report, which cannot be reached from pkg/saga without an import
// cycle, so the descriptor's own validation can only check that the fields are present. The same
// split is why a publisher kind was checked for emptiness and nothing else.
//
// Catching it here costs milliseconds. Not catching it costs a whole scan: the failure surfaces at
// publish time, after every scanner has run.
func checkReportNames(model *saga.Model) error {
	if model == nil {
		return nil
	}
	var problems []string

	formats := map[string]bool{}
	for _, f := range report.Formats() {
		formats[f] = true
	}
	// Not in the registry: it renders whatever the descriptor supplies rather than a fixed layout,
	// so there is no reporter to look up.
	formats["template"] = true

	for i, r := range model.Config.Reports {
		if r.Format == "" {
			problems = append(problems,
				fmt.Sprintf("config.reports[%d].format is required", i))
			continue
		}
		if formats[r.Format] {
			continue
		}
		msg := fmt.Sprintf("config.reports[%d].format: %q is not a format this build of Draugr renders",
			i, r.Format)
		if near := nearestName(r.Format, formats); near != "" {
			msg += fmt.Sprintf(", did you mean %q?", near)
		}
		problems = append(problems, msg)
	}

	kinds := map[string]bool{}
	for _, k := range publish.Kinds() {
		kinds[k] = true
	}
	project := map[string]bool{}
	for _, r := range model.Config.Reports {
		project[r.Format] = true
	}
	seen := map[string]int{}
	for i, p := range model.Config.Publishers {
		if p.Kind == "" {
			continue // the descriptor's own check reports this
		}
		if !kinds[p.Kind] {
			msg := fmt.Sprintf("config.publishers[%d].kind: %q is not a publisher this build of Draugr has",
				i, p.Kind)
			if near := nearestName(p.Kind, kinds); near != "" {
				msg += fmt.Sprintf(", did you mean %q?", near)
			}
			problems = append(problems, msg)
			continue
		}
		// One kind twice is deliberate where the entries name different destinations and a mistake
		// where they do not, and the two are written identically. The field that tells them apart
		// is different for every kind, which is why nothing could check it from outside.
		field := publish.Distinguishes(p.Kind)
		id := p.Kind + "\x00" + publish.DistinguishingValue(p)
		if first, dup := seen[id]; dup {
			problems = append(problems, fmt.Sprintf(
				"config.publishers[%d] is the same destination as config.publishers[%d]: both are "+
					"%s with the same %s, so the second delivers where the first already did. Give "+
					"them different %s values, or keep one", i, first, p.Kind, field, field))
		} else {
			seen[id] = i
		}

		// What this destination is handed: its own reports, or the project's where it names none.
		declared, where := project, "config.reports"
		if len(p.Reports) > 0 {
			declared = make(map[string]bool, len(p.Reports))
			for _, r := range p.Reports {
				declared[r.Format] = true
			}
			where = fmt.Sprintf("config.publishers[%d].reports", i)
		}
		// A destination that cannot use anything rendered delivers nothing, and says so after the
		// scanners have finished. The descriptor already contains both halves of that answer.
		for _, f := range publish.Requires(p.Kind) {
			if declared[f] {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"config.publishers[%d]: the %s publisher delivers a %q report and %s declares "+
					"none. Add `- format: %s`", i, p.Kind, f, where, f))
		}
		for j, r := range p.Reports {
			if r.Format == "" {
				problems = append(problems, fmt.Sprintf(
					"config.publishers[%d].reports[%d].format is required", i, j))
				continue
			}
			if formats[r.Format] {
				continue
			}
			msg := fmt.Sprintf(
				"config.publishers[%d].reports[%d].format: %q is not a format this build of Draugr renders",
				i, j, r.Format)
			if near := nearestName(r.Format, formats); near != "" {
				msg += fmt.Sprintf(", did you mean %q?", near)
			}
			problems = append(problems, msg)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return errors.New(strings.Join(problems, "\n") +
		"\n\nformats: " + strings.Join(append(report.Formats(), "template"), ", ") +
		"\npublishers: " + strings.Join(publish.Kinds(), ", "))
}
