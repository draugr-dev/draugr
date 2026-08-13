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
// `validate` answers "will this descriptor work", and it said yes to one that fails every run —
// the format registry lives in pkg/report, which cannot be reached from pkg/saga without an import
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
			msg += fmt.Sprintf(" — did you mean %q?", near)
		}
		problems = append(problems, msg)
	}

	kinds := map[string]bool{}
	for _, k := range publish.Kinds() {
		kinds[k] = true
	}
	for i, p := range model.Config.Publishers {
		if p.Kind == "" || kinds[p.Kind] {
			continue // an empty kind is the descriptor's own check, and already reported
		}
		msg := fmt.Sprintf("config.publishers[%d].kind: %q is not a publisher this build of Draugr has",
			i, p.Kind)
		if near := nearestName(p.Kind, kinds); near != "" {
			msg += fmt.Sprintf(" — did you mean %q?", near)
		}
		problems = append(problems, msg)
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return errors.New(strings.Join(problems, "\n") +
		"\n\nformats: " + strings.Join(append(report.Formats(), "template"), ", ") +
		"\npublishers: " + strings.Join(publish.Kinds(), ", "))
}
