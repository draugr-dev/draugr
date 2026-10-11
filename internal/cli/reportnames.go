package cli

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
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

	kinds := map[string]bool{}
	for _, k := range publish.Kinds() {
		kinds[k] = true
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

		problems = append(problems, checkPublisherFields(i, p)...)
		problems = append(problems, checkIssueFields(model, i, p)...)
		if publish.IssueKind(p.Kind) {
			continue
		}

		// A destination with no format of its own and none named delivers nothing. `file` is the
		// only such kind: a directory has no inherent format, so what goes in it is a choice
		// somebody has to make.
		if len(publish.Renders(p.Kind)) == 0 && len(p.Reports) == 0 {
			problems = append(problems, fmt.Sprintf(
				"config.publishers[%d]: the %s publisher has no format of its own and names none, "+
					"so it would deliver nothing. Add the formats it is for, e.g. "+
					"`reports: [{format: sarif}]`", i, p.Kind))
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

// checkPublisherFields holds an entry's fields to what its kind reads, requires and delivers, as
// pkg/publish declares them. The schema is generated from the same declarations, so the editor and
// this check give one answer.
//
// A field the kind does not read is ignored by the publisher, so a descriptor carrying one claims a
// destination, a narrowing or a label that nothing applies. A format the kind does not deliver is
// rendered and dropped.
func checkPublisherFields(i int, p saga.PublisherConfig) []string {
	var problems []string
	unread := publish.Unread(p)
	if publish.IssueKind(p.Kind) && slices.Contains(unread, "reports") {
		problems = append(problems, fmt.Sprintf(
			"config.publishers[%d].reports: the %s publisher builds its body from the run and renders no report; remove reports",
			i, p.Kind))
		unread = slices.DeleteFunc(unread, func(f string) bool { return f == "reports" })
	}
	if len(unread) > 0 {
		problems = append(problems, fmt.Sprintf(
			"config.publishers[%d]: the %s publisher does not read %s; remove %s",
			i, p.Kind, list(unread), english.Choose(len(unread), "it", "them")))
	}
	written := p.Written()
	for _, f := range publish.Requires(p.Kind) {
		// A missing reports list has its own message, which says what to write.
		if f != "reports" && !slices.Contains(written, f) {
			problems = append(problems, fmt.Sprintf("config.publishers[%d]: the %s publisher needs %s", i, p.Kind, f))
		}
	}
	if formats, deliversOnly := publish.Accepts(p.Kind); deliversOnly && !publish.IssueKind(p.Kind) {
		for j, r := range p.Reports {
			if r.Format != "" && !slices.Contains(formats, r.Format) {
				problems = append(problems, fmt.Sprintf(
					"config.publishers[%d].reports[%d].format: the %s publisher delivers only %s; name %s or remove this report",
					i, j, p.Kind, list(formats), list(formats)))
			}
		}
	}
	if p.PR < 0 {
		problems = append(problems, fmt.Sprintf(
			"config.publishers[%d].pr: %d is not valid; write the pull-request number, or omit pr to read it from CI", i, p.PR))
	}
	if p.URL != "" && !strings.HasPrefix(p.URL, "https://") && !strings.HasPrefix(p.URL, "http://") {
		problems = append(problems, fmt.Sprintf(
			"config.publishers[%d].url: %q must start with https:// or http://", i, p.URL))
	}
	return problems
}

// checkIssueFields holds what an issue publisher's fields say to the descriptor around them.
func checkIssueFields(model *saga.Model, i int, p saga.PublisherConfig) []string {
	if !publish.IssueKind(p.Kind) {
		return nil
	}
	var problems []string
	if model.ProjectName() == "" {
		problems = append(problems, fmt.Sprintf(
			"config.publishers[%d]: the %s publisher finds its issues by project, and the descriptor names none; set project",
			i, p.Kind))
	}
	if it := p.Item; it != nil {
		for _, key := range itemKeys(*it) {
			if readers := itemReaders[key]; !slices.Contains(readers, p.Kind) {
				problems = append(problems, fmt.Sprintf(
					"config.publishers[%d]: the %s publisher does not read item.%s, which only %s %s",
					i, p.Kind, key, english.And(readers), english.Choose(len(readers), "reads", "read")))
			}
		}
		if p.Kind == "gitlab-issue" && it.Type != "" && !slices.Contains(publish.GitLabIssueTypes, it.Type) {
			problems = append(problems, fmt.Sprintf(
				"config.publishers[%d].item.type is %q, but a GitLab issue type is %s",
				i, it.Type, list(publish.GitLabIssueTypes)))
		}
	}
	if p.Select != nil {
		declared := map[string]bool{}
		for _, c := range model.Components {
			declared[c.Name] = true
		}
		for _, name := range p.Select.Components {
			if declared[name] {
				continue
			}
			msg := fmt.Sprintf("config.publishers[%d].select.components: %q is not a component of this descriptor", i, name)
			if near := nearestName(name, declared); near != "" {
				msg += fmt.Sprintf(", did you mean %q?", near)
			}
			problems = append(problems, msg)
		}
	}
	return problems
}

// itemReaders names the kinds that read each `item` key. A key set on any other kind is refused,
// since nothing would apply it.
var itemReaders = map[string][]string{
	"labels":        {"github-issue", "gitlab-issue"},
	"assignees":     {"github-issue", "gitlab-issue"},
	"milestone":     {"github-issue", "gitlab-issue"},
	"type":          {"github-issue", "gitlab-issue", "azure-work-item"},
	"confidential":  {"gitlab-issue"},
	"tags":          {"azure-work-item"},
	"assignedTo":    {"azure-work-item"},
	"areaPath":      {"azure-work-item"},
	"iterationPath": {"azure-work-item"},
	"priority":      {"azure-work-item"},
	"fields":        {"azure-work-item"},
}

// itemKeys lists the `item` keys an entry sets, in the order the reference documents them.
func itemKeys(it saga.IssueItem) []string {
	var out []string
	for _, k := range []struct {
		name string
		set  bool
	}{
		{"labels", len(it.Labels) > 0},
		{"assignees", len(it.Assignees) > 0},
		{"milestone", it.Milestone != ""},
		{"type", it.Type != ""},
		{"confidential", it.Confidential != nil},
		{"tags", len(it.Tags) > 0},
		{"assignedTo", it.AssignedTo != ""},
		{"areaPath", it.AreaPath != ""},
		{"iterationPath", it.IterationPath != ""},
		{"priority", it.Priority != nil},
		{"fields", len(it.Fields) > 0},
	} {
		if k.set {
			out = append(out, k.name)
		}
	}
	return out
}
