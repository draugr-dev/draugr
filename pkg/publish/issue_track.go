package publish

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// defaultIssueLabel is the label that finds an issue publisher's items when `label` is unset.
const defaultIssueLabel = "draugr"

// issueKinds names the publishers that keep a tracking item, which are the kinds that read the
// issue fields of PublisherConfig.
var issueKinds = map[string]bool{
	"github-issue":    true,
	"gitlab-issue":    true,
	"azure-work-item": true,
}

// IssueKind reports whether kind keeps a tracking item, and so reads `label`, `branches`,
// `select`, `split`, `minPriority`, `children`, `maxChildren` and `item`.
func IssueKind(kind string) bool { return issueKinds[kind] }

// trackedItem is an open item carrying the tracking label.
type trackedItem struct {
	// Number is what the forge calls the item by in its own references, #12 on GitHub.
	Number int64
	// ID is what the forge links a child to its parent by, which on GitHub and GitLab is not the
	// number. Set on an item create returns.
	ID     int64
	Body   string
	Labels []string
}

// issueTracker is one forge's side of an issue publisher: the requests, in the forge's vocabulary.
// What to open, rewrite and close is decided once, in trackIssues.
type issueTracker interface {
	kind() string
	format() issueFormat
	// budget is the longest body the forge takes, in characters.
	budget() int
	// open lists the open items that carry the tracking label, oldest first.
	open(ctx context.Context) ([]trackedItem, error)
	// create opens an item carrying the tracking label, the configured labels and facts, the
	// labels labelBy keeps, as a child of parent when parent is set.
	create(ctx context.Context, title, body string, facts []string, parent *trackedItem) (trackedItem, error)
	rewrite(ctx context.Context, number int64, body string) error
	retitle(ctx context.Context, number int64, title string) error
	// affords reports whether the run's budget covers this many more writes.
	affords(writes int) bool
	// childWrites is how many writes creating one child takes.
	childWrites() int
	// syncLabels adds back the configured labels an item no longer carries, and makes its fact
	// labels exactly facts.
	syncLabels(ctx context.Context, item trackedItem, facts []string) error
	comment(ctx context.Context, number int64, text string) error
	close(ctx context.Context, number int64, reason closeReason) error
	// ref is how a comment refers to another item.
	ref(number int64) string
}

// closeReason is why an item is closed.
type closeReason int

const (
	closedPassing   closeReason = iota // the part it tracks passes
	closedDuplicate                    // another item tracks the same part
	closedUntracked                    // the run no longer covers the part it tracks
)

// entryOf is the part of a publisher's configuration that decides what its items cover.
func entryOf(cfg saga.PublisherConfig) issueEntry {
	e := issueEntry{MinPriority: cfg.MinPriority, ClosesOn: cfg.Branches, MaxChildren: cfg.ChildLimit()}
	if cfg.Children != saga.ChildrenNone {
		e.Children = cfg.Children
	}
	if cfg.Split != saga.SplitNone {
		e.Split = cfg.Split
	}
	if cfg.Select != nil {
		e.Select = issueSelection{
			Components: cfg.Select.Components,
			Labels:     cfg.Select.Labels,
			Controls:   cfg.Select.Controls,
		}
	}
	return e
}

// issueKey is what makes two issue entries against one destination different entries: the
// selection and the split, which are what their markers are built from.
func issueKey(cfg saga.PublisherConfig) string {
	e := entryOf(cfg)
	return e.Select.key() + " " + e.Split
}

// trackedBranch reports whether a run may change an item, and why not when it may not.
//
// Only a run on a branch the item follows may. A pull request's run is judged on changes nobody
// has merged, so a passing one would close an item the default branch still fails.
func trackedBranch(c *ci.Context, branches []string) (bool, string) {
	switch {
	case c == nil:
		return false, "not a CI run"
	case c.PullRequest:
		return false, "a pull-request run"
	case c.Branch == "":
		return false, "not a branch build"
	}
	if len(branches) > 0 {
		for _, b := range branches {
			if ok, _ := path.Match(b, c.Branch); ok {
				return true, ""
			}
		}
		return false, fmt.Sprintf("branch %s is not in branches", c.Branch)
	}
	if c.DefaultBranch == "" {
		return false, "the default branch is unknown; name the branches that change an item in branches"
	}
	if c.Branch != c.DefaultBranch {
		return false, fmt.Sprintf("branch %s is not the default branch, %s", c.Branch, c.DefaultBranch)
	}
	return true, ""
}

// trackIssues brings one entry's open items in line with the run: an item for every failing part,
// none for a passing one.
//
// Only open items are read. An item closed by hand while its part still fails stays closed, and
// the next failing run opens another.
func trackIssues(ctx context.Context, t issueTracker, data report.Data, cfg saga.PublisherConfig) error {
	if data.Gate.Disabled {
		slog.Info("publisher skipped", "kind", t.kind(), "reason", "the gate is disabled")
		return nil
	}
	if ok, why := trackedBranch(data.CI, cfg.Branches); !ok {
		slog.Info("publisher skipped", "kind", t.kind(), "reason", why)
		return nil
	}
	project := data.ProjectName()
	if project == "" {
		return fmt.Errorf("%s publisher: the descriptor names no project, and every item is keyed on it", t.kind())
	}

	entry := entryOf(cfg)
	s := &tracking{t: t, data: data, cfg: cfg, entry: entry, project: project, scope: scopeKey(data.Requested)}
	items, err := t.open(ctx)
	if err != nil {
		return err
	}
	// A child's marker is its parent's with one field more, so both are filed under the marker of
	// the part they track.
	parents := map[string][]trackedItem{}
	kids := map[string][]trackedItem{}
	for _, it := range items {
		m := markerLine(it.Body)
		if m == "" {
			continue
		}
		if parent, field := splitMarker(m); field != "" {
			kids[parent] = append(kids[parent], it)
		} else {
			parents[m] = append(parents[m], it)
		}
	}

	f := t.format()
	var errs []error
	current := map[string]bool{}
	parts := issueParts(data, entry)
	failing := 0
	for _, part := range parts {
		if part.Fails {
			failing++
		}
	}
	for _, part := range parts {
		marker := issueMarker(project, s.scope, entry, part)
		current[marker] = true
		mine, children := parents[marker], kids[marker]
		var err error
		switch {
		case part.Fails && entry.Children != childrenNone:
			failing--
			// Each parent still to be written may need one write of its own.
			err = s.keepFamily(ctx, part, family{marker: marker, parents: mine, kids: children}, 1+failing)
		case part.Fails:
			failing--
			if err = closeAll(ctx, t, children, closedUntracked, childrenChangedText(f, entry.Children)); err == nil {
				err = keepOpen(ctx, t, mine, issueTitle(project, data.Requested, entry, part),
					newIssueBody(data, s.scope, entry, part).render(f, t.budget()), factLabels(cfg.LabelBy.Facts(), part))
			}
		default:
			text := passedText(f, data, entry, part)
			if err = closeAll(ctx, t, children, closedPassing, text); err == nil {
				err = closeAll(ctx, t, mine, closedPassing, text)
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}

	// A split item whose part has left the run: a control no longer run, or a component no longer
	// declared. Nothing would ever close it otherwise. Its children close first.
	if entry.Split != splitNone {
		prefix := strings.TrimSuffix(issueMarker(project, s.scope, entry, issuePart{}), " -->") + " " + entry.Split + "="
		for _, group := range []map[string][]trackedItem{kids, parents} {
			for _, marker := range sortedKeys(group) {
				if current[marker] || !strings.HasPrefix(marker, prefix) {
					continue
				}
				value := strings.TrimSuffix(strings.TrimPrefix(marker, prefix), " -->")
				text := fmt.Sprintf("The run no longer includes %s %s.", entry.Split, f.code(unescapeMarker(value), false))
				if err := closeAll(ctx, t, group[marker], closedUntracked, text); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// tracking is one entry's run of trackIssues: the forge, the run, and what the entry's markers are
// built from.
type tracking struct {
	t              issueTracker
	data           report.Data
	cfg            saga.PublisherConfig
	entry          issueEntry
	project, scope string
}

// keepOpen leaves one open item holding body and carrying facts: the oldest when there are several,
// a new one when there are none.
func keepOpen(ctx context.Context, t issueTracker, items []trackedItem, title, body string, facts []string) error {
	if len(items) == 0 {
		_, err := t.create(ctx, title, body, facts, nil)
		return err
	}
	keep := items[0]
	if err := closeAll(ctx, t, items[1:], closedDuplicate, "Duplicate of "+t.ref(keep.Number)+"."); err != nil {
		return err
	}
	// The body names the run that last changed it rather than the latest, so an unchanged set of
	// findings sends no write and notifies nobody.
	if bodyChanged(t.format(), keep.Body, body) {
		if err := t.rewrite(ctx, keep.Number, body); err != nil {
			return err
		}
	}
	return t.syncLabels(ctx, keep, facts)
}

// closeAll comments on each item, then closes it. Comments are posted on these transitions and
// never on an ordinary run.
func closeAll(ctx context.Context, t issueTracker, items []trackedItem, reason closeReason, text string) error {
	for _, it := range items {
		if err := t.comment(ctx, it.Number, text); err != nil {
			return err
		}
		if err := t.close(ctx, it.Number, reason); err != nil {
			return err
		}
	}
	return nil
}

// passedText is the comment an item closes with: the gate passed, or nothing at or above the
// entry's minPriority still fails it, on the branch and in the job that found it so.
func passedText(f issueFormat, data report.Data, entry issueEntry, part issuePart) string {
	s := "The gate passes"
	if part.BelowMinimum {
		s = "No finding at or above " + entry.MinPriority + " fails the gate"
	}
	if data.CI != nil {
		s += " on " + f.code(data.CI.Branch, false)
		if job := jobRef(f, data.CI); job != "" {
			s += " in " + job
		}
	}
	return s + "."
}

// jobRef names the CI job, linked when the run recorded where it is, and empty when it recorded
// neither.
func jobRef(f issueFormat, c *ci.Context) string {
	label := "the job"
	if c.RunID != "" {
		label = "job " + c.RunID
	}
	if u := safeURL(c.URL); u != "" {
		return f.link(f.text(label), u)
	}
	if c.RunID != "" {
		return f.text(label)
	}
	return ""
}

// markerLine is the marker an item's body carries, or empty when it carries none.
func markerLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<!-- draugr:issue ") && strings.HasSuffix(line, " -->") {
			return line
		}
	}
	return ""
}

// unescapeMarker reverses markerValue, for a value read back out of a marker.
func unescapeMarker(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var c byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02X", &c); err == nil {
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Untracked lists the declared components that no issue entry's selection covers, in declaration
// order, and nil when the descriptor has no issue entry or every entry covers every component.
//
// A component left out of every selection has findings that fail the gate and open no item, which
// looks the same from the forge as a component with nothing to report.
func Untracked(model *saga.Model) []string {
	var entries []issueEntry
	for _, p := range model.Config.Publishers {
		if IssueKind(p.Kind) {
			entries = append(entries, entryOf(p))
		}
	}
	if len(entries) == 0 {
		return nil
	}
	labels := map[string]map[string]string{}
	for _, c := range model.Components {
		labels[c.Name] = c.Labels
	}
	var out []string
	for _, c := range model.Components {
		covered := false
		for _, e := range entries {
			if e.Select.coversComponent(c.Name, labels) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, c.Name)
		}
	}
	return out
}
