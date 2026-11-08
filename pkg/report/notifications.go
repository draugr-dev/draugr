package report

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	// scanErrorKind is the notification kind of a scan error, beside the kinds of caveat.
	scanErrorKind = "scan-error"
	// notificationsPerKind is how many notifications of one kind a SARIF file lists. A file that grows
	// without limit is one a platform refuses, and then it says nothing at all.
	notificationsPerKind = 200
)

// notifications is what a SARIF file says about the run itself: each scan error, then each caveat in
// the order the console groups them, at most notificationsPerKind of a kind.
//
// Level error is what SARIF defines as a run that failed, so it goes on what stopped a control and
// on a caveat the gate fails on, and --allow-scan-errors does not lower it: accepting a shortfall
// passes the run and does not make it complete.
func notifications(d Data) []sarif.Notification {
	out := cutToLimit(d, scanErrorNotifications(d))
	cs := caveats(d)
	slices.SortStableFunc(cs, compareGroups)
	ns := make([]sarif.Notification, 0, len(cs))
	for _, c := range cs {
		level := sarif.LevelWarning
		if c.fails(d) {
			level = sarif.LevelError
		}
		message := c.reason()
		if c.what != "" {
			message = c.what + ": " + message
		}
		ns = append(ns, sarif.Notification{
			Kind: string(c.key), Level: level, Message: message,
			Component: c.component, Controls: c.controls, Locations: c.locations,
		})
	}
	return scrubbedNotifications(append(out, cutToLimit(d, ns)...))
}

// urlUserinfo and credentialShaped match what a tool's message can quote that must not reach an
// uploaded file: a URL's userinfo, a bearer token, and a token or password given as a parameter. A scan error quotes
// a tool's own words, such as the clone URL it failed on, and this file goes to whichever platform
// the descriptor publishes to, where report.json stays with the run.
var (
	urlUserinfo      = regexp.MustCompile(`://[^/\s@]+@`)
	credentialShaped = regexp.MustCompile(`(?i)(bearer\s+)[^\s"']+|((?:token|password|passwd|secret)=)[^\s&"']+`)
)

// scrubbedNotifications is ns with anything credentialShaped in what it quotes replaced.
func scrubbedNotifications(ns []sarif.Notification) []sarif.Notification {
	scrub := func(s string) string {
		return credentialShaped.ReplaceAllString(urlUserinfo.ReplaceAllString(s, "://<redacted>@"), "$1$2<redacted>")
	}
	for i := range ns {
		ns[i].Message = scrub(ns[i].Message)
		locations := slices.Clone(ns[i].Locations)
		for j := range locations {
			locations[j].URI = scrub(locations[j].URI)
			locations[j].Repository = scrub(locations[j].Repository)
		}
		ns[i].Locations = locations
	}
	return ns
}

// scanErrorNotifications are the run's scan errors, by control, each distinct message once. Two jobs
// of a control failing on one target record one message twice.
func scanErrorNotifications(d Data) []sarif.Notification {
	var out []sarif.Notification
	for _, control := range slices.Sorted(maps.Keys(d.Run.ScanErrors)) {
		messages := slices.Sorted(slices.Values(d.Run.ScanErrors[control]))
		for _, m := range slices.Compact(messages) {
			out = append(out, sarif.Notification{
				Kind: scanErrorKind, Level: sarif.LevelError, Message: control + ": " + m, Controls: []string{control},
			})
		}
	}
	return out
}

// cutToLimit keeps the first notificationsPerKind of each run of one kind, and closes a kind it cut
// with a notification saying how many it left out and what lists them.
func cutToLimit(d Data, ns []sarif.Notification) []sarif.Notification {
	out := make([]sarif.Notification, 0, len(ns))
	for i := 0; i < len(ns); {
		j := i
		for j < len(ns) && ns[j].Kind == ns[i].Kind {
			j++
		}
		out = append(out, ns[i:min(j, i+notificationsPerKind)]...)
		if left := j - i - notificationsPerKind; left > 0 {
			out = append(out, sarif.Notification{
				Kind: ns[i].Kind, Level: ns[i].Level, LeftOut: left,
				Message: fmt.Sprintf("%s left out of this file · %s lists every one",
					english.Count(left, cutNoun(ns[i].Kind)), listedIn(d, ns[i].Kind)),
			})
		}
		i = j
	}
	return out
}

// cutNoun is what a notification of a kind is called in the line counting the ones left out.
func cutNoun(kind string) string {
	if kind == scanErrorKind {
		return "scan error"
	}
	return kind + " caveat"
}

// listedIn names what holds every notification of a kind.
//
// report.json carries a scan error, a not-measured scanner, an unread file and an unread check on
// every run, and the other two kinds only under failedCaveats, where the gate fails on them. The
// console lists all of them once it is told not to cut them.
func listedIn(d Data, kind string) string {
	k := saga.CaveatKind(kind)
	if (k == saga.CaveatNotChecked || k == saga.CaveatUnboundImports) && !slices.Contains(d.FailOnCaveats, k) {
		return "draugr scan --top 0"
	}
	return "report.json"
}

// SARIFOptions is what every SARIF file of this run carries beyond its findings: which analysis it
// is, the Draugr that wrote it, and what it says about the run itself. One function for the file -o
// writes and the one a publisher renders, so the two cannot say different things about one run.
func (d Data) SARIFOptions() sarif.MarshalOptions {
	return sarif.MarshalOptions{
		AutomationID:  AutomationID(d.ProjectName(), d.Run.Scope),
		ToolVersion:   d.Version,
		Notifications: notifications(d),
	}
}

// marshalOptions is SARIFOptions in the density the report's view asks for.
func (d Data) marshalOptions() sarif.MarshalOptions {
	opts := d.SARIFOptions()
	opts.Compact = d.View == ViewCompact
	return opts
}
