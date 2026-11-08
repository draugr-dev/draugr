package sarif

import (
	"net/url"
	"strings"
)

// maxNotificationLocations is how many locations one notification lists. A row folding a workspace
// of crates stands for as many files as the workspace holds, and report.json lists each of them.
const maxNotificationLocations = 10

// Notification is a condition a run reports about itself rather than about the code it read: a file
// it did not read, a check it could not evaluate, a scanner that failed.
type Notification struct {
	// Kind is SARIF's descriptor id for the notification, and is repeated in its property bag.
	Kind string
	// Level is LevelError for a condition that leaves the run failed, and otherwise LevelWarning.
	Level Level
	// Message is the condition in one sentence a reader can act on without the rest of the file.
	Message string
	// Component and Controls are what the condition belongs to, where it belongs to any.
	Component string
	Controls  []string
	// Locations are the files or images the condition names.
	Locations []NotificationLocation
	// LeftOut is how many notifications of this kind this one stands for, on the one that closes a
	// kind cut to a limit, and zero on any other.
	LeftOut int
}

// NotificationLocation is one file or image a notification names.
type NotificationLocation struct {
	// URI is a path relative to Repository, an absolute path, or an image reference.
	URI string
	// Repository is the repository a relative path is in, empty where the run did not record one.
	// Two repositories of one component can each hold a package.json, and a path alone does not say
	// which to open.
	Repository string
}

// sarifInvocations is a run's invocations array, written and never read.
//
// FromSARIF reads every scanner's SARIF as well as Draugr's, and a typed field would let one foreign
// member of an unexpected shape fail the whole file. Nothing here reads the array back, so a report
// loaded from a file has the findings it would have without it.
type sarifInvocations []sarifInvocation

// UnmarshalJSON discards the array. See sarifInvocations.
func (*sarifInvocations) UnmarshalJSON([]byte) error { return nil }

// sarifInvocation is SARIF's invocation object, of which Draugr writes one per run.
type sarifInvocation struct {
	// ExecutionSuccessful is false where any notification is at level error: SARIF defines the
	// presence of one as a failed run, whose results a consumer may not assume are complete.
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
}

// sarifNotification is SARIF's notification object.
type sarifNotification struct {
	Descriptor sarifDescriptorID           `json:"descriptor"`
	Level      string                      `json:"level,omitempty"`
	Message    sarifMessage                `json:"message"`
	Locations  []sarifNotificationLocation `json:"locations,omitempty"`
	Properties sarifNotificationProperties `json:"properties"`
}

// sarifDescriptorID is a reportingDescriptorReference holding only an id, which is the form SARIF
// requires of a reference with no descriptor behind it in tool.driver.notifications.
type sarifDescriptorID struct {
	ID string `json:"id"`
}

// sarifNotificationLocation is SARIF's location object with a property bag. It is apart from
// sarifLocation, which FromSARIF reads from other tools' files, so a key in this bag cannot fail one.
type sarifNotificationLocation struct {
	PhysicalLocation sarifPhysical                        `json:"physicalLocation"`
	Properties       *sarifNotificationLocationProperties `json:"properties,omitempty"`
}

type sarifNotificationLocationProperties struct {
	Repository string `json:"repository"`
}

type sarifNotificationProperties struct {
	Kind      string   `json:"kind"`
	Component string   `json:"component,omitempty"`
	Controls  []string `json:"controls,omitempty"`
	// LeftOut is Notification.LeftOut.
	LeftOut int `json:"leftOut,omitempty"`
	// LocationsLeftOut is how many of the notification's locations maxNotificationLocations cut.
	LocationsLeftOut int `json:"locationsLeftOut,omitempty"`
}

// invocationsOf renders notifications as a run's invocations, and reports whether a location in them
// is relative to the run's base. No notifications render as no invocations.
func invocationsOf(notifications []Notification) (sarifInvocations, bool) {
	if len(notifications) == 0 {
		return nil, false
	}
	inv := sarifInvocation{ExecutionSuccessful: true, ToolExecutionNotifications: make([]sarifNotification, 0, len(notifications))}
	relative := false
	for _, n := range notifications {
		if n.Level == LevelError {
			inv.ExecutionSuccessful = false
		}
		locations, left, rel := notificationLocations(n.Locations)
		relative = relative || rel
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{
			Descriptor: sarifDescriptorID{ID: n.Kind},
			Level:      string(n.Level),
			Message:    sarifMessage{Text: clampDescription(n.Message)},
			Locations:  locations,
			Properties: sarifNotificationProperties{
				Kind: n.Kind, Component: n.Component, Controls: n.Controls,
				LeftOut: n.LeftOut, LocationsLeftOut: left,
			},
		})
	}
	return sarifInvocations{inv}, relative
}

// notificationLocations renders locations, each once as SARIF requires, up to
// maxNotificationLocations, and says how many that left out and whether a path it kept needs the
// run's base. A location with no URI names nothing and is passed over.
func notificationLocations(in []NotificationLocation) (out []sarifNotificationLocation, left int, relative bool) {
	seen := make(map[NotificationLocation]bool, len(in))
	for _, l := range in {
		if l.URI == "" || seen[l] {
			continue
		}
		seen[l] = true
		if len(out) == maxNotificationLocations {
			left++
			continue
		}
		art := sarifArtifact{URI: l.URI}
		switch {
		case isRelativeURI(l.URI):
			art.URI, art.URIBaseID = escapedPath(l.URI), uriBaseID
			relative = true
		case strings.HasPrefix(l.URI, "/"):
			art.URI = escapedPath(l.URI)
		}
		loc := sarifNotificationLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: art}}
		if l.Repository != "" {
			loc.Properties = &sarifNotificationLocationProperties{Repository: l.Repository}
		}
		out = append(out, loc)
	}
	return out, left, relative
}

// escapedPath is a file's path as a URI reference. The file names a run could not read are the ones
// nothing has vouched for, and a space or a "#" in one would make the whole document fail a consumer
// validating `format: uri-reference`.
func escapedPath(path string) string {
	return (&url.URL{Path: path}).EscapedPath()
}
