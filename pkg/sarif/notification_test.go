package sarif

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func marshalNotifications(t *testing.T, r Report, ns ...Notification) []byte {
	t.Helper()
	out, err := r.MarshalSARIFWith(MarshalOptions{Notifications: ns})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A notification is not a finding, and reading a file back leaves the report it would have left
// without one.
func TestNotificationsAreNotReadBack(t *testing.T) {
	report := Report{Tool: "Draugr", Results: []Result{{RuleID: "R1", Level: LevelError, Message: "m", Tool: "t"}}}
	plain, err := report.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	withNotes := marshalNotifications(t, report, Notification{
		Kind: "unread-files", Level: LevelError, Message: "go.mod: no packages read",
		Locations: []NotificationLocation{{URI: "go.mod", Repository: "."}},
	})
	if string(plain) == string(withNotes) {
		t.Fatal("the notification was not written")
	}
	want, err := FromSARIF(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := FromSARIF(withNotes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reading notifications back changed the report:\n got %+v\nwant %+v", got, want)
	}
}

// FromSARIF reads every scanner's file, so an invocations member it has no use for cannot fail one,
// whatever its shape.
func TestAForeignInvocationCannotFailAFile(t *testing.T) {
	for _, invocations := range []string{
		`"not an array"`,
		`[{"executionSuccessful":"yes","toolExecutionNotifications":{"level":3}}]`,
		`[{"toolExecutionNotifications":[{"locations":"nowhere","properties":{"kind":1,"repository":[]}}]}]`,
		`null`,
	} {
		doc := fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"invocations":%s,
			"results":[{"ruleId":"R1","message":{"text":"m"}}]}]}`, invocations)
		rep, err := FromSARIF([]byte(doc))
		if err != nil {
			t.Errorf("invocations %s failed the file: %v", invocations, err)
			continue
		}
		if len(rep.Results) != 1 {
			t.Errorf("invocations %s: got %d results, want 1", invocations, len(rep.Results))
		}
	}
}

// No notifications writes no invocations, so the file of a clean run has nothing new in it.
func TestNoNotificationsWriteNoInvocations(t *testing.T) {
	if out := marshalNotifications(t, Report{}); strings.Contains(string(out), "invocations") {
		t.Errorf("wrote invocations for no notifications:\n%s", out)
	}
}

func TestExecutionSuccessfulFollowsTheLevels(t *testing.T) {
	for _, tc := range []struct {
		levels []Level
		want   string
	}{
		{[]Level{LevelWarning}, `"executionSuccessful": true`},
		{[]Level{LevelWarning, LevelError}, `"executionSuccessful": false`},
	} {
		var ns []Notification
		for _, l := range tc.levels {
			ns = append(ns, Notification{Kind: "k", Level: l, Message: "m"})
		}
		if out := marshalNotifications(t, Report{}, ns...); !strings.Contains(string(out), tc.want) {
			t.Errorf("levels %v: want %s in\n%s", tc.levels, tc.want, out)
		}
	}
}

// Locations are unique, as SARIF requires, capped, and valid URI references; only a relative path is
// joined to the run's base, and only then is the base declared.
func TestNotificationLocations(t *testing.T) {
	var in []NotificationLocation
	for i := range maxNotificationLocations + 2 {
		in = append(in, NotificationLocation{URI: fmt.Sprintf("f%02d", i), Repository: "."})
	}
	in = append([]NotificationLocation{{URI: "f00", Repository: "."}, {}}, in...)
	out, left, relative := notificationLocations(in)
	if len(out) != maxNotificationLocations || left != 2 || !relative {
		t.Errorf("got %d locations, %d left out, relative %v", len(out), left, relative)
	}

	// The same path in two repositories is two places.
	out, _, _ = notificationLocations([]NotificationLocation{{URI: "go.mod", Repository: "a"}, {URI: "go.mod", Repository: "b"}})
	if len(out) != 2 {
		t.Errorf("got %d locations for one path in two repositories, want 2", len(out))
	}

	for _, tc := range []struct {
		in, uri, base string
		relative      bool
	}{
		{"a b/c#d.json", "a%20b/c%23d.json", uriBaseID, true},
		{".", ".", uriBaseID, true},
		{"/work/a b.sarif", "/work/a%20b.sarif", "", false},
		{"registry.example.com/app@sha256:aaaa", "registry.example.com/app@sha256:aaaa", "", false},
	} {
		out, _, relative := notificationLocations([]NotificationLocation{{URI: tc.in}})
		art := out[0].PhysicalLocation.ArtifactLocation
		if art.URI != tc.uri || art.URIBaseID != tc.base || relative != tc.relative {
			t.Errorf("%q: got %+v relative %v, want %q base %q relative %v", tc.in, art, relative, tc.uri, tc.base, tc.relative)
		}
		if out[0].Properties != nil {
			t.Errorf("%q: a location with no repository wrote a property bag", tc.in)
		}
	}
}

func TestANotificationAbsolutePathDeclaresNoBase(t *testing.T) {
	out := marshalNotifications(t, Report{}, Notification{Kind: "k", Level: LevelWarning, Message: "m",
		Locations: []NotificationLocation{{URI: "/work/review.sarif"}}})
	if strings.Contains(string(out), "originalUriBaseIds") {
		t.Errorf("declared a base no location uses:\n%s", out)
	}
}

// A long reason is clamped as a rule description is.
func TestANotificationMessageIsClamped(t *testing.T) {
	out := marshalNotifications(t, Report{}, Notification{Kind: "k", Level: LevelError, Message: strings.Repeat("x", descriptionLimit+50)})
	var doc struct {
		Runs []struct {
			Invocations []struct {
				ToolExecutionNotifications []struct {
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	text := doc.Runs[0].Invocations[0].ToolExecutionNotifications[0].Message.Text
	if len(text) > descriptionLimit || !strings.HasSuffix(text, "…") {
		t.Errorf("got %d bytes ending %q", len(text), text[len(text)-5:])
	}
}
