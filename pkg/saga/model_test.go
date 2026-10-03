package saga

import (
	"errors"
	"strings"
	"testing"
)

// A descriptor names its project once, at the top level. The accessor is what everything reads,
// and an empty one is a run a platform files under nothing.
func TestProjectName(t *testing.T) {
	for _, c := range []struct{ name, project, want string }{
		{"declared", "payments-api", "payments-api"},
		{"not declared", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := (&Model{Project: c.project}).ProjectName(); got != c.want {
				t.Errorf("ProjectName() = %q, want %q", got, c.want)
			}
		})
	}
}

// A removed field arrives at the decoder as an unknown one, and "unknown field" sends somebody
// hunting for a typo in a line they copied from our own reference. This is the sentence that has
// to survive: what it named, and where the value goes now.
func TestReleaseNameSaysWhereItWent(t *testing.T) {
	_, err := Load([]byte("project: payments\nrelease:\n  name: payments\n  version: \"1.0\"\n"))
	if err == nil {
		t.Fatal("a descriptor still using release.name loaded without a word")
	}
	for _, want := range []string{"release.name was removed", "`project`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not carry %q: %v", want, err)
		}
	}
}

// Who publishes a target is declared in up to three places, and the most specific wins. The rule
// matters because getting it backwards makes a component-wide declaration unsayable: a component
// that is entirely somebody else's software would need the field on every target, and a target
// added later would silently default back to being the reader's own.
func TestWhoPublishesATargetResolvesMostSpecificFirst(t *testing.T) {
	for name, tc := range map[string]struct {
		component, target BuiltBy
		want              BuiltBy
	}{
		"nobody says":                {"", "", BuiltBySelf},
		"the component says":         {BuiltByUpstream, "", BuiltByUpstream},
		"the target says":            {"", BuiltByUpstream, BuiltByUpstream},
		"the target overrides":       {BuiltByUpstream, BuiltBySelf, BuiltBySelf},
		"the target agrees":          {BuiltByUpstream, BuiltByUpstream, BuiltByUpstream},
		"self on the component only": {BuiltBySelf, "", BuiltBySelf},
	} {
		t.Run(name, func(t *testing.T) {
			comp := Component{BuiltBy: tc.component}
			if got := comp.PublishedBy(Repository{BuiltBy: tc.target}); got != tc.want {
				t.Errorf("repository = %q, want %q", got, tc.want)
			}
			// The same rule for both kinds of target, because a reader who learns it once should
			// not find that images answer differently.
			if got := comp.PublishesImage(Image{BuiltBy: tc.target}); got != tc.want {
				t.Errorf("image = %q, want %q", got, tc.want)
			}
		})
	}
}

// A descriptor Draugr writes is indented the way Draugr writes it, so the next edit to one field
// is a one-line diff rather than a whole-file reindent.
func TestMarshalWritesTheIndentDraugrUses(t *testing.T) {
	out, err := Marshal(Model{Project: "p", Release: Release{Version: "1"},
		Components: []Component{{Name: "api", Kubernetes: []ClusterRef{{Cluster: "prod"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\n  - name: api\n    kubernetes:\n      - cluster: prod\n") {
		t.Errorf("not written at a two-space indent:\n%s", out)
	}
	if _, err := Marshal(unmarshalable{}); err == nil {
		t.Error("a value that refuses to marshal was written")
	}
}

// unmarshalable refuses to be written, as a value a descriptor cannot hold does.
type unmarshalable struct{}

func (unmarshalable) MarshalYAML() (any, error) { return nil, errors.New("cannot be written") }
