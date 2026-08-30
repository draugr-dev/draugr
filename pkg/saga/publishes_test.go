package saga

import "testing"

// `publishes` is what a consumer's own bill of materials calls this, and `project` is what you
// call it. They are different questions, and a descriptor answering the second twice answers
// neither: an identifier nothing matches is read, understood and applied to nothing, with no
// error on either side.
func TestPublishesHasToBeSomethingThatCanBeLookedUp(t *testing.T) {
	for name, tc := range map[string]struct {
		publishes string
		ok        bool
	}{
		"a package URL":     {"pkg:oci/acme/api", true},
		"an image":          {"registry.example.com/acme/api@sha256:abc", true},
		"a URI":             {"https://acme.example/products/api", true},
		"unset":             {"", true},
		"the project again": {"acme-api", false},
		"a path":            {"acme/api", false},
	} {
		t.Run(name, func(t *testing.T) {
			m := &Model{Project: "acme-api", Publishes: tc.publishes, Release: Release{Version: "2.4.0"}}
			err := m.Validate()
			if tc.ok && err != nil {
				t.Errorf("rejected %q: %v", tc.publishes, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("accepted %q, which nothing can look up", tc.publishes)
			}
		})
	}
}
