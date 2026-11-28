// Package detect turns on the controls a descriptor's repositories call for, for a descriptor that
// sets config.detect: the ones a scan with no descriptor turns on for the same files.
//
// Every command that acts on a descriptor goes through Apply, so a scan, `draugr doctor` and the
// MCP server's scan agree about what a descriptor turns on. `draugr validate` does not: it checks
// what the file says, and what the file says is `detect: true`.
package detect

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/scaffold"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Repository is one repository detect read, and the components that name it.
type Repository struct {
	// URL is the repository as the descriptor names it.
	URL string
	// Components are the components naming it, in the descriptor's order.
	Components []string
	// Tree is what the repository holds.
	Tree inventory.Tree
}

// Unread is a repository detect did not read: one that is not a directory on this machine.
type Unread struct {
	// URL is the repository as the descriptor names it.
	URL string
	// Components are the components naming it, in the descriptor's order.
	Components []string
}

// UnreadReason is why a repository was not read, in the words the run prints.
//
// A remote repository is fetched by the scan's jobs, which start once the controls are decided, so
// there is no copy of it to read while deciding them. Reading it here would mean a second clone of
// every remote repository on every command that loads the descriptor, doctor included.
const UnreadReason = "not a directory on this machine, so config.detect read none of its files"

// Result is what detect read, and what the descriptor wrote itself before anything was detected.
type Result struct {
	// Read are the local repositories, each once, in the order the descriptor first names them.
	Read []Repository
	// Unread are the repositories detect could not read, each once.
	Unread []Unread
	// Written is the descriptor's own controls and reachability analysis, as it wrote them.
	Written saga.Config
}

// Apply turns on what m's local repositories call for, beneath the controls m writes itself, and
// returns what it read. A model that does not set config.detect is left as it is, with a nil
// Result: a descriptor written without the field runs the controls it names and nothing else.
func Apply(m *saga.Model) (*Result, error) {
	return ApplyWith(m, inventory.Read)
}

// ApplyWith is Apply reading each local repository with read, for a caller that has already read
// the tree and a test that hands one over.
//
// The controls are one set for the whole descriptor, as config.controls is: a scanner one
// repository's files call for runs on every repository, and reads nothing where it has nothing to
// read. Each repository is read whole, whatever paths: and ignore: narrow a component to, because a
// control turned on for the descriptor runs on every component anyway.
func ApplyWith(m *saga.Model, read func(string) inventory.Tree) (*Result, error) {
	if m == nil || !m.Config.Detect {
		return nil, nil
	}
	res := &Result{Written: saga.Config{Controls: m.Config.Controls, Reachability: m.Config.Reachability}}
	read1 := map[string]int{}
	unread := map[string]int{}
	for _, c := range m.Components {
		for _, r := range c.Repositories {
			if i, ok := read1[r.URL]; ok {
				res.Read[i].Components = appendOnce(res.Read[i].Components, c.Name)
				continue
			}
			if i, ok := unread[r.URL]; ok {
				res.Unread[i].Components = appendOnce(res.Unread[i].Components, c.Name)
				continue
			}
			if !git.IsLocalPath(r.URL) {
				unread[r.URL] = len(res.Unread)
				res.Unread = append(res.Unread, Unread{URL: r.URL, Components: []string{c.Name}})
				continue
			}
			read1[r.URL] = len(res.Read)
			res.Read = append(res.Read, Repository{URL: r.URL, Components: []string{c.Name}, Tree: read(r.URL)})
		}
	}
	trees := make([]inventory.Tree, len(res.Read))
	for i, r := range res.Read {
		trees[i] = r.Tree
	}
	detected, err := scaffold.Detected(Merge(trees...))
	if err != nil {
		return nil, fmt.Errorf("config.detect: %w", err)
	}
	m.Config.Controls = Layer(detected.Controls, res.Written.Controls)
	if m.Config.Reachability == nil {
		m.Config.Reachability = detected.Reachability
	}
	return res, nil
}

// Layer lays the controls a descriptor writes over the ones detected: each control the descriptor
// names keeps every setting it writes, `enabled: false` included, and takes the detected settings
// it does not write. A control it does not name stays as detected.
func Layer(detected, written map[string]saga.ControllerSettings) map[string]saga.ControllerSettings {
	if len(detected) == 0 && len(written) == 0 {
		return nil
	}
	out := make(map[string]saga.ControllerSettings, len(detected)+len(written))
	for name, settings := range detected {
		out[name] = settings
	}
	for name, settings := range written {
		out[name] = config.DeepMerge(out[name], settings)
	}
	return out
}

// AsWritten is m with the controls and reachability analysis its descriptor wrote, before detect
// added to them. A scanner a scan of it would run is one the descriptor asked for by name.
func (r *Result) AsWritten(m *saga.Model) *saga.Model {
	written := *m
	written.Config.Controls, written.Config.Reachability = r.Written.Controls, r.Written.Reachability
	return &written
}

// Merge is one tree holding what each of trees holds, for deciding what they call for together.
//
// Every list in a Tree is appended, by reflection rather than by name, so a kind of file the
// inventory learns to find reaches detect without anybody remembering to add it here. The paths stay
// relative to their own repository, which is enough for what is decided from them: whether a kind of
// file is there, and how a requirements file is named.
func Merge(trees ...inventory.Tree) inventory.Tree {
	var out inventory.Tree
	v := reflect.ValueOf(&out).Elem()
	for _, t := range trees {
		tv := reflect.ValueOf(t)
		for i := range v.NumField() {
			if f := v.Field(i); f.Kind() == reflect.Slice {
				f.Set(reflect.AppendSlice(f, tv.Field(i)))
			}
		}
	}
	return out
}

func appendOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}
