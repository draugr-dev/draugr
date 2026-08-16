// Package surfaces maps what a descriptor declares to the controls that look at it.
//
// It exists so the question "what did this scan not look at?" has one answer regardless of who
// asks. The console prints it as a note after a scan; the MCP server returns it beside the
// verdict. Those two answers diverging would be worse than either being absent, because a reader
// comparing them has no way to tell which is stale.
package surfaces

import (
	"fmt"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// Controls names, for each surface a component can declare, the controls that examine it.
//
// Discovery's promise is that the descriptor writes itself, and a descriptor enabling no control
// has not written itself — it has written a shape, whose first scan reports PASS having checked
// nothing. This map is what turns a declared surface into the controls that would look at it.
//
// `dast` is deliberately absent from the host list. The passive host controls read a response;
// dast sends attack traffic at a live service, and turning that on because something noticed the
// service exists is not a decision Draugr gets to make on someone's behalf. Enable it yourself,
// having decided.
var Controls = map[string][]string{
	"repositories":   {"sca", "secrets", "sast", "iac"},
	"images":         {"images"},
	"hosts":          {"headers", "tls"},
	"infrastructure": {"infrastructure"},
}

// ComponentHas reports whether a component declares the given surface.
func ComponentHas(c *saga.Component, surface string) bool {
	switch surface {
	case "repositories":
		return len(c.Repositories) > 0
	case "images":
		return len(c.Images) > 0
	case "hosts":
		return len(c.Hosts) > 0
	case "infrastructure":
		return len(c.Infrastructure) > 0
	}
	return false
}

// Uncovered names each component surface that no enabled control looks at.
//
// A descriptor that declares a `hosts:` entry with the host controls off scans everything about
// that component except the thing it exposes to the internet, and says nothing. The run is a
// clean pass over a surface nobody looked at — the same shape as a scan that enables no control
// at all, which fails loudly, but with a smaller blast radius and no signal whatsoever.
//
// Advisory rather than fatal: the choice may be deliberate, and refusing to scan because a
// control is off would be worse than the gap.
func Uncovered(model *saga.Model) []string {
	var out []string
	for i := range model.Components {
		c := &model.Components[i]
		for _, surface := range sortedKeys(Controls) {
			if !ComponentHas(c, surface) {
				continue
			}
			var off []string
			for _, name := range Controls[surface] {
				if !c.ControllerEnabled(name, model.Config) {
					off = append(off, name)
				}
			}
			// Partial cover is still cover: one enabled control means someone is looking.
			if len(off) == len(Controls[surface]) {
				out = append(out, fmt.Sprintf("%s declares %s, and %s %s not enabled",
					c.Name, surface, strings.Join(off, ", "), plural2(len(off), "is", "are")))
			}
		}
	}
	return out
}

// DeclaresHosts reports whether any component exposes a host, which is the only case where the
// absence of `dast` from an uncovered-surface list is a question a reader would ask.
func DeclaresHosts(model *saga.Model) bool {
	for i := range model.Components {
		if len(model.Components[i].Hosts) > 0 {
			return true
		}
	}
	return false
}

// plural2 picks between two forms by count.
func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// sortedKeys returns a map's keys in order, so the list is stable between runs.
func sortedKeys[V any](m map[string][]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EnableControls turns on the controls the discovered components can be checked with.
//
// Only controls the descriptor says nothing about are touched. A control someone set — including
// one they set to `enabled: false` — is left exactly as it is, because `--merge` runs against a
// descriptor people edit, and a survey that re-enabled something you had switched off would be a
// worse failure than the one this fixes.
//
// Returns the controls it added, so the command can say what it did rather than changing the
// descriptor silently.
func EnableControls(model *saga.Model) []string {
	wanted := map[string]bool{}
	for i := range model.Components {
		c := &model.Components[i]
		for surface, controls := range Controls {
			if !ComponentHas(c, surface) {
				continue
			}
			for _, name := range controls {
				wanted[name] = true
			}
		}
	}

	var added []string
	for name := range wanted {
		if _, configured := model.Config.Controllers[name]; configured {
			continue
		}
		if model.Config.Controllers == nil {
			model.Config.Controllers = map[string]saga.ControllerSettings{}
		}
		model.Config.Controllers[name] = saga.ControllerSettings{"enabled": true}
		added = append(added, name)
	}
	sort.Strings(added)
	return added
}
