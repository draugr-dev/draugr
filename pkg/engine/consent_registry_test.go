package engine_test

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// remedyRoom is where the console has room for a refusal's remedy: the first two of the three lines
// it shows a planning error in, at its 96 columns, after a long job label. The third line is the
// details', and what does not fit there is cut.
const remedyRoom = 2*96 - len("kubernetes/platform/kube-bench-job: ")

// A refusal names what to change before what the effects do, so every built-in scanner's refusal
// shows `config.allowEffects` and the flag whatever its effects say about themselves, for each
// effect alone and for all of them at once.
func TestEveryRefusalShowsItsRemedy(t *testing.T) {
	checked := 0
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		var consent []plugin.Effect
		for _, e := range info.Effects {
			if e.Kind.RequiresConsent() {
				consent = append(consent, e)
			}
		}
		sets := [][]plugin.Effect{}
		for _, e := range consent {
			sets = append(sets, []plugin.Effect{e})
		}
		if len(consent) > 1 {
			sets = append(sets, consent)
		}
		for _, set := range sets {
			info.Effects = set
			err := engine.ConsentFor(info, nil)
			if err == nil {
				t.Fatalf("%s: effects %v were refused nothing", info.Name, set)
			}
			msg := err.Error()
			end := strings.Index(msg, "--allow-effects ")
			if !strings.Contains(msg, "config.allowEffects") || end < 0 {
				t.Errorf("%s: the refusal names no remedy: %s", info.Name, msg)
				continue
			}
			end += len("--allow-effects ") + len(strings.Fields(msg[end+len("--allow-effects "):])[0])
			if end > remedyRoom {
				t.Errorf("%s: the remedy ends at column %d, past the %d the console shows it in: %s",
					info.Name, end, remedyRoom, msg)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no built-in scanner declares an effect that needs consent, so nothing was checked")
	}
}
