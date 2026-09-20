package scanpolicy

import (
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/exploit"
)

// OverrulesUnreachable declares, for every signal that can raise a band, whether it stands against
// a verdict that nothing in this codebase can reach the flaw.
//
// A table rather than a switch, because this is the question a new signal is most likely to be
// added without answering. Ranking pipes compose, and the composition is where the surprises are:
// a signal written in isolation behaves correctly on its own and quietly discards somebody else's
// evidence the first time both fire on one finding.
//
// `TestEverySignalDeclaresHowItComposes` reads the signal constants out of the packages that define
// them and fails on any that is missing here, so adding one is a decision somebody has to write
// down rather than a default they inherit.
//
// # How to decide the answer for a new signal
//
// An unreachable verdict is an *absence* claim: analysis found no route today, on one revision, and
// reflection, dynamic dispatch and code generation all defeat a call graph. So the question is not
// "is my signal important". It is **does my signal say this flaw is dangerous now, in a way that
// survives nobody being able to reach it?**
//
//   - Yes for exploitation, observed or predicted: the route appears the day somebody writes the
//     call, and a wrong absence claim costs most where the flaw is one people are already using.
//   - Yes for a malicious package: a hostile dependency in the tree is a problem whichever of its
//     functions anybody calls.
//   - No for deprecation: it says who is maintaining the package, which is an argument for
//     replacing it rather than evidence that this flaw can fire here.
var OverrulesUnreachable = map[string]bool{
	exploit.SignalKEV:          true,
	exploit.SignalEPSS:         true,
	dephealth.SignalMalicious:  true,
	dephealth.SignalDeprecated: false,
}
