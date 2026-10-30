// Package netpolicy holds one answer to one question: may this process reach the network?
//
// Draugr reaches out from several places, a release check, a vulnerability database, a template
// set, the exploitability feeds, tool downloads. Each used to decide for itself, so an
// air-gapped runner met the failures one at a time, each separately explicable and collectively
// a bad first hour. There is now one way to say it, and every caller asks here.
//
// A package-level value rather than something threaded through a context: offline is a property
// of the machine, decided once at startup and read everywhere, and a request-scoped mechanism
// would imply it can vary per request.
package netpolicy

import (
	"os"
	"strconv"
	"sync/atomic"
)

// EnvVar is the environment variable that says this machine has no network.
const EnvVar = "DRAUGR_OFFLINE"

// legacyUpdateEnvVar is the older, doctor-only opt-out. Still honored: it is documented, it is
// in people's CI, and what it asked for is a subset of what offline means.
const legacyUpdateEnvVar = "DRAUGR_NO_UPDATE_CHECK"

// forced is set by the --offline flag. Separate from the environment so a flag can turn offline
// on without the process having to rewrite its own environment.
var forced atomic.Bool

// allowed is --offline=false as typed, which outranks the environment and the configuration.
var allowed atomic.Bool

// configured is the configuration file whose `offline: true` is in force, or "" when none is.
var configured atomic.Pointer[string]

// SetOffline records that the operator asked for offline on the command line.
func SetOffline(v bool) { forced.Store(v) }

// Decide records the command line's and the configuration's answers, once, at startup.
//
// flag is --offline as typed, nil when it was not typed. by names the configuration file whose
// `offline: true` is in force, as a reader would be told it, or "" when no file turns it on. Every
// call replaces what an earlier one recorded.
func Decide(flag *bool, by string) {
	forced.Store(flag != nil && *flag)
	allowed.Store(flag != nil && !*flag)
	configured.Store(&by)
}

// Offline reports whether this process should avoid the network.
//
// The first source that answers decides: --offline as typed, then DRAUGR_OFFLINE, then the
// configuration. DRAUGR_OFFLINE answers whenever it is set to anything: a recognized falsey value
// is no, and anything else is yes. An unparseable value counts as yes: someone who wrote
// DRAUGR_OFFLINE=yes meant yes, and the safe reading of "I could not understand your request not to
// use the network" is not to use the network.
func Offline() bool {
	switch {
	case forced.Load():
		return true
	case allowed.Load():
		return false
	}
	if v := os.Getenv(EnvVar); v != "" {
		return truthy(v)
	}
	return configuredBy() != ""
}

// configuredBy is the file Decide recorded, or "".
func configuredBy() string {
	if p := configured.Load(); p != nil {
		return *p
	}
	return ""
}

// Because names what put this process offline, as the end of a sentence about something it
// declined to do: "--offline or DRAUGR_OFFLINE is set", or the configuration file that sets it.
func Because() string {
	if by := configuredBy(); by != "" && !forced.Load() && os.Getenv(EnvVar) == "" {
		return by + " sets offline: true"
	}
	return "--offline or " + EnvVar + " is set"
}

// SkipUpdateCheck reports whether the check for a newer Draugr release should be skipped.
//
// Offline implies it, and the older DRAUGR_NO_UPDATE_CHECK still asks for it on its own. The
// narrower request remains sayable for someone who has a network and simply does not want to be
// told about releases.
func SkipUpdateCheck() bool {
	return Offline() || os.Getenv(legacyUpdateEnvVar) != ""
}

// truthy reads an environment flag. Empty is false; "0", "false" and "no" are false; anything
// else is true.
func truthy(v string) bool {
	switch v {
	case "":
		return false
	case "no", "No", "NO":
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return true
}

// Refuse returns the error a command should return when it needs the network and has been told
// there is none.
//
// Names what would have been fetched, because "offline" on its own leaves the reader to work out
// which of Draugr's several network calls they just prevented.
func Refuse(action, url string) error {
	return &RefusedError{Action: action, URL: url, Because: Because()}
}

// RefusedError reports that an operation needing the network was declined.
type RefusedError struct {
	// Action is what was being attempted, in the user's terms: a command without the leading
	// "draugr", which the CLI already prints before every error, or a phrase such as "the threats
	// control".
	Action string
	// URL is what would have been fetched. Empty when there is no single one.
	URL string
	// Because is what put the process offline, as Because words it.
	Because string
}

func (e *RefusedError) Error() string {
	msg := e.Action + " needs the network; " + e.Because
	if e.URL != "" {
		msg += "\n\nit would have fetched " + e.URL
	}
	return msg
}
