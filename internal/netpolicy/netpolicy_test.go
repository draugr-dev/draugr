package netpolicy

import (
	"errors"
	"strings"
	"testing"
)

func TestOfflineFromEnvironment(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"0":     false,
		"false": false,
		"FALSE": false,
		"no":    false,
		"1":     true,
		"true":  true,
		// Not a recognized boolean. Someone who wrote this meant it, and the safe reading of
		// "I could not understand your request not to use the network" is not to use it.
		"yes":    true,
		"please": true,
	}
	for value, want := range cases {
		t.Setenv(EnvVar, value)
		if got := Offline(); got != want {
			t.Errorf("%s=%q → %v, want %v", EnvVar, value, got, want)
		}
	}
}

func TestOfflineFromFlag(t *testing.T) {
	t.Setenv(EnvVar, "")
	t.Cleanup(func() { SetOffline(false) })

	if Offline() {
		t.Fatal("offline before anything asked for it")
	}
	SetOffline(true)
	if !Offline() {
		t.Error("--offline did not take effect")
	}
	// The environment saying "no" must not undo an explicit flag: the flag is the more specific
	// instruction, and it is the one the operator typed just now.
	t.Setenv(EnvVar, "0")
	if !Offline() {
		t.Error("DRAUGR_OFFLINE=0 overrode --offline")
	}
}

// The configuration answers only when the flag and the environment are silent, and a refusal on
// its account names the file rather than a flag nobody typed.
func TestOfflineFromConfiguration(t *testing.T) {
	t.Setenv(EnvVar, "")
	t.Cleanup(func() { Decide(nil, "") })
	const by = "~/.draugr/config.yaml"
	yes, no := true, false

	Decide(nil, by)
	if !Offline() {
		t.Fatal("offline: true in the configuration did not take effect")
	}
	if got, want := Because(), by+" sets offline: true"; got != want {
		t.Errorf("Because() = %q, want %q", got, want)
	}
	if got := Refuse("tools install", "").Error(); got != "tools install needs the network; "+by+" sets offline: true" {
		t.Errorf("refusal = %q", got)
	}

	// The environment outranks the file, in both directions.
	t.Setenv(EnvVar, "0")
	if Offline() {
		t.Error("DRAUGR_OFFLINE=0 did not outrank the configuration")
	}
	t.Setenv(EnvVar, "1")
	if !Offline() {
		t.Error("DRAUGR_OFFLINE=1 is not offline")
	}
	if got := Because(); got != "--offline or "+EnvVar+" is set" {
		t.Errorf("Because() = %q, want the variable named, which is what is in force", got)
	}

	// The flag as typed outranks both, in both directions.
	Decide(&no, by)
	if Offline() {
		t.Error("--offline=false did not outrank DRAUGR_OFFLINE=1 and the configuration")
	}
	t.Setenv(EnvVar, "")
	Decide(&yes, "")
	if !Offline() {
		t.Error("--offline did not take effect")
	}
	if got := Because(); got != "--offline or "+EnvVar+" is set" {
		t.Errorf("Because() = %q, want the flag named", got)
	}

	// A later Decide replaces what an earlier one recorded.
	Decide(nil, "")
	if Offline() {
		t.Error("offline outlived the Decide that cleared it")
	}
}

func TestSkipUpdateCheck(t *testing.T) {
	t.Cleanup(func() { SetOffline(false) })
	t.Setenv(EnvVar, "")
	t.Setenv(legacyUpdateEnvVar, "")
	if SkipUpdateCheck() {
		t.Error("skipping the update check with nothing set")
	}

	// The narrower request stays sayable on its own: a machine with a network whose owner does
	// not want to be told about releases is not offline.
	t.Setenv(legacyUpdateEnvVar, "1")
	if !SkipUpdateCheck() {
		t.Error("the legacy opt-out stopped working")
	}
	if Offline() {
		t.Error("the legacy opt-out made the whole process offline")
	}

	t.Setenv(legacyUpdateEnvVar, "")
	SetOffline(true)
	if !SkipUpdateCheck() {
		t.Error("offline should imply skipping the update check")
	}
}

func TestRefuse(t *testing.T) {
	err := Refuse("tools install", "https://example.test/tool.tar.gz")
	msg := err.Error()
	// The CLI prints "draugr: " before every error, so the message starts with the command alone.
	if want := "tools install needs the network; --offline or " + EnvVar + " is set"; !strings.HasPrefix(msg, want) {
		t.Errorf("message = %q, want it to start %q", msg, want)
	}
	// The message has to name what would have been fetched. "Offline" alone leaves the reader
	// to work out which of several network calls they just prevented.
	for _, want := range []string{"tools install", EnvVar, "https://example.test/tool.tar.gz"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not mention %q: %s", want, msg)
		}
	}
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Error("the error is not inspectable as a RefusedError")
	}

	if strings.Contains(Refuse("something", "").Error(), "it would have fetched") {
		t.Error("claimed a URL it does not have")
	}
}
