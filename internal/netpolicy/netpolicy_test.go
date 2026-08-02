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
		// Not a recognised boolean. Someone who wrote this meant it, and the safe reading of
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
	err := Refuse("draugr tools install", "https://example.test/tool.tar.gz")
	msg := err.Error()
	// The message has to name what would have been fetched. "Offline" alone leaves the reader
	// to work out which of several network calls they just prevented.
	for _, want := range []string{"draugr tools install", EnvVar, "https://example.test/tool.tar.gz"} {
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
