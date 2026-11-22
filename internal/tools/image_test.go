package tools

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// KICS runs from its image, so it is present when the Docker daemon holds the pinned image, and
// the daemon is asked rather than PATH.
func TestDetectAsksTheDaemonForAnImageTool(t *testing.T) {
	t.Parallel()
	kics := Catalog()["kics"]
	if kics.Image != KICSImage || !strings.Contains(kics.Image, "@sha256:") || kics.ImageVersion != KICSVersion {
		t.Fatalf("kics = %+v, want the image pinned by digest", kics)
	}
	onPath := func(name string) (string, error) {
		if name == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("not found")
	}
	var asked []string
	held := func(_ context.Context, argv []string, _ ...string) ([]byte, error) {
		asked = argv
		return []byte("sha256:cdf1\n"), nil
	}
	st := Detect(context.Background(), kics, onPath, held)
	if !st.Found || st.Path != KICSImage || st.Version != KICSVersion || st.Err != nil {
		t.Errorf("with the image held: %+v", st)
	}
	if want := []string{"docker", "image", "inspect", "--format", "{{.Id}}", KICSImage}; !slices.Equal(asked, want) {
		t.Errorf("asked %v, want %v", asked, want)
	}

	missing := func(context.Context, []string, ...string) ([]byte, error) { return nil, errors.New("No such image") }
	if st := Detect(context.Background(), kics, onPath, missing); st.Found || st.Err == nil {
		t.Errorf("with no image: %+v", st)
	}
	noDocker := func(string) (string, error) { return "", errors.New("docker: not found") }
	if st := Detect(context.Background(), kics, noDocker, held); st.Found || st.Err == nil {
		t.Errorf("with no docker: %+v", st)
	}
	if got := PullCommand(kics); got != "docker pull "+KICSImage {
		t.Errorf("pull command = %q", got)
	}
	if !strings.Contains(kics.InstallHint, PullCommand(kics)) {
		t.Errorf("install hint %q does not name the pull command", kics.InstallHint)
	}
	if !kics.Optional || !Catalog()["docker"].Optional {
		t.Error("kics and docker are needed only by an opt-in scanner, so are optional until a descriptor selects it")
	}
	if Provisionable("kics") {
		t.Error("`draugr tools install` claims to provision kics, whose image it does not pull")
	}
}

func TestDetectImageDefaultsToDocker(t *testing.T) {
	t.Parallel()
	tool := Tool{Binary: "x", Image: "example/x@sha256:00", ImageVersion: "1.0"}
	var looked string
	st := Detect(context.Background(), tool,
		func(name string) (string, error) { looked = name; return "/usr/bin/" + name, nil },
		func(context.Context, []string, ...string) ([]byte, error) { return nil, nil })
	if looked != "docker" || !st.Found {
		t.Errorf("looked for %q, status %+v", looked, st)
	}
}
