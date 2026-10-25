package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	checkout := []debug.BuildSetting{
		{Key: "vcs", Value: "git"},
		{Key: "vcs.revision", Value: "0cfffcfe1a2b3c4d5e6f708192a3b4c5d6e7f809"},
		{Key: "vcs.time", Value: "2026-10-18T21:10:04Z"},
	}
	tests := []struct {
		name                string
		main                string
		settings            []debug.BuildSetting
		version, commit     string
		date                string
		wantV, wantC, wantD string
	}{
		{
			name: "go install of a release tag",
			main: "v0.154.1", version: "dev", commit: "none", date: "unknown",
			wantV: "0.154.1", wantC: "none", wantD: "unknown",
		},
		{
			name: "go install of a pseudo-version names no release",
			main: "v0.154.2-0.20261018211004-0cfffcfe1a2b", version: "dev", commit: "none", date: "unknown",
			wantV: "dev", wantC: "none", wantD: "unknown",
		},
		{
			name: "go build in a checkout",
			main: "(devel)", settings: checkout, version: "dev", commit: "none", date: "unknown",
			wantV: "dev", wantC: "0cfffcfe", wantD: "2026-10-18T21:10:04Z",
		},
		{
			name: "a release binary keeps what the linker stamped",
			main: "v0.154.1", settings: checkout, version: "0.154.1", commit: "abcdef12", date: "2026-10-18T21:23:27Z",
			wantV: "0.154.1", wantC: "abcdef12", wantD: "2026-10-18T21:23:27Z",
		},
		{
			name: "a short revision is kept whole",
			main: "(devel)", settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}},
			version: "dev", commit: "none", date: "unknown",
			wantV: "dev", wantC: "abc", wantD: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &debug.BuildInfo{Main: debug.Module{Version: tt.main}, Settings: tt.settings}
			v, c, d := fromBuildInfo(info, tt.version, tt.commit, tt.date)
			if v != tt.wantV || c != tt.wantC || d != tt.wantD {
				t.Errorf("fromBuildInfo = %q, %q, %q; want %q, %q, %q", v, c, d, tt.wantV, tt.wantC, tt.wantD)
			}
		})
	}
}

func TestStringAndCurrentAgree(t *testing.T) {
	info := Current()
	line := String()
	for _, part := range []string{info.Version, info.Commit, info.Built, info.Go} {
		if !strings.Contains(line, part) {
			t.Errorf("String() = %q, missing %q from Current()", line, part)
		}
	}
}
