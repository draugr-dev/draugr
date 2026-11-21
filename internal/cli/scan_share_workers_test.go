package cli

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/config"
)

// --share-workers is off unless typed, and a run that types it gives its tools a context asking
// them to hold their own worker pools to their job's share.
func TestShareWorkersIsOptIn(t *testing.T) {
	f := newScanCommand().Flags().Lookup("share-workers")
	if f == nil {
		t.Fatal("draugr scan has no --share-workers")
	}
	if f.DefValue != "false" {
		t.Errorf("--share-workers defaults to %s, want false", f.DefValue)
	}
	if toolexec.SharesWorkers((&scanOptions{}).toolLimits(context.Background())) {
		t.Error("a run without --share-workers asked its tools to share worker pools")
	}
	if !toolexec.SharesWorkers((&scanOptions{shareWorkers: true}).toolLimits(context.Background())) {
		t.Error("a run with --share-workers did not ask its tools to share worker pools")
	}
}

// --limit-tool-threads is off unless typed, so each tool sizes itself to the machine; typed, it
// reaches toolexec, and --share-workers implies it without asking the pools of a run that typed
// only the limit to share.
func TestLimitToolThreadsIsOptIn(t *testing.T) {
	f := newScanCommand().Flags().Lookup("limit-tool-threads")
	if f == nil {
		t.Fatal("draugr scan has no --limit-tool-threads")
	}
	if f.DefValue != "false" {
		t.Errorf("--limit-tool-threads defaults to %s, want false", f.DefValue)
	}
	ctx := context.Background()
	if toolexec.LimitsThreads((&scanOptions{}).toolLimits(ctx)) {
		t.Error("a run without --limit-tool-threads limited its tools' threads")
	}
	limited := (&scanOptions{limitToolThreads: true}).toolLimits(ctx)
	if !toolexec.LimitsThreads(limited) {
		t.Error("a run with --limit-tool-threads did not limit its tools' threads")
	}
	if toolexec.SharesWorkers(limited) {
		t.Error("--limit-tool-threads alone asked the tools to share worker pools")
	}
	if !toolexec.LimitsThreads((&scanOptions{shareWorkers: true}).toolLimits(ctx)) {
		t.Error("a run with --share-workers did not limit its tools' threads")
	}
}

// scan.limitToolThreads turns the limit on where the flag was not typed, and a typed flag wins
// whatever its value, so --limit-tool-threads=false runs without the limit a file turned on.
func TestScanLimitToolThreadsReachesToolexec(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name  string
		typed map[string]bool
		flag  bool
		file  *bool
		want  bool
	}{
		{"neither", nil, false, nil, false},
		{"the file turns it on", nil, false, &on, true},
		{"the file turns it off", nil, false, &off, false},
		{"the typed flag turns it on", map[string]bool{"limit-tool-threads": true}, true, nil, true},
		{"a typed false wins over the file", map[string]bool{"limit-tool-threads": true}, false, &on, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := scanOptions{setFlags: tc.typed, limitToolThreads: tc.flag}
			scanSettingsFrom(&opts, config.ScanSettings{LimitToolThreads: tc.file})
			if got := toolexec.LimitsThreads(opts.toolLimits(context.Background())); got != tc.want {
				t.Errorf("the tools' context limits threads = %v, want %v", got, tc.want)
			}
		})
	}
}
