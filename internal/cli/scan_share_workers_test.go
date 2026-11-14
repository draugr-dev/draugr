package cli

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
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
	if toolexec.SharesWorkers((&scanOptions{}).workerShare(context.Background())) {
		t.Error("a run without --share-workers asked its tools to share worker pools")
	}
	if !toolexec.SharesWorkers((&scanOptions{shareWorkers: true}).workerShare(context.Background())) {
		t.Error("a run with --share-workers did not ask its tools to share worker pools")
	}
}
