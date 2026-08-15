package plugin

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestWaitRecorderSumsPerTool: waits happen in concurrent jobs, so the recorder is written from
// several at once and its whole purpose is the total.
func TestWaitRecorderSumsPerTool(t *testing.T) {
	r := &WaitRecorder{}
	ctx := WithWaitRecorder(t.Context(), r)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RecordWait(ctx, "trivy", 100*time.Millisecond)
			RecordWait(ctx, "grype", 50*time.Millisecond)
		}()
	}
	wg.Wait()

	got := r.Totals()
	if got["trivy"] != time.Second {
		t.Errorf("trivy = %v, want 1s", got["trivy"])
	}
	if got["grype"] != 500*time.Millisecond {
		t.Errorf("grype = %v, want 500ms", got["grype"])
	}
}

// TestRecordWaitWithoutARecorderIsSafe: a scanner run outside a run, or from a test, must not
// have to install one — and losing the measurement is not a reason to behave differently.
func TestRecordWaitWithoutARecorderIsSafe(*testing.T) {
	RecordWait(context.Background(), "trivy", time.Second) // must not panic
}

func TestWaitRecorderTotalsIsACopy(t *testing.T) {
	r := &WaitRecorder{}
	RecordWait(WithWaitRecorder(t.Context(), r), "trivy", time.Second)

	got := r.Totals()
	got["trivy"] = 0
	if again := r.Totals(); again["trivy"] != time.Second {
		t.Errorf("the caller mutated the recorder through its copy: %v", again["trivy"])
	}
	if (&WaitRecorder{}).Totals() != nil {
		t.Error("an empty recorder should report nothing, not an empty map to check")
	}
}
