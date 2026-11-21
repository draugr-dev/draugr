package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// killedScanner fails each job as a scanner does whose tool the kernel killed, or with another
// error where err is set.
type killedScanner struct{ err error }

func (killedScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "fake", Version: "1"} }

func (s killedScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	if s.err != nil {
		return sarif.Report{}, s.err
	}
	return sarif.Report{}, fmt.Errorf("run fake: %w", toolexec.ErrKilled)
}

// failuresOf runs two components' jobs under ctx with s and returns what the run recorded of their
// failures: the control's errors and each failed scan's detail.
func failuresOf(ctx context.Context, t *testing.T, s plugin.Scanner) []string {
	t.Helper()
	reg := NewRegistry()
	reg.RegisterController(boundController{scanner: "fake"})
	reg.RegisterScanner(s)
	run, err := New(reg, WithConcurrency(2)).Run(ctx, boundModel())
	if err == nil {
		t.Fatal("a run whose every job failed returned no error")
	}
	got := append([]string{}, run.ScanErrors["bound"]...)
	for _, f := range run.FailedScans {
		got = append(got, f.Detail)
	}
	if len(run.FailedScans) != 2 {
		t.Fatalf("failed scans = %+v, want one per component", run.FailedScans)
	}
	return got
}

// A tool killed in a run that gave each tool the whole machine says how to rerun under the limit,
// in every place the failure is read, and is still a kill to errors.Is. A run already under the
// limit, and a failure that was no kill, are told nothing about it.
func TestAKilledToolNamesTheLimitWhereTheRunHadNone(t *testing.T) {
	for _, detail := range failuresOf(context.Background(), t, killedScanner{}) {
		if !strings.HasSuffix(detail, "run fake: was killed. "+limitAdvice) {
			t.Errorf("a killed tool's failure %q does not end with the limit's advice", detail)
		}
		// A report shows a failure's last clause as its reason, so the advice stays in the clause
		// that says the tool was killed.
		if last := detail[strings.LastIndex(detail, ": ")+2:]; !strings.HasPrefix(last, "was killed. ") {
			t.Errorf("the last clause of %q is %q, want the kill and its advice", detail, last)
		}
	}
	for _, detail := range failuresOf(toolexec.WithThreadLimit(context.Background()), t, killedScanner{}) {
		if strings.Contains(detail, "--limit-tool-threads") {
			t.Errorf("a run already under the limit was told to rerun under it: %q", detail)
		}
	}
	for _, detail := range failuresOf(context.Background(), t, killedScanner{err: errors.New("run fake: exit status 2")}) {
		if strings.Contains(detail, "--limit-tool-threads") {
			t.Errorf("a failure that was no kill was told to rerun under the limit: %q", detail)
		}
	}
	err := adviseOnKill(context.Background(), fmt.Errorf("run fake: %w", toolexec.ErrKilled))
	if !errors.Is(err, toolexec.ErrKilled) {
		t.Errorf("the advised failure %v is no longer ErrKilled", err)
	}
}
