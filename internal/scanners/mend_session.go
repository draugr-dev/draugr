package scanners

import (
	"context"
	"sync"
)

// mendUpload is one repository's inventory, sent to Mend once per run however many controls want
// it.
//
// Both Mend scanners need the same upload: `sca` reads the alerts it produces, `licenses` reads
// the inventory. Doing it twice would not merely be slow — a Unified Agent upload *replaces* a
// project's inventory, so a second one can land while the first's results are being read, and the
// findings would then describe a project that no longer matches them.
//
// So the upload belongs to neither control. Whichever scanner needs it first performs it; the
// other waits on the same result. That also makes the awkward configuration work: licenses
// enabled with SCA disabled still gets an upload, because the upload was never the SCA scanner's
// to own.
type mendUpload struct {
	summary uaSummary
	err     error
}

// mendSessions holds one run's uploads, keyed by what makes an upload distinct: the repository it
// came from and the Mend project it went to.
type mendSessions struct {
	mu   sync.Mutex
	done map[string]*mendOnce
}

type mendOnce struct {
	once   sync.Once
	result mendUpload
}

// sharedMendUploads is the per-process session table.
//
// Package-level because the two scanners are constructed independently by the registry and never
// see each other. Keyed tightly enough that a stale entry cannot serve the wrong scan: a
// different repository, revision or project is a different key.
var sharedMendUploads = &mendSessions{done: map[string]*mendOnce{}}

// upload runs fn once per key and returns the same result to every caller.
func (s *mendSessions) upload(ctx context.Context, key string, fn func(context.Context) (uaSummary, error)) (uaSummary, error) {
	s.mu.Lock()
	entry, ok := s.done[key]
	if !ok {
		entry = &mendOnce{}
		s.done[key] = entry
	}
	s.mu.Unlock()

	entry.once.Do(func() {
		summary, err := fn(ctx)
		entry.result = mendUpload{summary: summary, err: err}
	})
	return entry.result.summary, entry.result.err
}

// reset clears the table. Tests only; a run is a process.
func (s *mendSessions) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = map[string]*mendOnce{}
}
