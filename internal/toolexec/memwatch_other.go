//go:build !linux

package toolexec

import "context"

// canWatch says a memory bound is not enforced here: Draugr reads a process group's memory only
// from Linux's /proc.
const canWatch = false

// preferKilled does nothing where the kernel takes no oom_score_adj.
func preferKilled(context.Context, int) {}

// watch is never called where canWatch is false.
func watch(int, uint64) func() bool { return func() bool { return false } }
