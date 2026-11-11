//go:build !windows

package toolexec

import (
	"os/exec"
	"syscall"
)

// inOwnGroup starts the tool as the leader of a process group of its own, and makes canceling it
// end the whole group.
//
// Go's cancellation kills the process it started and nothing else. A tool that starts processes
// of its own, Semgrep's analysis workers, the go list and compile processes under gosec and
// govulncheck, kubectl under kube-bench, leaves them running after a canceled scan, holding memory
// and CPU and the pipes Draugr is still reading.
func inOwnGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The negative pid names the group, which the tool leads since Setpgid.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
