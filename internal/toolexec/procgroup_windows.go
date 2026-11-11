//go:build windows

package toolexec

import "os/exec"

// inOwnGroup leaves Go's cancellation as it is on Windows, which kills the tool's own process: a
// process group there is a job object, which nothing in Draugr's tool contract needs yet. WaitDelay
// still bounds how long a canceled run waits on processes the tool started.
func inOwnGroup(*exec.Cmd) {}
