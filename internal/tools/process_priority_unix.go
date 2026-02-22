//go:build linux || darwin

package tools

import (
	"os/exec"
	"syscall"
)

func applyBackgroundPriority(_ *exec.Cmd, _ string) {}

func adjustStartedProcessPriority(cmd *exec.Cmd, binary string) {
	if cmd == nil || cmd.Process == nil || !shouldLowerProcessPriority(binary) {
		return
	}
	// Best-effort: keep TUI interaction responsive while heavy tools run.
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, 10)
}
