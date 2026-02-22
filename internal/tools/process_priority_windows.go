//go:build windows

package tools

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func applyBackgroundPriority(cmd *exec.Cmd, binary string) {
	if cmd == nil || !shouldLowerProcessPriority(binary) {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Best-effort: reduce scanner process scheduling pressure on interactive UI.
	cmd.SysProcAttr.CreationFlags |= windows.BELOW_NORMAL_PRIORITY_CLASS
}

func adjustStartedProcessPriority(_ *exec.Cmd, _ string) {}
