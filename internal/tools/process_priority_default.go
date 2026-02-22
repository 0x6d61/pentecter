//go:build !windows && !linux && !darwin

package tools

import "os/exec"

func applyBackgroundPriority(_ *exec.Cmd, _ string) {}

func adjustStartedProcessPriority(_ *exec.Cmd, _ string) {}
