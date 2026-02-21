package tools

import (
	"context"
	"os/exec"
)

// BuildDockerCmdForTest は buildDockerCmd をテストから呼べるようにエクスポートする。
func BuildDockerCmdForTest(ctx context.Context, cfg *DockerConfig, binary string, args []string) *exec.Cmd {
	return buildDockerCmd(ctx, cfg, binary, args)
}

// ResolveDockerForTest は resolveDocker をテストから呼べるようにエクスポートする。
func (r *CommandRunner) ResolveDockerForTest(def *ToolDef) (useDocker bool, dockerAvailable bool) {
	return r.resolveDocker(def)
}

// NeedsProposalForTest は needsProposal をテストから呼べるようにエクスポートする。
func (r *CommandRunner) NeedsProposalForTest(def *ToolDef, useDocker bool, dockerOK bool) bool {
	return r.needsProposal(def, useDocker, dockerOK)
}
