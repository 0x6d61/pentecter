package tools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// resolveBinary は exec_utils.go で定義されている。

// CommandRunner は Brain が生成したコマンド文字列を実行する。
//
// 実行方式の決定:
//   - Docker 設定あり + Docker 利用可 → docker run（自動承認）
//   - Docker 設定あり + Docker 不可 + Fallback: true → ホスト直接実行（要承認）
//   - Docker 設定なし → ホスト直接実行（要承認）
//   - proposal_required 明示指定 → その値に従う
type CommandRunner struct {
	registry    *Registry
	blacklist   *Blacklist
	store       *LogStore
	autoApprove bool // グローバル自動承認（true: 未登録ツールも自動実行）
}

// NewCommandRunner は CommandRunner を構築する。
func NewCommandRunner(registry *Registry, blacklist *Blacklist, store *LogStore) *CommandRunner {
	return &CommandRunner{
		registry:  registry,
		blacklist: blacklist,
		store:     store,
	}
}

// Run はコマンドを実行する。
//
// 戻り値:
//   - needsProposal: true なら Brain は propose アクションを使うべきで、呼び出し元は
//     ユーザー承認を得てから再度 ForceRun を呼ぶ。
//   - lines: 生出力のストリーム（needsProposal=true なら nil）
//   - result: 実行完了通知（needsProposal=true なら nil）
//   - err: ブラックリスト検出 or 引数エラー
func (r *CommandRunner) Run(ctx context.Context, command string) (needsProposal bool, lines <-chan OutputLine, result <-chan *ToolResult, err error) {
	// ブラックリスト確認（ホスト実行のみ。Docker はチェックしない）
	binary, args := ParseCommand(command)
	if binary == "" {
		return false, nil, nil, errors.New("empty command")
	}

	def, _ := r.registry.Get(binary)

	useDocker, dockerOK := r.resolveDocker(def)

	// Docker ではない → ブラックリスト確認
	if !useDocker && r.blacklist.Match(command) {
		return false, nil, nil, fmt.Errorf("blacklist: command blocked — %q", command)
	}

	// 承認が必要かを判定
	if r.needsProposal(def, useDocker, dockerOK) {
		return true, nil, nil, nil
	}

	// 実行
	l, res := r.execute(ctx, command, binary, args, def, useDocker)
	return false, l, res, nil
}

// ForceRun はユーザーが承認した後に強制実行する（proposal フロー用）。
// ブラックリストチェックは行わない（ユーザーが明示承認済みのため）。
func (r *CommandRunner) ForceRun(ctx context.Context, command string) (<-chan OutputLine, <-chan *ToolResult) {
	binary, args := ParseCommand(command)
	def, _ := r.registry.Get(binary)
	_, useDocker := r.resolveDocker(def)
	return r.execute(ctx, command, binary, args, def, useDocker)
}

// resolveDocker は Docker を使うべきか、Docker が利用可能かを返す。
func (r *CommandRunner) resolveDocker(def *ToolDef) (useDocker bool, dockerAvailable bool) {
	if def == nil || def.Docker == nil {
		return false, false
	}
	avail := isDockerAvailable()
	if avail {
		return true, true
	}
	// Docker 不可でも Fallback: true ならホスト実行
	return false, false
}

// SetAutoApprove はグローバル自動承認を切り替える。
// true にすると、proposal_required: true が明示されたツール以外は全て自動実行される。
func (r *CommandRunner) SetAutoApprove(v bool) {
	r.autoApprove = v
}

// AutoApprove は現在のグローバル自動承認設定を返す。
func (r *CommandRunner) AutoApprove() bool {
	return r.autoApprove
}

// needsProposal は承認ゲートが必要かを判定する。
func (r *CommandRunner) needsProposal(def *ToolDef, useDocker bool, _ bool) bool {
	// グローバル auto-approve が ON → 全コマンド無条件で自動実行
	if r.autoApprove {
		return false
	}
	if useDocker {
		// Docker 実行 = サンドボックス = 自動承認
		if def != nil && def.ProposalRequired != nil {
			return *def.ProposalRequired // 明示指定を優先
		}
		return false
	}
	if def != nil {
		return def.IsProposalRequired()
	}
	// ToolDef 未登録 = 未知のコマンド = ホスト実行として要承認
	return true
}

// execute は実際にコマンドを実行してストリームを返す。
func (r *CommandRunner) execute(
	ctx context.Context,
	originalCommand, binary string,
	args []string,
	def *ToolDef,
	useDocker bool,
) (<-chan OutputLine, <-chan *ToolResult) {
	linesCh := make(chan OutputLine, 256)
	resultCh := make(chan *ToolResult, 1)

	go func() {
		defer close(linesCh)
		defer close(resultCh)

		startedAt := time.Now()
		id := MakeID(binary, originalCommand, startedAt)

		timeout := 300
		if def != nil && def.TimeoutSec > 0 {
			timeout = def.TimeoutSec
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()

		var cmd *exec.Cmd
		if useDocker && def != nil && def.Docker != nil {
			cmd = buildDockerCmd(ctx, def.Docker, binary, args)
		} else {
			absPath, err := resolveBinary(binary)
			if err != nil {
				resultCh <- &ToolResult{ID: id, ToolName: binary, StartedAt: startedAt,
					FinishedAt: time.Now(), Err: fmt.Errorf("binary not found: %w", err)}
				return
			}
			cmd = exec.CommandContext(ctx, absPath, args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- absPath は LookPath で検証済み
		}

		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		var rawLines []OutputLine
		collect := func(sc *bufio.Scanner, isErr bool) {
			for sc.Scan() {
				line := OutputLine{Time: time.Now(), Content: sc.Text(), IsError: isErr}
				rawLines = append(rawLines, line)
				select {
				case linesCh <- line:
				case <-ctx.Done():
					return
				}
			}
		}

		exitCode := 0
		var runErr error

		if err := cmd.Start(); err != nil {
			runErr = err
		} else {
			done := make(chan struct{}, 2)
			go func() { collect(bufio.NewScanner(stdout), false); done <- struct{}{} }()
			go func() { collect(bufio.NewScanner(stderr), true); done <- struct{}{} }()
			<-done
			<-done
			if err := cmd.Wait(); err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					exitCode = exitErr.ExitCode()
				} else {
					runErr = err
				}
			}
		}

		rawTextLines := make([]string, len(rawLines))
		for i, l := range rawLines {
			rawTextLines[i] = l.Content
		}

		var truncCfg TruncateConfig
		if def != nil {
			truncCfg = def.Output.ToTruncateConfig()
		} else {
			truncCfg = DefaultHeadTailConfig
		}

		truncated := Truncate(rawTextLines, truncCfg)
		entities := ExtractEntities(rawTextLines)

		res := &ToolResult{
			ID:         id,
			ToolName:   binary,
			Args:       args,
			ExitCode:   exitCode,
			RawLines:   rawLines,
			Truncated:  truncated,
			Entities:   entities,
			StartedAt:  startedAt,
			FinishedAt: time.Now(),
			Err:        runErr,
		}
		r.store.Save(res)
		resultCh <- res
	}()

	return linesCh, resultCh
}

// buildDockerCmd は docker run コマンドを構築する。
func buildDockerCmd(ctx context.Context, cfg *DockerConfig, binary string, args []string) *exec.Cmd {
	network := cfg.Network
	if network == "" {
		network = "host"
	}

	dockerArgs := []string{"run", "--rm", "--network=" + network}
	dockerArgs = append(dockerArgs, cfg.RunFlags...)
	dockerArgs = append(dockerArgs, cfg.Image)

	// binary が image の ENTRYPOINT と同名なら省略
	// そうでなければ binary も渡す
	// シンプルに: 常に binary + args を渡す（ENTRYPOINT が binary 以外の場合も対応）
	dockerArgs = append(dockerArgs, binary)
	dockerArgs = append(dockerArgs, args...)

	return exec.CommandContext(ctx, "docker", dockerArgs...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- "docker" は静的な文字列
}

// isDockerAvailable は docker コマンドとデーモンが利用可能かを確認する。
func isDockerAvailable() bool {
	path, err := exec.LookPath("docker")
	if err != nil || path == "" {
		return false
	}
	// docker info で daemon の疎通確認
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, "docker", "info").Run()
	return err == nil
}

// ParseCommand はコマンド文字列を binary と args に分割する。
// Brain が生成するコマンドはシェルクォートを含まない前提。
func ParseCommand(command string) (binary string, args []string) {
	parts := strings.Fields(strings.TrimSpace(command))
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}
