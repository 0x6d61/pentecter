package tools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner はツール定義に基づいて外部コマンドを非同期実行する汎用ランナー。
type Runner struct {
	store *LogStore
}

// NewRunner はRunnerを返す。store に実行結果の生ログが保存される。
func NewRunner(store *LogStore) *Runner {
	return &Runner{store: store}
}

// Run は def で定義されたツールを target に対して非同期実行する。
// 実行中の生出力は lines チャネルにストリームされ、
// 完了時に result チャネルに ToolResult が送信される。
//
// TUI は lines を読みながらログパネルを更新し、
// result を受け取ったらナレッジグラフを更新する。
func (r *Runner) Run(
	ctx context.Context,
	def *ToolDef,
	target string,
	extraArgs []string,
) (lines <-chan OutputLine, result <-chan *ToolResult) {
	linesCh := make(chan OutputLine, 256)
	resultCh := make(chan *ToolResult, 1)

	go func() {
		defer close(linesCh)
		defer close(resultCh)

		res := r.execute(ctx, def, target, extraArgs, linesCh)
		r.store.Save(res)
		resultCh <- res
	}()

	return linesCh, resultCh
}

// resolveBinary は def.Binary を絶対パスに解決して返す。
//
// resolveBinary の目的:
//   1. ツールが PATH に存在するか確認する（UX: 実行前に明確なエラーを出す）
//   2. 相対パス（../../bin/sh など）によるパストラバーサルを防ぐ
//   3. 絶対パスに解決することで、実行中の PATH 差し替えに対して安定させる
//
// スレットモデルの注記:
//   YAML ファイルは開発者が管理する信頼済み設定であり、ユーザー入力ではない。
//   そのため「binary: bash」のような正規バイナリ名の悪用は対象外。
//   exec.CommandContext はシェルを経由しないため args のシェルインジェクションは不可。
//   Semgrep の警告は「変数が静的でない」という構文検出によるもので、
//   このツールでは外部コマンド呼び出しが設計上必須のため nosemgrep で抑制する。
func resolveBinary(name string) (string, error) {
	// パス区切り文字を含む名前は拒否（../../bin/evil など）
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("binary name must not contain path separators: %q", name)
	}
	// 空文字を拒否
	if strings.TrimSpace(name) == "" {
		return "", errors.New("binary name must not be empty")
	}

	absPath, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("binary %q not found in PATH: %w", name, err)
	}

	// LookPath が返すパスは絶対パスのはずだが念のため確認
	if !filepath.IsAbs(absPath) {
		return "", fmt.Errorf("resolved path is not absolute: %q", absPath)
	}

	return absPath, nil
}

// execute はコマンドを実行し生出力を linesCh に送りながら ToolResult を構築する。
func (r *Runner) execute(
	ctx context.Context,
	def *ToolDef,
	target string,
	extraArgs []string,
	linesCh chan<- OutputLine,
) *ToolResult {
	startedAt := time.Now()
	id := MakeID(def.Name, target, startedAt)

	// バイナリを絶対パスに解決（パストラバーサル防止）
	absPath, err := resolveBinary(def.Binary)
	if err != nil {
		return &ToolResult{
			ID: id, ToolName: def.Name, Target: target,
			StartedAt: startedAt, FinishedAt: time.Now(),
			Err: fmt.Errorf("binary resolve failed: %w", err),
		}
	}

	// タイムアウト設定
	timeout := def.TimeoutSec
	if timeout <= 0 {
		timeout = 300
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// 引数: defaultArgs + target + extraArgs
	args := make([]string, 0, len(def.DefaultArgs)+1+len(extraArgs))
	args = append(args, def.DefaultArgs...)
	if target != "" {
		args = append(args, target)
	}
	args = append(args, extraArgs...)

	// セキュリティ根拠:
	//   absPath は resolveBinary() により以下を保証済み:
	//   1. パス区切り文字（/ \）を含まないバイナリ名のみ受け付ける
	//   2. exec.LookPath で PATH 内の実在バイナリに解決された絶対パス
	//   3. 絶対パスであることを検証済み
	//   exec.CommandContext はシェルを経由しないため args のシェルインジェクションも不可。
	//   Semgrep の警告は「変数が静的文字列でない」という構文的検出によるもので、
	//   上記の検証によりリスクは軽減されている。
	cmd := exec.CommandContext(ctx, absPath, args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var rawLines []OutputLine
	collect := func(src *bufio.Scanner, isErr bool) {
		for src.Scan() {
			line := OutputLine{
				Time:    time.Now(),
				Content: src.Text(),
				IsError: isErr,
			}
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

	truncCfg := def.Output.ToTruncateConfig()
	truncated := Truncate(rawTextLines, truncCfg)
	entities := ExtractEntities(rawTextLines)

	if strings.Contains(truncated, "省略") {
		truncated = "# " + def.Name + " on " + target + "\n" + truncated
	}

	return &ToolResult{
		ID:         id,
		ToolName:   def.Name,
		Target:     target,
		Args:       args,
		ExitCode:   exitCode,
		RawLines:   rawLines,
		Truncated:  truncated,
		Entities:   entities,
		StartedAt:  startedAt,
		FinishedAt: time.Now(),
		Err:        runErr,
	}
}
