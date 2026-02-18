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

// YAMLExecutor は ToolDef をもとに外部コマンドを subprocess で実行する Executor。
type YAMLExecutor struct {
	def *ToolDef
}

func (e *YAMLExecutor) ExecutorType() string { return "yaml" }

// Execute は ToolDef の binary を非同期実行し、生出力を lines チャネルにストリームする。
func (e *YAMLExecutor) Execute(ctx context.Context, store *LogStore, args map[string]any) (<-chan OutputLine, <-chan *ToolResult) {
	linesCh := make(chan OutputLine, 256)
	resultCh := make(chan *ToolResult, 1)

	go func() {
		defer close(linesCh)
		defer close(resultCh)
		res := e.run(ctx, store, args, linesCh)
		store.Save(res)
		resultCh <- res
	}()

	return linesCh, resultCh
}

func (e *YAMLExecutor) run(ctx context.Context, _ *LogStore, args map[string]any, linesCh chan<- OutputLine) *ToolResult {
	startedAt := time.Now()
	id := MakeID(e.def.Name, fmt.Sprintf("%v", args), startedAt)

	absPath, err := resolveBinary(e.def.Binary)
	if err != nil {
		return &ToolResult{
			ID: id, ToolName: e.def.Name,
			StartedAt: startedAt, FinishedAt: time.Now(),
			Err: fmt.Errorf("binary resolve: %w", err),
		}
	}

	cliArgs, err := BuildCLIArgs(e.def.ArgsTemplate, args)
	if err != nil {
		return &ToolResult{
			ID: id, ToolName: e.def.Name,
			StartedAt: startedAt, FinishedAt: time.Now(),
			Err: fmt.Errorf("arg build: %w", err),
		}
	}

	timeout := e.def.TimeoutSec
	if timeout <= 0 {
		timeout = 300
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, absPath, cliArgs...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- absPath は LookPath で検証済み
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var rawLines []OutputLine
	collect := func(src *bufio.Scanner, isErr bool) {
		for src.Scan() {
			line := OutputLine{Time: time.Now(), Content: src.Text(), IsError: isErr}
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

	truncCfg := e.def.Output.ToTruncateConfig()
	truncated := Truncate(rawTextLines, truncCfg)
	entities := ExtractEntities(rawTextLines)

	if strings.Contains(truncated, "省略") {
		truncated = "# " + e.def.Name + "\n" + truncated
	}

	return &ToolResult{
		ID:         id,
		ToolName:   e.def.Name,
		Args:       cliArgs,
		ExitCode:   exitCode,
		RawLines:   rawLines,
		Truncated:  truncated,
		Entities:   entities,
		StartedAt:  startedAt,
		FinishedAt: time.Now(),
		Err:        runErr,
	}
}

// --- 既存 runner.go から移植（後方互換のため残す） ---

// resolveBinary は binary 名を絶対パスに解決する。
// パス区切り文字を拒否し、LookPath で PATH 内の実在バイナリのみ許可する。
func resolveBinary(name string) (string, error) {
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("binary name must not contain path separators: %q", name)
	}
	if strings.TrimSpace(name) == "" {
		return "", errors.New("binary name must not be empty")
	}
	absPath, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("binary %q not found in PATH: %w", name, err)
	}
	if !filepath.IsAbs(absPath) {
		return "", fmt.Errorf("resolved path is not absolute: %q", absPath)
	}
	return absPath, nil
}
