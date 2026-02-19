package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

const (
	maxBrainRetries = 3
	// maxConsecutiveFailures は連続失敗でユーザーに方針を聞く閾値。
	maxConsecutiveFailures = 3
)

// commandEntry はコマンド履歴の1エントリを保持する。
type commandEntry struct {
	Command  string
	ExitCode int
	Summary  string // 出力の先頭200文字（切り捨て済み）
	Time     time.Time
}

// Loop は Brain・CommandRunner・TUI を接続するオーケストレーター。
//
// ループの流れ:
//
//	Brain.Think(snapshot) → action
//	action == run     → CommandRunner.Run() → 自動実行 or needsProposal チェック
//	action == propose → TUIにProposalを表示 → ユーザー承認 → CommandRunner.ForceRun()
//	action == memory  → ナレッジグラフに記録
//	action == think   → 思考をTUIログに表示してループ継続
//	action == complete → ループ終了
type Loop struct {
	target       *Target
	br           brain.Brain
	runner       *tools.CommandRunner
	skillsReg    *skills.Registry  // スキルテンプレート（nil = 無効）
	memoryStore  *memory.Store     // 発見物の永続化（nil = 無効）
	mcpMgr       *mcp.MCPManager  // MCP サーバーマネージャー（nil = MCP 無効）
	taskMgr      *TaskManager     // SubTask マネージャー（nil = SubTask 無効）

	// TUI との通信チャネル
	events  chan<- Event  // Agent → TUI
	approve <-chan bool   // TUI → Agent（Proposal 承認/拒否）
	userMsg <-chan string // TUI → Agent（チャット入力）

	lastToolOutput      string
	consecutiveFailures int

	// Brain コンテキスト強化用：コマンド履歴
	lastCommand  string         // 直前に実行したコマンド
	lastExitCode int            // 直前のコマンドの exit code
	history      []commandEntry // 直近の実行履歴（最大10件）

	// ユーザーメッセージ即時処理用
	pendingUserMsg string // post-drain で取得したユーザーメッセージ
	turnCount      int    // 現在のターン番号
}

// NewLoop は Loop を構築する。
func NewLoop(
	target *Target,
	br brain.Brain,
	runner *tools.CommandRunner,
	events chan<- Event,
	approve <-chan bool,
	userMsg <-chan string,
) *Loop {
	return &Loop{
		target:  target,
		br:      br,
		runner:  runner,
		events:  events,
		approve: approve,
		userMsg: userMsg,
	}
}

// WithSkills は Skills レジストリをセットする（メソッドチェーン用）。
func (l *Loop) WithSkills(reg *skills.Registry) *Loop {
	l.skillsReg = reg
	return l
}

// WithMemory は Memory Store をセットする（メソッドチェーン用）。
func (l *Loop) WithMemory(store *memory.Store) *Loop {
	l.memoryStore = store
	return l
}

// WithMCP は MCP マネージャーをセットする（メソッドチェーン用）。
func (l *Loop) WithMCP(mgr *mcp.MCPManager) *Loop {
	l.mcpMgr = mgr
	return l
}
// WithTaskManager は TaskManager をセットする（メソッドチェーン用）。
func (l *Loop) WithTaskManager(tm *TaskManager) *Loop {
	l.taskMgr = tm
	return l
}

// Run はエージェントループを実行する。別 goroutine で呼び出すこと。
func (l *Loop) Run(ctx context.Context) {
	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Agent started: %s", l.target.Host)})
	l.target.Status = StatusScanning

	for {
		select {
		case <-ctx.Done():
			l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "Agent stopped"})
			return
		default:
		}

		var userMsg string
		if l.pendingUserMsg != "" {
			userMsg = l.pendingUserMsg
			l.pendingUserMsg = ""
		} else {
			userMsg = l.drainUserMsg()
		}
		l.turnCount++

		// Check if stalled: consecutive failures reached threshold → pause and ask user
		if l.consecutiveFailures >= maxConsecutiveFailures {
			l.emit(Event{Type: EventStalled,
				Message: fmt.Sprintf("Stalled after %d consecutive failures. Waiting for direction.", l.consecutiveFailures)})
			l.target.Status = StatusPaused

			// Wait for user input before continuing
			userMsg = l.waitForUserMsg(ctx)
			if userMsg == "" {
				return // context cancelled
			}
			l.consecutiveFailures = 0
			l.target.Status = StatusScanning
		}

		l.emit(Event{Type: EventTurnStart, TurnNumber: l.turnCount})
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "Thinking..."})

		var action *schema.Action
		var brainErr error
		for attempt := 1; attempt <= maxBrainRetries; attempt++ {
			action, brainErr = l.br.Think(ctx, brain.Input{
				TargetSnapshot: l.buildSnapshot(),
				ToolOutput:     l.lastToolOutput,
				LastCommand:    l.lastCommand,
				LastExitCode:   l.lastExitCode,
				CommandHistory: l.buildHistory(),
				UserMessage:    userMsg,
				TurnCount:      l.turnCount,
				Memory:         l.buildMemory(),
			})
			if brainErr == nil {
				break
			}
			if attempt < maxBrainRetries {
				l.emit(Event{Type: EventLog, Source: SourceSystem,
					Message: fmt.Sprintf("Brain error: %v — retrying (%d/%d)", brainErr, attempt, maxBrainRetries)})
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(attempt) * time.Second):
				}
			}
		}
		if brainErr != nil {
			l.emit(Event{Type: EventError, Message: fmt.Sprintf("Brain error after %d retries: %v", maxBrainRetries, brainErr)})
			l.target.Status = StatusFailed
			return
		}

		// Post-think drain: Brain.Think() 中に届いたユーザーメッセージを回収
		if msg := l.drainUserMsg(); msg != "" {
			l.pendingUserMsg = msg
		}

		if action.Thought != "" {
			l.emit(Event{Type: EventLog, Source: SourceAI, Message: action.Thought})
		}

		switch action.Action {
		case schema.ActionRun:
			l.runCommand(ctx, action.Command)
			l.evaluateResult()

		case schema.ActionPropose:
			if !l.handlePropose(ctx, action.Command, action.Thought) {
				return
			}

		case schema.ActionMemory:
			l.recordMemory(action.Memory)

		case schema.ActionCallMCP:
			l.callMCP(ctx, action)
			l.evaluateResult()

		case schema.ActionSpawnTask:
			l.handleSpawnTask(ctx, action)

		case schema.ActionWait:
			l.handleWait(ctx, action)

		case schema.ActionCheckTask:
			l.handleCheckTask(action)

		case schema.ActionKillTask:
			l.handleKillTask(action)

		case schema.ActionAddTarget:
			if action.Target != "" {
				l.emit(Event{Type: EventAddTarget, NewHost: action.Target})
				msg := fmt.Sprintf("Lateral movement: adding new target %s", action.Target)
				l.emit(Event{Type: EventLog, Source: SourceAI, Message: msg})
			}

		case schema.ActionThink:
			// 思考のみ

		case schema.ActionComplete:
			l.target.Status = StatusPwned
			l.emit(Event{Type: EventComplete, Message: "Assessment complete — waiting for further instructions (report, cleanup, etc.)"})
			// PWNED 後もユーザー指示を待ち続ける
			userMsg = l.waitForUserMsg(ctx)
			if userMsg == "" {
				return // context cancelled
			}
			l.pendingUserMsg = userMsg
			// メインループの次のイテレーションで処理される

		default:
			l.emit(Event{Type: EventLog, Source: SourceSystem,
				Message: fmt.Sprintf("Unknown action: %q", action.Action)})
		}
	}
}

// runCommand は CommandRunner でコマンドを実行する。
// needsProposal が true のとき Brain が誤って run を使った場合の安全ネット。
func (l *Loop) runCommand(ctx context.Context, command string) {
	if command == "" {
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "run: command is empty"})
		return
	}

	l.lastCommand = command
	l.emit(Event{Type: EventLog, Source: SourceTool, Message: command})
	l.target.Status = StatusRunning

	needsProposal, linesCh, resultCh, err := l.runner.Run(ctx, command)
	if err != nil {
		errMsg := fmt.Sprintf("Execution error: %v", err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.lastToolOutput = "Error: " + err.Error()
		l.target.Status = StatusScanning
		return
	}

	if needsProposal {
		// Brain が run を使ったが要承認ツール → 安全ネットとして propose に格上げ
		l.target.Status = StatusScanning
		l.handlePropose(ctx, command, "Approval required: direct host execution")
		return
	}

	l.streamAndCollect(ctx, linesCh, resultCh)

	// Post-exec drain: コマンド実行中に届いたユーザーメッセージを回収
	if msg := l.drainUserMsg(); msg != "" {
		l.pendingUserMsg = msg
	}
}

// handlePropose は Proposal を TUI に表示し承認を待つ。
func (l *Loop) handlePropose(ctx context.Context, command, description string) bool {
	l.lastCommand = command
	p := &Proposal{
		Description: description,
		Tool:        command,
		Args:        nil,
	}
	l.target.SetProposal(p)
	l.emit(Event{Type: EventProposal, Proposal: p})

	select {
	case approved := <-l.approve:
		l.target.ClearProposal()
		if approved {
			l.target.Status = StatusRunning
			linesCh, resultCh := l.runner.ForceRun(ctx, command)
			l.streamAndCollect(ctx, linesCh, resultCh)
		} else {
			l.lastToolOutput = "User rejected: " + description
			l.target.Status = StatusScanning
		}
		return true
	case <-ctx.Done():
		l.target.ClearProposal()
		return false
	}
}

// recordMemory は Brain の発見物をナレッジグラフに記録する。
func (l *Loop) recordMemory(m *schema.Memory) {
	if m == nil {
		return
	}
	msg := fmt.Sprintf("[%s] %s: %s", m.Type, m.Title, m.Description)
	l.emit(Event{Type: EventLog, Source: SourceAI, Message: "📝 " + msg})

	// Memory Store に永続化
	if l.memoryStore != nil {
		if err := l.memoryStore.Record(l.target.Host, m); err != nil {
			l.emit(Event{Type: EventLog, Source: SourceSystem,
				Message: fmt.Sprintf("Memory write error: %v", err)})
		}
	}
}

// callMCP は MCP サーバーのツールを呼び出す。
func (l *Loop) callMCP(ctx context.Context, action *schema.Action) {
	if l.mcpMgr == nil {
		l.emit(Event{Type: EventLog, Source: SourceSystem,
			Message: "MCP not configured — cannot call MCP tools"})
		l.lastToolOutput = "Error: MCP not configured"
		return
	}
	if action.MCPServer == "" || action.MCPTool == "" {
		l.emit(Event{Type: EventLog, Source: SourceSystem,
			Message: "call_mcp: missing mcp_server or mcp_tool"})
		l.lastToolOutput = "Error: missing mcp_server or mcp_tool"
		return
	}

	// 承認ゲートチェック
	if l.mcpMgr.IsProposalRequired(action.MCPServer) {
		desc := fmt.Sprintf("MCP call: %s.%s", action.MCPServer, action.MCPTool)
		l.lastCommand = desc
		if !l.handlePropose(ctx, desc, action.Thought) {
			return
		}
	}

	toolLabel := fmt.Sprintf("[MCP] %s.%s", action.MCPServer, action.MCPTool)
	l.lastCommand = toolLabel
	l.emit(Event{Type: EventLog, Source: SourceTool, Message: toolLabel})
	l.target.Status = StatusRunning

	result, err := l.mcpMgr.CallTool(ctx, action.MCPServer, action.MCPTool, action.MCPArgs)
	if err != nil {
		errMsg := fmt.Sprintf("MCP error: %v", err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.lastToolOutput = "Error: " + err.Error()
		l.lastExitCode = 1
		l.target.Status = StatusScanning
		return
	}

	// MCP 結果をテキストに変換
	var sb strings.Builder
	for _, block := range result.Content {
		if block.Text != "" {
			sb.WriteString(block.Text)
			sb.WriteString("\n")
		}
	}
	output := strings.TrimSpace(sb.String())

	if result.IsError {
		l.lastExitCode = 1
		l.emit(Event{Type: EventLog, Source: SourceSystem,
			Message: fmt.Sprintf("MCP tool returned error: %s", output)})
	} else {
		l.lastExitCode = 0
	}

	l.lastToolOutput = output
	l.target.Status = StatusScanning

	// TUI にツール出力を表示
	if output != "" {
		l.emit(Event{Type: EventLog, Source: SourceTool, Message: output})
	}

	// コマンド結果サマリー
	l.emit(Event{
		Type:     EventCommandResult,
		Source:   SourceTool,
		Message:  buildCommandSummary(l.lastExitCode, output),
		ExitCode: l.lastExitCode,
	})

	// Post-exec drain
	if msg := l.drainUserMsg(); msg != "" {
		l.pendingUserMsg = msg
	}
}

// waitForUserMsg はユーザーからのメッセージをブロッキングで待つ。
// コンテキストがキャンセルされた場合は空文字を返す。
func (l *Loop) waitForUserMsg(ctx context.Context) string {
	select {
	case msg := <-l.userMsg:
		if l.skillsReg != nil {
			return l.skillsReg.Expand(msg)
		}
		return msg
	case <-ctx.Done():
		return ""
	}
}

// evaluateResult はコマンド実行結果を評価し、成功/失敗を判定する。
// 3つのシグナルで判定: exit code, 出力パターン, コマンド繰り返し。
func (l *Loop) evaluateResult() {
	failed := l.lastExitCode != 0

	// Signal B: 出力パターンマッチ
	if isFailedOutput(l.lastToolOutput) {
		failed = true
	}

	// Signal C: 同一バイナリの繰り返し（直近5件で3回以上）
	if l.isCommandRepetition() {
		failed = true
		l.emit(Event{Type: EventLog, Source: SourceSystem,
			Message: "Repetition detected: same tool used repeatedly"})
	}

	if failed {
		l.consecutiveFailures++
	} else {
		l.consecutiveFailures = 0
	}
}

// isCommandRepetition は直近5件のコマンド履歴で同一バイナリが3回以上使われたか判定する。
func (l *Loop) isCommandRepetition() bool {
	n := len(l.history)
	if n < 3 {
		return false
	}
	start := 0
	if n > 5 {
		start = n - 5
	}
	counts := map[string]int{}
	for _, e := range l.history[start:] {
		bin := extractBinary(e.Command)
		if bin != "" {
			counts[bin]++
		}
	}
	for _, c := range counts {
		if c >= 3 {
			return true
		}
	}
	return false
}

// extractBinary はコマンド文字列から実行バイナリ名を抽出する。
// "nmap -sV 10.0.0.5" → "nmap", "/usr/bin/nmap -sV" → "nmap"
func extractBinary(command string) string {
	if command == "" {
		return ""
	}
	// 最初のスペースまでがコマンド部分
	cmd := command
	if idx := strings.IndexByte(command, ' '); idx >= 0 {
		cmd = command[:idx]
	}
	// パスからファイル名だけ取り出す
	if idx := strings.LastIndexByte(cmd, '/'); idx >= 0 {
		cmd = cmd[idx+1:]
	}
	if idx := strings.LastIndexByte(cmd, '\\'); idx >= 0 {
		cmd = cmd[idx+1:]
	}
	return cmd
}

// buildCommandSummary はコマンド実行結果のサマリーを生成する。
func buildCommandSummary(exitCode int, output string) string {
	lines := 0
	if output != "" {
		lines = strings.Count(output, "\n") + 1
	}

	if exitCode == 0 {
		if lines > 0 {
			return fmt.Sprintf("exit 0 (%d lines)", lines)
		}
		return "exit 0"
	}

	// 失敗時: exit code + 出力の1行目（エラーメッセージ）
	firstLine := output
	if idx := strings.IndexByte(output, '\n'); idx >= 0 {
		firstLine = output[:idx]
	}
	if len(firstLine) > 80 {
		firstLine = firstLine[:80] + "..."
	}
	if firstLine != "" {
		return fmt.Sprintf("exit %d: %s", exitCode, firstLine)
	}
	return fmt.Sprintf("exit %d", exitCode)
}

// isFailedOutput はツール出力が実質的に失敗かどうかを判定する。
func isFailedOutput(output string) bool {
	if output == "" {
		return true
	}
	failurePatterns := []string{
		// ネットワークエラー
		"0 hosts up",
		"Host seems down",
		"host is down",
		"No route to host",
		"Connection refused",
		"Connection timed out",
		"Network is unreachable",
		"Name or service not known",
		"couldn't connect to host",
		// プログラムエラー
		"SyntaxError",
		"command not found",
		"No such file or directory",
		"Permission denied",
		"Traceback (most recent call last)",
		"ModuleNotFoundError",
		"ImportError",
		"panic:",
		"NameError",
		"Segmentation fault",
	}
	for _, pattern := range failurePatterns {
		if containsCI(output, pattern) {
			return true
		}
	}
	// Error prefix from our own error handling
	if len(output) > 6 && output[:6] == "Error:" {
		return true
	}
	return false
}

// containsCI は大文字小文字を区別せずに部分一致を判定する。
func containsCI(s, substr string) bool {
	sLower := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		sLower[i] = c
	}
	subLower := make([]byte, len(substr))
	for i := range substr {
		c := substr[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		subLower[i] = c
	}
	return bytesContains(sLower, subLower)
}

func bytesContains(s, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := range sub {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// streamAndCollect は実行結果をストリームして TUI に表示する。
func (l *Loop) streamAndCollect(ctx context.Context, linesCh <-chan tools.OutputLine, resultCh <-chan *tools.ToolResult) {
	for line := range linesCh {
		if line.Content == "" {
			continue
		}
		l.emit(Event{Type: EventLog, Source: SourceTool, Message: line.Content})
	}

	result := <-resultCh
	if result.Err != nil {
		errMsg := fmt.Sprintf("Execution error: %v", result.Err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.lastToolOutput = "Error: " + result.Err.Error()
	} else {
		l.target.AddEntities(result.Entities)
		l.lastToolOutput = result.Truncated
	}

	// コマンド履歴を記録
	entry := commandEntry{
		Command:  l.lastCommand,
		ExitCode: result.ExitCode,
		Time:     result.FinishedAt,
	}
	if len(result.Truncated) > 200 {
		entry.Summary = result.Truncated[:200]
	} else {
		entry.Summary = result.Truncated
	}
	l.history = append(l.history, entry)
	if len(l.history) > 10 {
		l.history = l.history[len(l.history)-10:]
	}
	l.lastExitCode = result.ExitCode

	l.emit(Event{
		Type:     EventCommandResult,
		Source:   SourceTool,
		Message:  buildCommandSummary(result.ExitCode, result.Truncated),
		ExitCode: result.ExitCode,
	})

	l.target.Status = StatusScanning
}

// drainUserMsg はユーザーメッセージを取得し、スキル呼び出し（/skill-name）なら展開する。
func (l *Loop) drainUserMsg() string {
	select {
	case msg := <-l.userMsg:
		if l.skillsReg != nil {
			expanded := l.skillsReg.Expand(msg)
			if expanded != msg {
				l.emit(Event{Type: EventLog, Source: SourceSystem,
					Message: fmt.Sprintf("Skill expanded: %s", msg)})
			}
			return expanded
		}
		return msg
	default:
		return ""
	}
}

// buildHistory は直近5件のコマンド履歴をテキストで返す。
func (l *Loop) buildHistory() string {
	if len(l.history) == 0 {
		return ""
	}
	n := len(l.history)
	start := 0
	if n > 5 {
		start = n - 5
	}
	var sb strings.Builder
	for i, e := range l.history[start:] {
		if e.Summary != "" {
			fmt.Fprintf(&sb, "%d. `%s` → exit %d: %s\n", i+1, e.Command, e.ExitCode, e.Summary)
		} else {
			fmt.Fprintf(&sb, "%d. `%s` → exit %d\n", i+1, e.Command, e.ExitCode)
		}
	}
	return sb.String()
}

// buildMemory はメモリストアからターゲットの過去の発見物を読み出す。
func (l *Loop) buildMemory() string {
	if l.memoryStore == nil {
		return ""
	}
	return l.memoryStore.Read(l.target.Host)
}

func (l *Loop) buildSnapshot() string {
	entityMap := map[string][]string{}
	for _, e := range l.target.Entities {
		t := string(e.Type)
		entityMap[t] = append(entityMap[t], e.Value)
	}
	snapshot := map[string]any{
		"host":     l.target.Host,
		"status":   string(l.target.Status),
		"entities": entityMap,
	}

	b, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Sprintf(`{"host":%q}`, l.target.Host)
	}
	return string(b)
}

func (l *Loop) emit(e Event) {
	e.TargetID = l.target.ID
	select {
	case l.events <- e:
	default:
	}
}
