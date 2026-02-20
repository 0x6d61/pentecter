package tui

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
)

// ipv4Re matches an IPv4 address in text.
var ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// domainRe matches a domain name with at least one dot (e.g. eighteen.htb, example.com, sub.domain.co.jp).
var domainRe = regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)

// extractHostFromText extracts an IPv4 address or domain name from natural language text.
// Returns (host, remainingMessage, found).
// Tries IPv4 first, then falls back to domain name matching.
// Does not match /target commands (handled separately by parseTargetInput).
func extractHostFromText(text string) (string, string, bool) {
	if text == "" || strings.HasPrefix(text, "/") {
		return "", "", false
	}

	// Try IPv4 first
	match := ipv4Re.FindStringSubmatchIndex(text)
	if match != nil {
		ip := text[match[2]:match[3]]
		// Validate it's a real IP
		if net.ParseIP(ip) != nil {
			raw := text[:match[2]] + text[match[3]:]
			remaining := strings.TrimSpace(strings.Join(strings.Fields(raw), " "))
			return ip, remaining, true
		}
	}

	// Fallback: try domain name
	domainMatch := domainRe.FindStringIndex(text)
	if domainMatch != nil {
		domain := text[domainMatch[0]:domainMatch[1]]
		raw := text[:domainMatch[0]] + text[domainMatch[1]:]
		remaining := strings.TrimSpace(strings.Join(strings.Fields(raw), " "))
		return domain, remaining, true
	}

	return "", "", false
}

// Update implements tea.Model and routes all incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.handleResize(msg.Width, msg.Height)
		m.ready = true
		m.rebuildViewport()
		return m, nil

	// スピナーティックメッセージ処理（thinking/subtask アニメーション用）
	case spinner.TickMsg:
		if m.spinning {
			var spinCmd tea.Cmd
			m.spinner, spinCmd = m.spinner.Update(msg)
			m.viewportDirty = false // フラッシュ
			m.rebuildViewport()
			return m, spinCmd
		}
		return m, nil

	case debounceMsg:
		if m.viewportDirty {
			m.viewportDirty = false
			m.rebuildViewport()
		}
		return m, nil

	// Agent ループからのイベントを処理する。
	case AgentEventMsg:
		spinnerCmd := m.handleAgentEvent(agent.Event(msg))
		// 次のイベントを待つコマンドを再登録（Bubble Tea の非同期ループパターン）
		var batchCmds []tea.Cmd
		if spinnerCmd != nil {
			batchCmds = append(batchCmds, spinnerCmd)
		}
		if m.agentEvents != nil {
			batchCmds = append(batchCmds, AgentEventCmd(m.agentEvents))
		}
		return m, tea.Batch(batchCmds...)

	case tea.KeyMsg:
		// Quit confirmation dialog intercepts all keys when active.
		if m.inputMode == InputConfirmQuit {
			return m.handleConfirmQuitKey(msg)
		}

		// Ctrl+C: show confirmation dialog instead of quitting immediately.
		if msg.String() == "ctrl+c" {
			m.inputMode = InputConfirmQuit
			return m, nil
		}

		// Select mode intercepts all keys before any other handling.
		if m.inputMode == InputSelect {
			m.handleSelectKey(msg)
			return m, nil
		}

		// Global: Tab cycles focus between panes.
		if msg.String() == "tab" {
			m.cycleFocus()
			return m, nil
		}

		// Global: Ctrl+O toggles log folding (works from any pane).
		if msg.String() == "ctrl+o" {
			m.logsExpanded = !m.logsExpanded
			m.rebuildViewport()
			return m, nil
		}

		// Proposal approval keys — handled regardless of which pane is focused,
		// as long as the active target has a pending proposal.
		if t := m.activeTarget(); t != nil {
			if prop := t.GetProposal(); prop != nil {
				switch msg.String() {
				case "y", "Y":
					t.AddBlock(agent.NewUserInputBlock("Approved: " + prop.Description))
					t.SetStatusSafe(agent.StatusRunning)
					t.ClearProposal()
					m.rebuildViewport()
					// 対象ターゲットの Agent ループに承認を通知
					if ch, ok := m.agentApproveMap[t.ID]; ok {
						select {
						case ch <- true:
						default:
						}
					}
					return m, nil
				case "n", "N":
					t.AddBlock(agent.NewUserInputBlock("Rejected: " + prop.Description))
					t.SetStatusSafe(agent.StatusIdle)
					t.ClearProposal()
					m.rebuildViewport()
					// 対象ターゲットの Agent ループに拒否を通知
					if ch, ok := m.agentApproveMap[t.ID]; ok {
						select {
						case ch <- false:
						default:
						}
					}
					return m, nil
				case "e", "E":
					// Populate the input box with the proposal command for editing.
					m.input.SetValue(prop.Tool + " " + strings.Join(prop.Args, " "))
					m.focus = FocusInput
					m.input.Focus()
					return m, nil
				}
			}
		}

		// Focus-specific key handling.
		switch m.focus {
		case FocusViewport:
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)

		case FocusInput:
			switch msg.String() {
			case "enter":
				m.submitInput()
			default:
				// textarea handles Ctrl+Enter / Alt+Enter as newline via KeyMap.InsertNewline
				m.input, cmd = m.input.Update(msg)
				cmds = append(cmds, cmd)
			}
		}
	}

	return m, tea.Batch(cmds...)
}

// handleResize recomputes all component dimensions to fit the new terminal size.
func (m *Model) handleResize(w, h int) {
	m.width = w
	m.height = h

	const (
		statusBarH  = 1
		inputBorder = 2 // rounded border top + bottom
		paneVBorder = 2 // top + bottom borders for panes
	)
	inputAreaH := inputBorder + m.input.MaxHeight

	paneH := h - statusBarH - inputAreaH - paneVBorder
	if paneH < 4 {
		paneH = 4
	}

	// Main pane: viewport (full width)
	vpW := w - 4 // subtract 2 borders + 2 side margins
	vpH := paneH - 2
	if vpW < 10 {
		vpW = 10
	}

	if !m.ready {
		m.viewport = viewport.New(vpW, vpH)
	} else {
		m.viewport.Width = vpW
		m.viewport.Height = vpH
	}

	m.input.SetWidth(w - 6)
}

// cycleFocus toggles focus between Viewport and Input.
func (m *Model) cycleFocus() {
	switch m.focus {
	case FocusViewport:
		m.focus = FocusInput
		m.input.Focus()
	case FocusInput:
		m.focus = FocusViewport
		m.input.Blur()
	}
}

// submitInput sends the current input as a USER log entry and to the Agent.
func (m *Model) submitInput() {
	fullText := strings.TrimSpace(m.input.Value())

	if fullText == "" {
		return
	}
	m.input.Reset()

	// /approve command — toggle auto-approve
	if strings.HasPrefix(fullText, "/approve") {
		m.handleApproveCommand(fullText)
		return
	}

	// /model command — switch LLM provider/model
	if strings.HasPrefix(fullText, "/model") {
		m.handleModelCommand(fullText)
		return
	}

	// /targets command — show target list for selection
	if fullText == "/targets" {
		m.handleTargetsCommand()
		return
	}

	// /recontree command — show recon tree for the active target
	if fullText == "/recontree" {
		m.handleReconTreeCommand()
		return
	}

	// /skip-recon command — unlock RECON phase for the active target
	if fullText == "/skip-recon" {
		m.handleSkipReconCommand()
		return
	}

	// ターゲット追加: IP アドレスまたは /target <host>
	if host, ok := parseTargetInput(fullText); ok && m.team != nil {
		m.addTarget(host)
		return
	}

	// Natural language host extraction: "192.168.81.1をスキャンして" or "eighteen.htbをスキャンして" → add target + send message
	if m.team != nil && len(m.targets) == 0 {
		if host, msg, ok := extractHostFromText(fullText); ok {
			m.addTarget(host)
			// Log the full original input as user message
			if t := m.activeTarget(); t != nil {
				t.AddBlock(agent.NewUserInputBlock(fullText))
			}
			// Send remaining message (without IP) to agent for processing
			if msg != "" {
				if t := m.activeTarget(); t != nil {
					if ch, ok := m.agentUserMsgMap[t.ID]; ok {
						select {
						case ch <- msg:
						default:
						}
					}
				}
			}
			m.rebuildViewport()
			return
		}
	}

	if t := m.activeTarget(); t != nil {
		t.AddBlock(agent.NewUserInputBlock(fullText))
		m.rebuildViewport()
	}

	// 現在選択中のターゲットの Agent にメッセージを送る（非ブロッキング）
	if t := m.activeTarget(); t != nil {
		if ch, ok := m.agentUserMsgMap[t.ID]; ok {
			select {
			case ch <- fullText:
			default:
			}
		}
	}
}

// parseTargetInput は IP アドレス、ドメイン名、または /target <host> を検知する。
func parseTargetInput(text string) (string, bool) {
	// /target <host>
	if strings.HasPrefix(text, "/target ") {
		host := strings.TrimSpace(strings.TrimPrefix(text, "/target "))
		if host != "" {
			return host, true
		}
	}
	// 素の IP アドレス（ターゲットが未選択のときのみ自然に追加）
	if net.ParseIP(text) != nil {
		return text, true
	}
	// 素のドメイン名（完全一致）
	if domainRe.MatchString(text) && domainRe.FindString(text) == text {
		return text, true
	}
	return "", false
}

// addTarget は Team にターゲットを追加し TUI を更新する。
// Team が nil チャネルを返した場合は既存ターゲット（重複）なので追加しない。
func (m *Model) addTarget(host string) {
	target, approveCh, userMsgCh := m.team.AddTarget(host)

	// Team が nil チャネルを返した場合は既存ターゲット（重複）
	if approveCh == nil {
		return
	}

	m.targets = append(m.targets, target)
	m.agentApproveMap[target.ID] = approveCh
	m.agentUserMsgMap[target.ID] = userMsgCh
	// 新しいターゲットを選択状態にする
	m.selected = len(m.targets) - 1
	m.rebuildViewport()
}

// handleApproveCommand processes /approve commands.
// Always shows interactive select UI (ON/OFF).
func (m *Model) handleApproveCommand(_ string) {
	if m.Runner == nil {
		m.logSystem("Auto-approve not available")
		return
	}

	currentStatus := "OFF"
	if m.Runner.AutoApprove() {
		currentStatus = "ON"
	}
	m.showSelect(
		fmt.Sprintf("Auto-approve (current: %s):", currentStatus),
		[]SelectOption{
			{Label: "ON  -- auto-approve all commands", Value: "on"},
			{Label: "OFF -- require approval", Value: "off"},
		},
		func(m *Model, value string) {
			if m.Runner == nil {
				return
			}
			switch value {
			case "on":
				m.Runner.SetAutoApprove(true)
				m.logSystem("Auto-approve: ON -- all commands will execute without confirmation")
			case "off":
				m.Runner.SetAutoApprove(false)
				m.logSystem("Auto-approve: OFF -- proposals will require confirmation")
			}
		},
	)
}

// modelsForProvider はプロバイダーごとの代表的なモデル一覧を返す。
func modelsForProvider(p brain.Provider) []SelectOption {
	switch p {
	case brain.ProviderAnthropic:
		return []SelectOption{
			{Label: "claude-sonnet-4-6 (recommended)", Value: "claude-sonnet-4-6"},
			{Label: "claude-opus-4-6", Value: "claude-opus-4-6"},
			{Label: "claude-haiku-4-5", Value: "claude-haiku-4-5-20251001"},
		}
	case brain.ProviderOpenAI:
		return []SelectOption{
			{Label: "gpt-4o (recommended)", Value: "gpt-4o"},
			{Label: "gpt-4o-mini", Value: "gpt-4o-mini"},
			{Label: "o3-mini", Value: "o3-mini"},
		}
	case brain.ProviderOllama:
		return []SelectOption{
			{Label: "llama3.2 (recommended)", Value: "llama3.2"},
			{Label: "llama3.2:3b", Value: "llama3.2:3b"},
			{Label: "qwen2.5:7b", Value: "qwen2.5:7b"},
			{Label: "gemma2:9b", Value: "gemma2:9b"},
		}
	default:
		return nil
	}
}

// handleModelCommand processes /model commands.
// Always shows interactive 2-step select UI (provider → model).
func (m *Model) handleModelCommand(_ string) {
	detected := brain.DetectAvailableProviders()
	if len(detected) == 0 {
		m.logSystem("No providers detected. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_BASE_URL.")
		return
	}

	options := make([]SelectOption, len(detected))
	for i, p := range detected {
		options[i] = SelectOption{
			Label: string(p),
			Value: string(p),
		}
	}

	m.showSelect(
		"Select provider:",
		options,
		func(m *Model, providerValue string) {
			provider := brain.Provider(providerValue)
			models := modelsForProvider(provider)
			if len(models) == 0 {
				m.switchModel(provider, "")
				return
			}
			m.showSelect(
				fmt.Sprintf("Select model (%s):", providerValue),
				models,
				func(m *Model, modelValue string) {
					m.switchModel(provider, modelValue)
				},
			)
		},
	)
}

// switchModel executes the actual model switch via BrainFactory.
func (m *Model) switchModel(provider brain.Provider, model string) {
	if m.BrainFactory == nil {
		m.logSystem("Model switching not available (no brain factory)")
		return
	}

	newBrain, err := m.BrainFactory(brain.ConfigHint{
		Provider: provider,
		Model:    model,
	})
	if err != nil {
		m.logSystem(fmt.Sprintf("Failed to switch model: %v", err))
		return
	}

	if m.team != nil {
		m.team.SetBrain(newBrain)
	}
	m.CurrentProvider = string(provider)
	m.CurrentModel = model
	msg := fmt.Sprintf("Switched to %s", provider)
	if model != "" {
		msg += "/" + model
	}
	m.logSystem(msg)
}

// handleTargetsCommand shows an interactive target list using the select UI.
func (m *Model) handleTargetsCommand() {
	if len(m.targets) == 0 {
		m.logSystem("No targets. Add one with /target <host>")
		return
	}

	options := make([]SelectOption, len(m.targets))
	for i, t := range m.targets {
		status := t.GetStatus()
		icon := status.Icon()
		label := fmt.Sprintf("%s %s [%s]", icon, t.Host, status)
		options[i] = SelectOption{
			Label: label,
			Value: fmt.Sprintf("%d", i),
		}
	}

	m.showSelect(
		"Select target:",
		options,
		func(m *Model, value string) {
			var idx int
			if _, err := fmt.Sscanf(value, "%d", &idx); err != nil {
				return
			}
			if idx >= 0 && idx < len(m.targets) {
				m.selected = idx
				m.rebuildViewport()
				m.logSystem(fmt.Sprintf("Switched to target: %s", m.targets[idx].Host))
			}
		},
	)
}

// handleReconTreeCommand は /recontree コマンドを処理する。
func (m *Model) handleReconTreeCommand() {
	if m.selected < 0 || m.selected >= len(m.targets) {
		m.logSystem("No target selected.")
		return
	}
	target := m.targets[m.selected]
	rt := target.GetReconTree()
	if rt == nil {
		m.logSystem("No recon tree available for this target.")
		return
	}
	output := rt.RenderTree()
	// コードブロックで囲んで glamour の崩れを防止
	m.logSystem("```\n" + output + "```")
}

// handleSkipReconCommand は /skip-recon コマンドを処理する。
func (m *Model) handleSkipReconCommand() {
	if m.selected < 0 || m.selected >= len(m.targets) {
		m.logSystem("No target selected.")
		return
	}
	target := m.targets[m.selected]
	rt := target.GetReconTree()
	if rt == nil {
		m.logSystem("No recon tree available for this target.")
		return
	}
	if !rt.IsLocked() {
		m.logSystem("RECON phase is already unlocked.")
		return
	}
	pending := rt.CountPending()
	rt.Unlock()
	m.logSystem(fmt.Sprintf("RECON phase unlocked (%d pending tasks skipped). Agent will proceed to ANALYZE.", pending))
}

// logSystem adds a system message to the active target as a Block.
func (m *Model) logSystem(msg string) {
	if t := m.activeTarget(); t != nil {
		t.AddBlock(agent.NewSystemBlock(msg))
	} else {
		m.globalLogs = append(m.globalLogs, msg)
	}
	m.rebuildViewport()
}

// targetByID は ID でターゲットを検索する。
func (m *Model) targetByID(id int) *agent.Target {
	for _, t := range m.targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// hasActiveSpinner は処理中の thinking または subtask ブロックが存在するかチェックする。
func (m *Model) hasActiveSpinner() bool {
	t := m.activeTarget()
	if t == nil {
		return false
	}
	for i := len(t.Blocks) - 1; i >= 0; i-- {
		b := t.Blocks[i]
		if b.Type == agent.BlockThinking && !b.ThinkingDone {
			return true
		}
		if b.Type == agent.BlockSubTask && !b.TaskDone {
			return true
		}
	}
	return false
}

// handleAgentEvent は Agent ループから届くイベントを処理する。
// TargetID を使って正しいターゲットのログを更新する。
// スピナーの開始が必要な場合は tea.Cmd を返す。
func (m *Model) handleAgentEvent(e agent.Event) tea.Cmd {
	t := m.targetByID(e.TargetID)
	if t == nil {
		t = m.activeTarget() // フォールバック
	}
	if t == nil {
		return nil
	}

	needsViewportUpdate := t.ID == m.activeTarget().ID // 表示中のターゲットか

	var spinnerCmd tea.Cmd

	switch e.Type {
	case agent.EventLog:
		// DisplayBlock を追加
		switch e.Source {
		case agent.SourceAI:
			t.AddBlock(agent.NewAIMessageBlock(e.Message))
		case agent.SourceTool:
			// 未完了の BlockCommand があれば出力として追記、なければ新しいコマンドブロックを作成
			if last := t.LastBlock(); last != nil && last.Type == agent.BlockCommand && !last.Completed {
				last.Output = append(last.Output, e.Message)
			} else {
				t.AddBlock(agent.NewCommandBlock(e.Message))
			}
		case agent.SourceSystem:
			t.AddBlock(agent.NewSystemBlock(e.Message))
		case agent.SourceUser:
			t.AddBlock(agent.NewUserInputBlock(e.Message))
		}

	case agent.EventProposal:
		if e.Proposal != nil {
			t.SetProposal(e.Proposal)
		}

	case agent.EventComplete:
		t.AddBlock(agent.NewSystemBlock("✅ " + e.Message))

	case agent.EventError:
		t.AddBlock(agent.NewSystemBlock("❌ " + e.Message))

	case agent.EventAddTarget:
		// AI が横展開で新ターゲットを追加
		if e.NewHost != "" && m.team != nil {
			m.addTarget(e.NewHost)
		}

	case agent.EventStalled:
		t.AddBlock(agent.NewSystemBlock("⚠ " + e.Message))
		t.AddBlock(agent.NewSystemBlock("Type a message to give the agent new direction."))

	case agent.EventTurnStart:
		// ターン開始はブロックを追加しない（新UIではターンは暗黙的）

	case agent.EventThinkStart:
		// 新しい ThinkingBlock を追加
		t.AddBlock(agent.NewThinkingBlock())
		// スピナーがまだ動いていなければ開始
		if !m.spinning {
			m.spinning = true
			spinnerCmd = m.spinner.Tick
		}

	case agent.EventThinkDone:
		// 最後の ThinkingBlock を完了にマーク
		if last := t.LastBlock(); last != nil && last.Type == agent.BlockThinking && !last.ThinkingDone {
			last.ThinkingDone = true
			last.ThinkDuration = e.Duration
		}
		// アクティブなスピナーブロックが残っているかチェック
		m.spinning = m.hasActiveSpinner()

	case agent.EventCmdStart:
		// 新しい CommandBlock を追加
		t.AddBlock(agent.NewCommandBlock(e.Message))

	case agent.EventCmdOutput:
		// 最後の未完了 CommandBlock に出力行を追記
		if last := t.LastBlock(); last != nil && last.Type == agent.BlockCommand && !last.Completed {
			last.Output = append(last.Output, e.OutputLine)
		}

	case agent.EventCmdDone:
		// 最後の CommandBlock を完了にマーク
		if last := t.LastBlock(); last != nil && last.Type == agent.BlockCommand {
			last.Completed = true
			last.ExitCode = e.ExitCode
			last.Duration = e.Duration
		}
		// アクティブなスピナーブロックが残っているかチェック
		m.spinning = m.hasActiveSpinner()

	case agent.EventSubTaskStart:
		// 新しい SubTaskBlock を追加
		t.AddBlock(agent.NewSubTaskBlock(e.TaskID, e.Message))
		// スピナーがまだ動いていなければ開始
		if !m.spinning {
			m.spinning = true
			spinnerCmd = m.spinner.Tick
		}

	case agent.EventSubTaskLog:
		// サブタスクログはブロックを追加しない（内部処理）

	case agent.EventSubTaskComplete:
		// 対応するサブタスクブロックを完了にマーク
		for i := len(t.Blocks) - 1; i >= 0; i-- {
			if t.Blocks[i].Type == agent.BlockSubTask && t.Blocks[i].TaskID == e.TaskID && !t.Blocks[i].TaskDone {
				t.Blocks[i].TaskDone = true
				break
			}
		}
		// アクティブなスピナーブロックが残っているかチェック
		m.spinning = m.hasActiveSpinner()
	}

	if needsViewportUpdate {
		// EventCmdOutput はデバウンス: スピナーが動いていれば次の TickMsg でフラッシュ、
		// 停止中は debounceMsg タイマーで 100ms 後にフラッシュ。
		if e.Type == agent.EventCmdOutput {
			m.viewportDirty = true
			if !m.spinning {
				return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg {
					return debounceMsg{}
				})
			}
		} else {
			m.rebuildViewport()
		}
	}
	return spinnerCmd
}

// handleConfirmQuitKey processes key events in the quit confirmation dialog.
func (m Model) handleConfirmQuitKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		return m, tea.Quit
	case "n", "N", "esc":
		m.inputMode = InputNormal
		return m, nil
	}
	// Other keys: ignore, stay in confirmation dialog.
	return m, nil
}

// handleSelectKey processes key events when the select UI is active.
func (m *Model) handleSelectKey(msg tea.KeyMsg) {
	switch msg.Type {
	case tea.KeyUp:
		if m.selectIndex > 0 {
			m.selectIndex--
		}
	case tea.KeyDown:
		if m.selectIndex < len(m.selectOptions)-1 {
			m.selectIndex++
		}
	case tea.KeyEnter:
		cb := m.selectCallback
		value := ""
		if len(m.selectOptions) > 0 {
			value = m.selectOptions[m.selectIndex].Value
		}
		// 先にリセット（コールバック内で showSelect が再設定する可能性がある）
		m.inputMode = InputNormal
		m.selectOptions = nil
		m.selectCallback = nil
		// コールバック実行（内部で showSelect が呼ばれると InputSelect に戻る）
		if cb != nil && value != "" {
			cb(m, value)
		}
	case tea.KeyEscape:
		m.inputMode = InputNormal
		m.selectOptions = nil
		m.selectCallback = nil
	}
}
