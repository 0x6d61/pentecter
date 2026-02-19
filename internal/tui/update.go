package tui

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
)

// ipv4Re matches an IPv4 address in text.
var ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// extractIPFromText extracts an IPv4 address from natural language text.
// Returns (ip, remainingMessage, found).
// Does not match /target commands (handled separately by parseTargetInput).
func extractIPFromText(text string) (string, string, bool) {
	if text == "" || strings.HasPrefix(text, "/") {
		return "", "", false
	}

	match := ipv4Re.FindStringSubmatchIndex(text)
	if match == nil {
		return "", "", false
	}

	ip := text[match[2]:match[3]]
	// Validate it's a real IP
	if net.ParseIP(ip) == nil {
		return "", "", false
	}

	// Build remaining message by removing the IP and collapsing whitespace
	raw := text[:match[2]] + text[match[3]:]
	remaining := strings.TrimSpace(strings.Join(strings.Fields(raw), " "))
	return ip, remaining, true
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

	// Agent ループからのイベントを処理する。
	case AgentEventMsg:
		m.handleAgentEvent(agent.Event(msg))
		// 次のイベントを待つコマンドを再登録（Bubble Tea の非同期ループパターン）
		if m.agentEvents != nil {
			return m, AgentEventCmd(m.agentEvents)
		}
		return m, nil

	case tea.KeyMsg:
		// Select mode intercepts all keys before any other handling.
		if m.inputMode == InputSelect {
			m.handleSelectKey(msg)
			return m, nil
		}

		// Global: always handle quit.
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		// Global: Tab cycles focus between panes.
		if msg.String() == "tab" {
			m.cycleFocus()
			return m, nil
		}

		// Proposal approval keys — handled regardless of which pane is focused,
		// as long as the active target has a pending proposal.
		if t := m.activeTarget(); t != nil && t.Proposal != nil {
			switch msg.String() {
			case "y", "Y":
				t.AddLog(agent.SourceUser, "Approved: "+t.Proposal.Description)
				t.Status = agent.StatusRunning
				t.ClearProposal()
				m.syncListItems()
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
				t.AddLog(agent.SourceUser, "Rejected: "+t.Proposal.Description)
				t.Status = agent.StatusIdle
				t.ClearProposal()
				m.syncListItems()
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
				m.input.SetValue(t.Proposal.Tool + " " + strings.Join(t.Proposal.Args, " "))
				m.focus = FocusInput
				m.input.Focus()
				return m, nil
			}
		}

		// Focus-specific key handling.
		switch m.focus {
		case FocusList:
			prevIdx := m.list.Index()
			m.list, cmd = m.list.Update(msg)
			cmds = append(cmds, cmd)
			// When selection changes, reload viewport for the newly selected target.
			if m.list.Index() != prevIdx {
				m.selected = m.list.Index()
				m.rebuildViewport()
			}

		case FocusViewport:
			m.viewport, cmd = m.viewport.Update(msg)
			cmds = append(cmds, cmd)

		case FocusInput:
			switch msg.String() {
			case "alt+enter", "ctrl+enter":
				// Accumulate current line and clear input for next line
				if text := m.input.Value(); text != "" {
					m.multilineBuffer = append(m.multilineBuffer, text)
					m.input.SetValue("")
					m.input.Placeholder = fmt.Sprintf("[%d lines] Continue typing or Alt+Enter for more...", len(m.multilineBuffer))
				}
			case "esc":
				if len(m.multilineBuffer) > 0 {
					m.multilineBuffer = nil
					m.input.Placeholder = "Chat with AI or enter command..."
				}
			case "enter":
				m.submitInput()
			default:
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
		statusBarH = 1
		inputAreaH = 3 // rounded border (1) + content (1) + rounded border (1)
		paneVBorder = 2 // top + bottom borders for panes
	)

	paneH := h - statusBarH - inputAreaH - paneVBorder
	if paneH < 4 {
		paneH = 4
	}

	// Left pane: list
	listContentW := leftPaneOuterWidth - 4 // subtract 2 borders + 2 internal margins
	listContentH := paneH - 2              // subtract top + bottom borders
	m.list.SetWidth(listContentW)
	m.list.SetHeight(listContentH)

	// Right pane: viewport
	rightOuterW := w - leftPaneOuterWidth
	vpW := rightOuterW - 4 // subtract 2 borders + 2 side margins
	vpH := paneH - 2       // subtract top + bottom borders
	if vpW < 10 {
		vpW = 10
	}

	if !m.ready {
		m.viewport = viewport.New(vpW, vpH)
	} else {
		m.viewport.Width = vpW
		m.viewport.Height = vpH
	}

	// Input bar: spans full width minus borders.
	m.input.Width = w - 6 // subtract 2 borders + 2 side margins + 2 for prompt prefix
}

// cycleFocus advances focus to the next pane in order: List → Viewport → Input → List.
func (m *Model) cycleFocus() {
	switch m.focus {
	case FocusList:
		m.focus = FocusViewport
		m.input.Blur()
	case FocusViewport:
		m.focus = FocusInput
		m.input.Focus()
	case FocusInput:
		m.focus = FocusList
		m.input.Blur()
	}
}

// submitInput sends the current input as a USER log entry and to the Agent.
func (m *Model) submitInput() {
	currentText := m.input.Value()

	// Combine multiline buffer with current input
	var fullText string
	if len(m.multilineBuffer) > 0 {
		allLines := append(m.multilineBuffer, currentText)
		fullText = strings.TrimSpace(strings.Join(allLines, "\n"))
		m.multilineBuffer = nil
		m.input.Placeholder = "Chat with AI or enter command..."
	} else {
		fullText = strings.TrimSpace(currentText)
	}

	if fullText == "" {
		return
	}
	m.input.SetValue("")

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

	// ターゲット追加: IP アドレスまたは /target <host>
	if host, ok := parseTargetInput(fullText); ok && m.team != nil {
		m.addTarget(host)
		return
	}

	// Natural language IP extraction: "192.168.81.1をスキャンして" → add target + send message
	if m.team != nil && len(m.targets) == 0 {
		if ip, msg, ok := extractIPFromText(fullText); ok {
			m.addTarget(ip)
			// Log the full original input as user message
			if t := m.activeTarget(); t != nil {
				t.AddLog(agent.SourceUser, fullText)
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
			m.syncListItems()
			m.rebuildViewport()
			return
		}
	}

	if t := m.activeTarget(); t != nil {
		t.AddLog(agent.SourceUser, fullText)
		m.syncListItems()
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

// parseTargetInput は IP アドレスまたは /target <host> を検知する。
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
	return "", false
}

// addTarget は Team にターゲットを追加し TUI を更新する。
func (m *Model) addTarget(host string) {
	target, approveCh, userMsgCh := m.team.AddTarget(host)
	m.targets = append(m.targets, target)
	m.agentApproveMap[target.ID] = approveCh
	m.agentUserMsgMap[target.ID] = userMsgCh
	// 新しいターゲットを選択状態にする
	m.selected = len(m.targets) - 1
	m.syncListItems()
	m.list.Select(m.selected)
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
	msg := fmt.Sprintf("Switched to %s", provider)
	if model != "" {
		msg += "/" + model
	}
	m.logSystem(msg)
}

// logSystem adds a system log to the active target or viewport.
func (m *Model) logSystem(msg string) {
	if t := m.activeTarget(); t != nil {
		t.AddLog(agent.SourceSystem, msg)
	}
	m.syncListItems()
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

// handleAgentEvent は Agent ループから届くイベントを処理する。
// TargetID を使って正しいターゲットのログを更新する。
func (m *Model) handleAgentEvent(e agent.Event) {
	t := m.targetByID(e.TargetID)
	if t == nil {
		t = m.activeTarget() // フォールバック
	}
	if t == nil {
		return
	}

	needsViewportUpdate := t.ID == m.activeTarget().ID // 表示中のターゲットか

	switch e.Type {
	case agent.EventLog:
		t.AddLog(e.Source, e.Message)
	case agent.EventProposal:
		if e.Proposal != nil {
			t.SetProposal(e.Proposal)
		}
	case agent.EventComplete:
		t.AddLog(agent.SourceSystem, "✅ "+e.Message)
	case agent.EventError:
		t.AddLog(agent.SourceSystem, "❌ "+e.Message)
	case agent.EventAddTarget:
		// AI が横展開で新ターゲットを追加
		if e.NewHost != "" && m.team != nil {
			m.addTarget(e.NewHost)
		}
	case agent.EventStalled:
		t.AddLog(agent.SourceSystem, "⚠ "+e.Message)
		t.AddLog(agent.SourceSystem, "Type a message to give the agent new direction.")
	case agent.EventTurnStart:
		t.Logs = append(t.Logs, agent.LogEntry{
			Time:       time.Now(),
			Source:     agent.SourceSystem,
			Message:    fmt.Sprintf("Turn %d", e.TurnNumber),
			Type:       agent.EventTurnStart,
			TurnNumber: e.TurnNumber,
		})
	case agent.EventCommandResult:
		t.Logs = append(t.Logs, agent.LogEntry{
			Time:     time.Now(),
			Source:   agent.SourceTool,
			Message:  e.Message,
			Type:     agent.EventCommandResult,
			ExitCode: e.ExitCode,
		})
	}

	m.syncListItems()
	if needsViewportUpdate {
		m.rebuildViewport()
	}
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
