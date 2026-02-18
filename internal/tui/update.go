package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/agent"
)

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
				t.AddLog(agent.SourceUser, "✓ 承認: "+t.Proposal.Description)
				t.Status = agent.StatusRunning
				t.ClearProposal()
				m.syncListItems()
				m.rebuildViewport()
				// Agent ループに承認を通知
				if m.agentApprove != nil {
					select {
					case m.agentApprove <- true:
					default:
					}
				}
				return m, nil
			case "n", "N":
				t.AddLog(agent.SourceUser, "✗ 拒否: "+t.Proposal.Description)
				t.Status = agent.StatusIdle
				t.ClearProposal()
				m.syncListItems()
				m.rebuildViewport()
				// Agent ループに拒否を通知
				if m.agentApprove != nil {
					select {
					case m.agentApprove <- false:
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
	text := strings.TrimSpace(m.input.Value())
	if text == "" {
		return
	}
	m.input.SetValue("")

	if t := m.activeTarget(); t != nil {
		t.AddLog(agent.SourceUser, text)
		m.syncListItems()
		m.rebuildViewport()
	}

	// Agent が接続されていればユーザーメッセージを送る（非ブロッキング）
	if m.agentUserMsg != nil {
		select {
		case m.agentUserMsg <- text:
		default:
		}
	}
}

// handleAgentEvent は Agent ループから届くイベントを処理する。
func (m *Model) handleAgentEvent(e agent.Event) {
	t := m.activeTarget()
	if t == nil {
		return
	}

	switch e.Type {
	case agent.EventLog:
		t.AddLog(e.Source, e.Message)
		m.syncListItems()
		m.rebuildViewport()

	case agent.EventProposal:
		if e.Proposal != nil {
			t.SetProposal(e.Proposal)
		}
		m.syncListItems()
		m.rebuildViewport()

	case agent.EventComplete:
		t.AddLog(agent.SourceSystem, "✅ "+e.Message)
		m.syncListItems()
		m.rebuildViewport()

	case agent.EventError:
		t.AddLog(agent.SourceSystem, "❌ "+e.Message)
		m.syncListItems()
		m.rebuildViewport()
	}
}
