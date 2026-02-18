package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// View implements tea.Model and renders the full Commander Console layout.
func (m Model) View() string {
	if !m.ready {
		return "\n  ⚡ Pentecter を起動中...\n"
	}

	// ── Status bar (1 line) ──────────────────────────────────────────────────
	statusBar := m.renderStatusBar()

	// ── Left pane: target list ───────────────────────────────────────────────
	leftContent := m.list.View()
	var leftStyle lipgloss.Style
	if m.focus == FocusList {
		leftStyle = leftPaneActiveStyle.Width(leftPaneOuterWidth - 2)
	} else {
		leftStyle = leftPaneStyle.Width(leftPaneOuterWidth - 2)
	}
	leftPane := leftStyle.Render(leftContent)

	// ── Right pane: session log ──────────────────────────────────────────────
	rightOuterW := m.width - leftPaneOuterWidth
	rightContentW := rightOuterW - 2 // subtract left+right borders
	rightContent := m.viewport.View()
	var rightStyle lipgloss.Style
	if m.focus == FocusViewport {
		rightStyle = rightPaneActiveStyle.Width(rightContentW)
	} else {
		rightStyle = rightPaneStyle.Width(rightContentW)
	}
	rightPane := rightStyle.Render(rightContent)

	// ── Join panes side by side ──────────────────────────────────────────────
	panesRow := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)

	// ── Input bar (3 lines) ──────────────────────────────────────────────────
	inputBar := m.renderInputBar()

	return lipgloss.JoinVertical(lipgloss.Left, statusBar, panesRow, inputBar)
}

// renderStatusBar renders the single-line header with app name and focus hints.
func (m Model) renderStatusBar() string {
	appName := lipgloss.NewStyle().
		Foreground(colorPrimary).
		Bold(true).
		Render("⚡ PENTECTER")

	t := m.activeTarget()
	var targetInfo string
	if t != nil {
		targetInfo = fmt.Sprintf(
			"フォーカス: %s [%s]",
			lipgloss.NewStyle().Foreground(colorWarning).Render(t.Host),
			t.Status,
		)
	} else {
		targetInfo = lipgloss.NewStyle().Foreground(colorMuted).Render("ターゲット未選択")
	}

	hint := lipgloss.NewStyle().Foreground(colorMuted).Render("[Tab] フォーカス切替  [y/n/e] Proposal承認")
	focusIndicator := m.renderFocusIndicator()

	left := fmt.Sprintf("%s  %s  %s", appName, targetInfo, focusIndicator)
	gap := strings.Repeat(" ", max(0, m.width-lipgloss.Width(left)-lipgloss.Width(hint)-2))

	return statusBarStyle.Width(m.width).Render(left + gap + hint)
}

// renderFocusIndicator shows which pane is currently focused.
func (m Model) renderFocusIndicator() string {
	dim := lipgloss.NewStyle().Foreground(colorMuted)
	active := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true)

	list := dim.Render("[LIST]")
	log := dim.Render("[LOG]")
	input := dim.Render("[INPUT]")

	switch m.focus {
	case FocusList:
		list = active.Render("[LIST]")
	case FocusViewport:
		log = active.Render("[LOG]")
	case FocusInput:
		input = active.Render("[INPUT]")
	}

	return fmt.Sprintf("%s %s %s", list, log, input)
}

// renderInputBar renders the bottom input area with context-aware prefix.
func (m Model) renderInputBar() string {
	var prefix string
	switch m.focus {
	case FocusList:
		prefix = lipgloss.NewStyle().Foreground(colorMuted).Render("[List] ↑↓でターゲット選択")
	case FocusViewport:
		prefix = lipgloss.NewStyle().Foreground(colorMuted).Render("[Log]  ↑↓でスクロール")
	case FocusInput:
		prefix = lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("> ")
	}

	content := prefix + " " + m.input.View()
	w := m.width - 2

	if m.focus == FocusInput {
		return inputBarActiveStyle.Width(w).Render(content)
	}
	return inputBarStyle.Width(w).Render(content)
}

// max returns the larger of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
