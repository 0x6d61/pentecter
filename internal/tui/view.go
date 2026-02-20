package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

// View implements tea.Model and renders the full Commander Console layout.
func (m Model) View() string {
	if !m.ready {
		return "\n  ⚡ Starting Pentecter...\n"
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

	base := lipgloss.JoinVertical(lipgloss.Left, statusBar, panesRow, inputBar)

	// Overlay quit confirmation dialog in the center of the screen.
	if m.inputMode == InputConfirmQuit {
		overlay := m.renderConfirmQuit()
		base = m.overlayCenter(base, overlay)
	}

	return base
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
			"Focus: %s [%s]",
			lipgloss.NewStyle().Foreground(colorWarning).Render(t.Host),
			t.GetStatus(),
		)
	} else {
		targetInfo = lipgloss.NewStyle().Foreground(colorMuted).Render("No target selected")
	}

	// Model info
	var modelInfo string
	if m.CurrentModel != "" {
		modelInfo = lipgloss.NewStyle().Foreground(colorMuted).Render(
			fmt.Sprintf("Model: %s/%s", m.CurrentProvider, m.CurrentModel))
	} else if m.CurrentProvider != "" {
		modelInfo = lipgloss.NewStyle().Foreground(colorMuted).Render(
			fmt.Sprintf("Model: %s", m.CurrentProvider))
	}

	hint := lipgloss.NewStyle().Foreground(colorMuted).Render("[Tab] Switch pane  [y/n/e] Proposal")
	focusIndicator := m.renderFocusIndicator()

	left := appName + "  " + targetInfo + "  " + focusIndicator
	if modelInfo != "" {
		left += "  " + modelInfo
	}
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
// When select mode is active, it renders the select UI instead of the text input.
func (m Model) renderInputBar() string {
	// Select mode: show interactive options instead of text input
	if m.inputMode == InputSelect {
		return m.renderSelectBar()
	}

	var prefix string
	switch m.focus {
	case FocusList:
		prefix = lipgloss.NewStyle().Foreground(colorMuted).Render("[List] ↑↓ Select target")
	case FocusViewport:
		prefix = lipgloss.NewStyle().Foreground(colorMuted).Render("[Log]  ↑↓ Scroll")
	case FocusInput:
		prefix = lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("> ")
	}

	content := prefix + " " + m.input.View()
	w := m.width - 2
	return inputBarStyle.Width(w).Render(content)
}

// renderSelectBar renders the interactive selection UI in the input bar area.
func (m Model) renderSelectBar() string {
	var sb strings.Builder

	title := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render(m.selectTitle)
	sb.WriteString(title + "\n")

	for i, opt := range m.selectOptions {
		if i == m.selectIndex {
			selected := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("> " + opt.Label)
			sb.WriteString("  " + selected + "\n")
		} else {
			sb.WriteString("    " + opt.Label + "\n")
		}
	}

	hint := lipgloss.NewStyle().Foreground(colorMuted).Render("[Up/Down] Move  [Enter] Select  [Esc] Cancel")
	sb.WriteString(hint)

	w := m.width - 2
	return inputBarActiveStyle.Width(w).Render(sb.String())
}

// renderConfirmQuit renders the centered quit confirmation dialog.
func (m Model) renderConfirmQuit() string {
	title := lipgloss.NewStyle().
		Foreground(colorWarning).
		Bold(true).
		Render("Quit Pentecter?")

	hint := lipgloss.NewStyle().
		Foreground(colorMuted).
		Render("[Y] Yes  [N] No  [Esc] Cancel")

	content := fmt.Sprintf("\n  %s\n\n  %s\n", title, hint)

	return confirmQuitBoxStyle.Render(content)
}

// overlayCenter places the overlay string in the center of the base string.
func (m Model) overlayCenter(base, overlay string) string {
	baseLines := strings.Split(base, "\n")
	overlayLines := strings.Split(overlay, "\n")

	// Calculate center position
	overlayH := len(overlayLines)
	overlayW := 0
	for _, line := range overlayLines {
		if w := lipgloss.Width(line); w > overlayW {
			overlayW = w
		}
	}

	startRow := (m.height - overlayH) / 2
	startCol := (m.width - overlayW) / 2
	if startRow < 0 {
		startRow = 0
	}
	if startCol < 0 {
		startCol = 0
	}

	// Pad base to have enough lines
	for len(baseLines) < startRow+overlayH {
		baseLines = append(baseLines, strings.Repeat(" ", m.width))
	}

	// Overlay each line
	for i, oLine := range overlayLines {
		row := startRow + i
		if row >= len(baseLines) {
			break
		}

		baseLine := baseLines[row]
		// Pad base line to at least startCol width
		for lipgloss.Width(baseLine) < startCol {
			baseLine += " "
		}

		// Build new line: left part + overlay + right part
		// Use rune-safe slicing based on visual width
		left := truncateVisual(baseLine, startCol)
		rightStart := startCol + lipgloss.Width(oLine)
		right := ""
		if lipgloss.Width(baseLine) > rightStart {
			right = skipVisual(baseLine, rightStart)
		}

		baseLines[row] = left + oLine + right
	}

	return strings.Join(baseLines, "\n")
}

// truncateVisual returns the first n visual columns of a string.
func truncateVisual(s string, n int) string {
	w := 0
	for i, r := range s {
		rw := runewidth.RuneWidth(r)
		if w+rw > n {
			return s[:i] + strings.Repeat(" ", n-w)
		}
		w += rw
	}
	// String is shorter than n — pad with spaces
	return s + strings.Repeat(" ", n-w)
}

// skipVisual returns everything after the first n visual columns.
func skipVisual(s string, n int) string {
	w := 0
	for i, r := range s {
		if w >= n {
			return s[i:]
		}
		w += runewidth.RuneWidth(r)
	}
	return ""
}

// max returns the larger of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

