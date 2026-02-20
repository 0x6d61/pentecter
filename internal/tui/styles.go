package tui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	colorPrimary      = lipgloss.Color("#00D7FF") // cyan  — focus / AI
	colorSecondary    = lipgloss.Color("#AF87FF") // purple — AI source label
	colorSuccess      = lipgloss.Color("#87FF5F") // green — PWNED / USER
	colorWarning      = lipgloss.Color("#FFD700") // yellow — PAUSED / proposal
	colorDanger       = lipgloss.Color("#FF5555") // red — FAILED
	colorMuted        = lipgloss.Color("#555577") // dim gray — timestamps / hints
	colorBorder       = lipgloss.Color("#333355") // default border
	colorBorderActive = lipgloss.Color("#00D7FF") // focused border
)

// Pane borders
var (
	rightPaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	rightPaneActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorBorderActive)
)

// Input bar
var (
	inputBarStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	inputBarActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorBorderActive)
)

// Status bar (top)
var statusBarStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("#0D0D1A")).
	Foreground(colorPrimary).
	Padding(0, 1)

// Proposal box (rendered inside viewport)
var proposalBoxStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(colorWarning).
	Padding(0, 1)

// Quit confirmation dialog (centered overlay)
var confirmQuitBoxStyle = lipgloss.NewStyle().
	Border(lipgloss.DoubleBorder()).
	BorderForeground(colorDanger).
	Padding(0, 2)


// foldIndicatorStyle は折りたたみ行の「⋯ +N Lines (Ctrl+O)」スタイル。
var foldIndicatorStyle = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)

// User input block style — ハイライト背景でユーザー入力を目立たせる
var userInputBlockStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("#1A1A2E")).
	Foreground(colorSuccess).
	Bold(true).
	Padding(0, 1)
