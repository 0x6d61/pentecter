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
	colorTitle        = lipgloss.Color("#FFFFFF") // pane titles
)

// Pane borders
var (
	leftPaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	leftPaneActiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorBorderActive)

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

// Log source label styles
var (
	sourceAIStyle   = lipgloss.NewStyle().Foreground(colorSecondary).Bold(true)
	sourceToolStyle = lipgloss.NewStyle().Foreground(colorPrimary).Bold(true)
	sourceSysStyle  = lipgloss.NewStyle().Foreground(colorMuted)
	sourceUserStyle = lipgloss.NewStyle().Foreground(colorSuccess).Bold(true)
)

// Status icon color styles
var (
	statusIdleStyle     = lipgloss.NewStyle().Foreground(colorMuted)
	statusScanningStyle = lipgloss.NewStyle().Foreground(colorWarning)
	statusRunningStyle  = lipgloss.NewStyle().Foreground(colorPrimary)
	statusPausedStyle   = lipgloss.NewStyle().Foreground(colorWarning).Bold(true)
	statusPwnedStyle    = lipgloss.NewStyle().Foreground(colorSuccess).Bold(true)
	statusFailedStyle   = lipgloss.NewStyle().Foreground(colorDanger).Bold(true)
)

// Turn separator and command result styles
var (
	turnSeparatorStyle = lipgloss.NewStyle().
				Foreground(colorMuted).
				Bold(true)

	commandSuccessStyle = lipgloss.NewStyle().
				Foreground(colorSuccess)

	commandFailStyle = lipgloss.NewStyle().
				Foreground(colorDanger).
				Bold(true)
)
