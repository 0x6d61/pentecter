package tui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	colorPrimary      = lipgloss.Color("#00D7FF") // cyan  — focus / AI
	colorSecondary    = lipgloss.Color("#AF87FF") // purple — AI source label
	colorSuccess      = lipgloss.Color("#87FF5F") // green — PWNED / USER
	colorWarning      = lipgloss.Color("#FFD700") // yellow — PAUSED / proposal
	colorDanger       = lipgloss.Color("#FF5555") // red — FAILED
	colorMuted = lipgloss.Color("#555577") // dim gray — timestamps / hints
)

// Output style for command output lines
var outputStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))

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

// foldIndicatorStyle は折りたたみ行の「⋯ +N Lines (Ctrl+O)」スタイル。
var foldIndicatorStyle = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)

// User input block style — 灰背景・白文字でユーザー入力を目立たせる
var userInputBlockStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("#333344")).
	Foreground(lipgloss.Color("#FFFFFF")).
	Bold(true).
	Padding(0, 1)

// Select box style — Proposal と同パターンの角丸ボーダー
var selectBoxStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(colorPrimary).
	Padding(0, 1)

// Recon tree box style — 偵察ツリー表示用
var reconBoxStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(colorPrimary).
	Padding(0, 1)
