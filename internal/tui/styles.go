package tui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	colorPrimary      = lipgloss.Color("#00D7FF") // cyan  — focus / AI
	colorSecondary    = lipgloss.Color("#AF87FF") // purple — AI source label
	colorSuccess      = lipgloss.Color("#87FF5F") // green — PWNED / USER
	colorWarning      = lipgloss.Color("#FFD700") // yellow — PAUSED / proposal
	colorMuted = lipgloss.Color("#555577") // dim gray — timestamps / hints
)

// foldIndicatorStyle は折りたたみ行の「⋯ +N Lines (Ctrl+O)」スタイル。
var foldIndicatorStyle = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)

// User input block style — 灰背景・白文字でユーザー入力を目立たせる
var userInputBlockStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("#333344")).
	Foreground(lipgloss.Color("#FFFFFF")).
	Bold(true).
	Padding(0, 1)

