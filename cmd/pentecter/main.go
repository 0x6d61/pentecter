package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/tui"
)

func main() {
	m := tui.New()
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Pentecter エラー: %v\n", err)
		os.Exit(1)
	}
}
