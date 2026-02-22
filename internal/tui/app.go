package tui

import (
	"context"
	"fmt"
	"io"
	"strings"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/ergochat/readline"
	"golang.org/x/term"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

// App is the hybrid terminal UI application.
// Output goes directly to stdout (terminal scrolls), while readline manages input.
// This architecture completely separates input from output, preventing event floods
// from blocking keyboard input.
// The input area is fixed at the terminal bottom with simple horizontal dividers
// (Claude Code style). Output scrolls naturally above the input frame.
type App struct {
	// Terminal
	rl     *readline.Instance
	width  int
	height int

	// Target management
	targets  []*agent.Target
	selected int

	// Agent connection (nil = standalone mode)
	team            *agent.Team
	agentEvents     <-chan agent.Event
	agentApproveMap map[int]chan<- bool
	agentUserMsgMap map[int]chan<- string

	// Thread safety — protects targets, selected, blocks
	mu            sync.Mutex
	spinnerActive atomic.Bool
	spinnerIdx    atomic.Int32

	// Input state
	inputMode   InputMode
	selectTitle string
	selectOpts  []SelectOption
	selectIdx   int
	selectCb    func(a *App, value string)

	// Display state
	logsExpanded bool

	// Multiline input (Ctrl+N to insert newline, Enter to submit all lines)
	multilineBuffer []string // accumulated lines (excluding current line)
	multilineMode   bool     // true while continuation prompt is shown
	lastLineBuf     string   // buffer snapshot from previous Listener call

	// Spinner animation frames (Braille dots)
	spinnerFrames []string

	// Global logs (shown when no target selected)
	globalLogs []string

	// External dependencies
	CurrentProvider string
	CurrentModel    string
	Runner          *tools.CommandRunner
	BrainFactory    func(brain.ConfigHint) (brain.Brain, error)

	// For testing: override stdout writer (nil = use rl.Stdout())
	testWriter io.Writer

	// outputMu protects direct os.Stdout writes for cursor manipulation
	// (overwriteOutputLine, setupLayout). Does NOT protect rl.Stdout() writes.
	outputMu sync.Mutex
}

// NewApp creates a new App with the given initial targets.
func NewApp(targets []*agent.Target) *App {
	return &App{
		targets:         targets,
		agentApproveMap: make(map[int]chan<- bool),
		agentUserMsgMap: make(map[int]chan<- string),
		spinnerFrames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
}

// ConnectTeam connects the App to an Agent Team for bidirectional communication.
func (a *App) ConnectTeam(
	team *agent.Team,
	events <-chan agent.Event,
	approveMap map[int]chan<- bool,
	userMsgMap map[int]chan<- string,
) {
	a.team = team
	a.agentEvents = events
	for k, v := range approveMap {
		a.agentApproveMap[k] = v
	}
	for k, v := range userMsgMap {
		a.agentUserMsgMap[k] = v
	}
}

// Run starts the TUI application. Blocks until the user quits or ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg := &readline.Config{
		Prompt:          a.buildPrompt(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		Listener: func(line []rune, pos int, key rune) ([]rune, int, bool) {
			switch key {
			case 0x0F: // Ctrl+O — toggle log folding
				go a.toggleFold()
				return line, pos, false

			case readline.CharNext: // Ctrl+N — insert newline (multiline input)
				if a.inputMode != ModeNormal {
					return line, pos, false
				}
				saved := a.lastLineBuf
				a.multilineBuffer = append(a.multilineBuffer, saved)
				a.multilineMode = true
				go func() {
					w := a.writer()
					prefix := "> "
					if len(a.multilineBuffer) > 1 {
						prefix = "... "
					}
					_, _ = fmt.Fprintln(w, lipgloss.NewStyle().Foreground(colorMuted).Render(prefix+saved))
					a.rl.SetPrompt("... ")
					a.rl.Refresh()
				}()
				return []rune{}, 0, true // clear buffer (overwrite history.Next result)

			case readline.CharBackspace, readline.CharCtrlH: // Backspace
				if pos == 0 && len(line) == 0 && a.multilineMode && len(a.multilineBuffer) > 0 {
					popped := a.multilineBuffer[len(a.multilineBuffer)-1]
					a.multilineBuffer = a.multilineBuffer[:len(a.multilineBuffer)-1]
					if len(a.multilineBuffer) == 0 {
						a.multilineMode = false
					}
					go func() {
						// Erase frozen line above
						if a.testWriter == nil {
							a.outputMu.Lock()
							_, _ = fmt.Fprint(os.Stdout, "\033[1A\033[2K")
							a.outputMu.Unlock()
						}
						if a.multilineMode {
							a.rl.SetPrompt("... ")
						} else {
							a.rl.SetPrompt(a.buildPrompt())
						}
						a.rl.Refresh()
					}()
					poppedRunes := []rune(popped)
					return poppedRunes, len(poppedRunes), true
				}
				a.lastLineBuf = string(line)
				return line, pos, false // let readline handle normal backspace

			default:
				a.lastLineBuf = string(line)
				return line, pos, true
			}
		},
	}

	rl, err := readline.NewFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	a.rl = rl
	defer func() {
		_ = rl.Close()
	}()

	// Setup terminal layout (clear, fill, position input at bottom)
	a.setupLayout()

	// Start background goroutines
	if a.agentEvents != nil {
		go a.consumeEvents(ctx)
	}
	go a.runSpinner(ctx)
	go a.pollResize(ctx)

	// Print welcome banner
	a.printWelcome()

	// Main readline loop (blocking — input-only goroutine)
	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if a.multilineMode {
					a.resetMultiline()
					a.refreshPrompt()
					continue
				}
				if a.inputMode == ModeConfirmQuit {
					return nil // second Ctrl+C → force quit
				}
				a.inputMode = ModeConfirmQuit
				a.clearPromptEcho(line)
				a.refreshPrompt()
				continue
			}
			if err == io.EOF {
				return nil // Ctrl+D
			}
			return err
		}

		var fullText string
		if a.multilineMode {
			// Clear readline echo BEFORE resetting (buildPrompt needs multilineMode)
			a.clearPromptEcho(line)
			a.multilineBuffer = append(a.multilineBuffer, line)
			fullText = strings.Join(a.multilineBuffer, "\n")
			a.resetMultiline()
			a.rl.SetPrompt(a.buildPrompt())
		} else {
			a.clearPromptEcho(line)
			fullText = line
		}

		if a.handleInputLine(fullText) {
			return nil // quit requested
		}
	}
}

// activeTarget returns the currently selected target, or nil if none.
func (a *App) activeTarget() *agent.Target {
	if a.selected < 0 || a.selected >= len(a.targets) {
		return nil
	}
	return a.targets[a.selected]
}

// resetMultiline clears all multiline input state.
func (a *App) resetMultiline() {
	a.multilineBuffer = nil
	a.multilineMode = false
	a.lastLineBuf = ""
}

// targetByID finds a target by its ID.
func (a *App) targetByID(id int) *agent.Target {
	for _, t := range a.targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// buildPrompt constructs the readline prompt string.
// All status info is embedded in the prompt so readline manages it automatically.
// Layout (with status):  \n + status + \n + [modeHint]>
// Layout (no status):    \n + [modeHint]>
func (a *App) buildPrompt() string {
	if a.multilineMode {
		return "... "
	}

	var modeHint string
	switch a.inputMode {
	case ModeProposal:
		modeHint = lipgloss.NewStyle().Foreground(colorWarning).Render("approve? [y/n/e] ")
	case ModeSelect:
		if len(a.selectOpts) > 0 {
			modeHint = lipgloss.NewStyle().Foreground(colorWarning).Render(
				fmt.Sprintf("select [1-%d/q] ", len(a.selectOpts)))
		}
	case ModeConfirmQuit:
		modeHint = lipgloss.NewStyle().Foreground(colorDanger).Render("Quit Pentecter? [y/n] ")
	}

	promptChar := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render(">")

	return "\n" + modeHint + promptChar + " "
}

// buildStatusText returns the status line text shown below the input frame.
func (a *App) buildStatusText() string {
	var parts []string

	if t := a.activeTarget(); t != nil {
		host := lipgloss.NewStyle().Foreground(colorWarning).Render(t.Host)
		parts = append(parts, fmt.Sprintf("%s [%s]", host, t.GetStatus()))
	}

	if a.CurrentModel != "" {
		model := lipgloss.NewStyle().Foreground(colorMuted).Render(
			a.CurrentProvider + "/" + a.CurrentModel)
		parts = append(parts, model)
	}

	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, "  ")
}

// refreshPrompt updates the readline prompt to reflect current state.
func (a *App) refreshPrompt() {
	if a.rl == nil {
		return
	}
	prompt := a.buildPrompt()
	a.rl.SetPrompt(prompt)
	a.rl.Refresh()
}

// clearPromptEcho erases the readline-echoed prompt (P1) from the terminal.
// Dynamically calculates terminal lines based on prompt content + typed text width.
func (a *App) clearPromptEcho(typedText string) {
	if a.testWriter != nil {
		return
	}
	n := a.promptEchoLines(typedText)
	if n <= 0 {
		return
	}
	a.outputMu.Lock()
	_, _ = fmt.Fprintf(os.Stdout, "\033[%dA\033[J", n)
	a.outputMu.Unlock()
}

// promptEchoLines calculates how many terminal lines the prompt + typed text occupied.
// Prompt is 2 lines without status ("\n" + "> "), or 3 lines with status ("\n" + status + "\n" + "> ").
// The typed text is appended to the last line by readline.
// Uses lipgloss.Width() to correctly handle ANSI escapes and CJK character widths.
func (a *App) promptEchoLines(typedText string) int {
	w := a.width
	if w < 20 {
		w = 80
	}

	prompt := a.buildPrompt()
	// prompt = "\n───────\n[modeHint]> "
	// Split into all lines
	lines := strings.Split(prompt, "\n")

	total := 0
	for i, l := range lines {
		content := l
		if i == len(lines)-1 {
			// Last line: append typed text for wrap calculation
			content = l + typedText
		}
		vw := lipgloss.Width(content)
		if vw == 0 {
			total++
		} else {
			total += (vw-1)/w + 1 // ceil(vw / w)
		}
	}

	return total
}

// setupLayout initializes the terminal layout.
func (a *App) setupLayout() {
	if a.testWriter != nil {
		// Test mode: set default dimensions without terminal access
		if a.width == 0 {
			a.width = 80
		}
		if a.height == 0 {
			a.height = 24
		}
		return
	}

	w, h := a.getTerminalSize()
	a.width = w
	a.height = h

	// Clear screen and move cursor to home
	_, _ = fmt.Fprint(os.Stdout, "\033[2J\033[H")
}

// getTerminalSize returns the current terminal width and height.
func (a *App) getTerminalSize() (int, int) {
	fd := int(os.Stdout.Fd())
	w, h, err := term.GetSize(fd)
	if err != nil || w <= 0 {
		w = 80
	}
	if err != nil || h <= 0 {
		h = 24
	}
	return w, h
}

// pollResize polls terminal size changes (Windows has no SIGWINCH).
func (a *App) pollResize(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w, h := a.getTerminalSize()
			a.mu.Lock()
			changed := false
			if w != a.width && w > 0 {
				a.width = w
				changed = true
			}
			if h != a.height && h > 0 {
				a.height = h
				changed = true
			}
			a.mu.Unlock()
			if changed {
				a.refreshPrompt()
			}
		}
	}
}

// writer returns the safe stdout writer for concurrent output.
func (a *App) writer() io.Writer {
	if a.testWriter != nil {
		return a.testWriter
	}
	if a.rl != nil {
		return a.rl.Stdout()
	}
	return os.Stdout
}

// logSystem adds a system message to the active target or global logs and prints it.
func (a *App) logSystem(msg string) {
	w := a.writer()
	if t := a.activeTarget(); t != nil {
		block := agent.NewSystemBlock(msg)
		a.mu.Lock()
		t.AddBlock(block)
		a.mu.Unlock()
		_, _ = fmt.Fprint(w, renderSystemBlock(block))
	} else {
		a.globalLogs = append(a.globalLogs, msg)
		_, _ = fmt.Fprintln(w, lipgloss.NewStyle().Foreground(colorMuted).Render(msg))
	}
}

// printWelcome displays the initial welcome banner.
func (a *App) printWelcome() {
	w := a.writer()
	banner := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("⚡ PENTECTER")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "  "+banner+" — Autonomous Penetration Testing Agent")
	_, _ = fmt.Fprintln(w, "")
	if len(a.targets) == 0 {
		_, _ = fmt.Fprintln(w, lipgloss.NewStyle().Foreground(colorMuted).Render(
			"  Enter an IP address or domain to begin (e.g. 10.0.0.5, example.com)"))
		_, _ = fmt.Fprintln(w, lipgloss.NewStyle().Foreground(colorMuted).Render(
			"  Commands: /targets, /model, /approve, /recontree, /skip-recon"))
	} else {
		for _, t := range a.targets {
			_, _ = fmt.Fprintf(w, "  Target: %s [%s]\n",
				lipgloss.NewStyle().Foreground(colorWarning).Render(t.Host),
				t.GetStatus())
		}
	}
	if a.CurrentModel != "" {
		_, _ = fmt.Fprintln(w, lipgloss.NewStyle().Foreground(colorMuted).Render(
			fmt.Sprintf("  Model: %s/%s", a.CurrentProvider, a.CurrentModel)))
	}
	_, _ = fmt.Fprintln(w, "")
}
