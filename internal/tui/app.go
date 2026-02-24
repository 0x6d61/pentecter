package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

const (
	defaultWidth  = 80
	defaultHeight = 24
)

var ansiStripRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// App is the terminal UI application.
// It uses append-only terminal output and line-based input.
type App struct {
	// Target management
	targets  []*agent.Target
	selected int

	// Agent connection (nil = standalone mode)
	team            *agent.Team
	agentEvents     <-chan agent.Event
	agentApproveMap map[int]chan<- bool
	agentUserMsgMap map[int]chan<- string

	// Shared state
	mu            sync.Mutex
	writeMu       sync.Mutex
	spinnerActive atomic.Bool
	spinnerIdx    atomic.Int32

	// Input state
	inputMode   InputMode
	selectTitle string
	selectOpts  []SelectOption
	selectIdx   int
	selectCb    func(a *App, value string)

	// Display state
	logsExpanded     bool
	thinkingExpanded bool
	outputVersion    uint64
	renderedLines    []string

	width  int
	height int

	// Spinner animation frames
	spinnerFrames []string

	// Global logs (shown when no target selected)
	globalLogs []string

	// External dependencies
	CurrentProvider string
	CurrentModel    string
	Runner          *tools.CommandRunner
	BrainFactory    func(brain.ConfigHint) (brain.Brain, error)

	// For tests
	testWriter io.Writer

	// Guard to avoid duplicate banner insertion.
	welcomePrinted bool
}

// NewApp creates a new App with the given initial targets.
func NewApp(targets []*agent.Target) *App {
	selected := -1
	if len(targets) > 0 {
		selected = 0
	}

	return &App{
		targets:          targets,
		selected:         selected,
		agentApproveMap:  make(map[int]chan<- bool),
		agentUserMsgMap:  make(map[int]chan<- string),
		spinnerFrames:    []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		thinkingExpanded: true,
		width:            defaultWidth,
		height:           defaultHeight,
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

// Run starts the terminal UI application.
func (a *App) Run(ctx context.Context) error {
	a.setupLayout()

	if a.agentEvents != nil {
		go a.consumeEvents(ctx)
	}
	go a.runSpinner(ctx)

	a.printWelcome()

	// In tests, avoid blocking on stdin.
	if a.testWriter != nil {
		<-ctx.Done()
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		a.writePrompt(a.buildPrompt())

		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("read input: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		if line == string(rune(0x0f)) { // Ctrl+O
			a.toggleFold()
			if err == io.EOF {
				return nil
			}
			continue
		}
		if line == string(rune(0x14)) { // Ctrl+T
			a.toggleThinkingFold()
			if err == io.EOF {
				return nil
			}
			continue
		}

		if quit := a.handleInputLine(line); quit {
			return nil
		}
		if err == io.EOF {
			return nil
		}
	}
}

func (a *App) writePrompt(prompt string) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_, _ = fmt.Fprint(a.writer(), prompt)
}

func (a *App) writeLines(lines []string) {
	if len(lines) == 0 {
		return
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	w := a.writer()
	for _, l := range lines {
		_, _ = fmt.Fprintln(w, l)
	}
}

func (a *App) commonPrefixLen(prev, next []string) int {
	n := len(prev)
	if len(next) < n {
		n = len(next)
	}
	i := 0
	for i < n && prev[i] == next[i] {
		i++
	}
	return i
}

func (a *App) currentSpinnerFrameLocked() string {
	if len(a.spinnerFrames) == 0 || !a.spinnerActive.Load() {
		return ""
	}
	idx := int(a.spinnerIdx.Load()) % len(a.spinnerFrames)
	if idx < 0 {
		idx = 0
	}
	return a.spinnerFrames[idx]
}

func (a *App) buildOutputLinesLocked(width int) []string {
	lines := make([]string, 0, 128)
	t := a.activeTargetLocked()

	if t == nil {
		if len(a.globalLogs) == 0 {
			lines = append(lines, "PENTECTER")
			lines = append(lines, "Autonomous Penetration Testing Agent")
		} else {
			lines = append(lines, a.globalLogs...)
		}
	} else {
		blocks := make([]*agent.DisplayBlock, len(t.Blocks))
		copy(blocks, t.Blocks)

		rendered := renderBlocks(blocks, width, a.logsExpanded, a.thinkingExpanded, a.currentSpinnerFrameLocked())
		rendered = ansiStripRegex.ReplaceAllString(rendered, "")
		rendered = strings.TrimSuffix(rendered, "\n")
		if rendered != "" {
			lines = append(lines, strings.Split(rendered, "\n")...)
		}

		if p := t.GetProposal(); p != nil {
			lines = append(lines, "")
			lines = append(lines, a.proposalLinesLocked(p)...)
		}
	}

	if a.inputMode == ModeSelect && len(a.selectOpts) > 0 {
		lines = append(lines, "")
		lines = append(lines, a.selectLinesLocked()...)
	}

	if len(lines) == 0 {
		lines = append(lines, "")
	}
	return lines
}

func (a *App) clearAndReprint() {
	a.setupLayout()

	a.mu.Lock()
	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	lines := a.buildOutputLinesLocked(width)
	prev := cloneStrings(a.renderedLines)
	a.renderedLines = cloneStrings(lines)
	a.mu.Unlock()

	start := a.commonPrefixLen(prev, lines)
	if start >= len(lines) {
		return
	}
	a.writeLines(lines[start:])
}

func (a *App) proposalLinesLocked(p *agent.Proposal) []string {
	lines := []string{
		"PROPOSAL - Awaiting approval",
		"  " + p.Description,
		"  Tool: " + p.Tool + " " + strings.Join(p.Args, " "),
		"  [y] Approve  [n] Reject  [e] Edit",
	}
	return lines
}

func (a *App) selectLinesLocked() []string {
	lines := []string{a.selectTitle}
	for i, opt := range a.selectOpts {
		lines = append(lines, fmt.Sprintf("  %d. %s", i+1, opt.Label))
	}
	lines = append(lines, fmt.Sprintf("  [1-%d/q]", len(a.selectOpts)))
	return lines
}

func (a *App) modeHintLocked() string {
	switch a.inputMode {
	case ModeProposal:
		return "approve? [y/n/e]"
	case ModeSelect:
		if len(a.selectOpts) > 0 {
			return fmt.Sprintf("select [1-%d/q]", len(a.selectOpts))
		}
	case ModeConfirmQuit:
		return "Quit Pentecter? [y/n]"
	}
	return ""
}

// activeTarget returns the currently selected target, or nil if none.
func (a *App) activeTarget() *agent.Target {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activeTargetLocked()
}

// activeTargetLocked returns the currently selected target, or nil if none.
// Must be called with a.mu held.
func (a *App) activeTargetLocked() *agent.Target {
	if a.selected < 0 || a.selected >= len(a.targets) {
		return nil
	}
	return a.targets[a.selected]
}

// targetByID finds a target by its ID.
func (a *App) targetByID(id int) *agent.Target {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.targetByIDLocked(id)
}

// targetByIDLocked finds a target by its ID.
// Must be called with a.mu held.
func (a *App) targetByIDLocked(id int) *agent.Target {
	for _, t := range a.targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (a *App) invalidateOutputCacheLocked() {
	a.outputVersion++
}

// buildPrompt returns the current prompt string.
func (a *App) buildPrompt() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	hint := a.modeHintLocked()
	if hint == "" {
		return "> "
	}
	return hint + " > "
}

// buildStatusText returns the status line text.
func (a *App) buildStatusText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buildStatusTextLocked()
}

func (a *App) buildStatusTextLocked() string {
	var parts []string

	if t := a.activeTargetLocked(); t != nil {
		parts = append(parts, fmt.Sprintf("%s [%s]", t.Host, t.GetStatus()))
	}
	if a.CurrentModel != "" {
		parts = append(parts, a.CurrentProvider+"/"+a.CurrentModel)
	}

	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, "  ")
}

// refreshPrompt is a compatibility no-op for line-mode input.
func (a *App) refreshPrompt() {}

// clearPromptEcho is a compatibility no-op for line-mode input.
func (a *App) clearPromptEcho(string) {}

// promptEchoLines is a compatibility helper used by tests.
func (a *App) promptEchoLines(typedText string) int {
	prompt := a.buildPrompt()
	if typedText == "" {
		return 1
	}
	return len(strings.Split(prompt+typedText, "\n"))
}

// setupLayout updates cached terminal dimensions.
func (a *App) setupLayout() {
	w, h := a.getTerminalSize()
	a.mu.Lock()
	a.width = w
	a.height = h
	a.mu.Unlock()
}

// getTerminalSize returns the current terminal width and height.
func (a *App) getTerminalSize() (int, int) {
	if a.testWriter != nil {
		return defaultWidth, defaultHeight
	}

	fd := int(os.Stdout.Fd())
	w, h, err := term.GetSize(fd)
	if err != nil || w <= 0 || h <= 0 {
		return defaultWidth, defaultHeight
	}
	return w, h
}

// writer returns a test writer if configured; otherwise stdout.
func (a *App) writer() io.Writer {
	if a.testWriter != nil {
		return a.testWriter
	}
	return os.Stdout
}

// logSystem adds a system message to the active target or global logs.
func (a *App) logSystem(msg string) {
	a.mu.Lock()
	if t := a.activeTargetLocked(); t != nil {
		t.AddBlock(agent.NewSystemBlock(msg))
	} else {
		a.globalLogs = append(a.globalLogs, msg)
	}
	a.invalidateOutputCacheLocked()
	a.mu.Unlock()

	a.clearAndReprint()
}

// printWelcome stores the initial welcome banner.
func (a *App) printWelcome() {
	a.mu.Lock()
	if a.welcomePrinted {
		a.mu.Unlock()
		return
	}
	a.welcomePrinted = true

	lines := []string{
		"PENTECTER - Autonomous Penetration Testing Agent",
	}
	if len(a.targets) == 0 {
		lines = append(lines,
			"Enter an IP address or domain to begin (e.g. 10.0.0.5, example.com)",
		)
	} else {
		for _, t := range a.targets {
			lines = append(lines, fmt.Sprintf("Target: %s [%s]", t.Host, t.GetStatus()))
		}
	}
	lines = append(lines,
		"Input: ip/domain or /target HOST",
		"Commands: /targets, /model, /attackdata, /skip-recon, /fold, /status",
		"Keys: Ctrl+O toggle tool output, Ctrl+T toggle thinking blocks",
	)
	if a.CurrentModel != "" {
		lines = append(lines, fmt.Sprintf("Model: %s/%s", a.CurrentProvider, a.CurrentModel))
	}

	a.globalLogs = append(a.globalLogs, lines...)
	a.invalidateOutputCacheLocked()
	a.mu.Unlock()

	a.clearAndReprint()
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func displayWidth(s string) int {
	return runewidth.StringWidth(s)
}

// resetMultiline is kept for compatibility with legacy tests.
func (a *App) resetMultiline() {}

// sleepSmall is used by tests to wait for asynchronous writes.
func sleepSmall() {
	time.Sleep(20 * time.Millisecond)
}
