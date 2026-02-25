package tui

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/mattn/go-runewidth"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

const (
	defaultWidth         = 80
	defaultHeight        = 24
	uiFrameInterval      = time.Second / 30
	uiEventProcessBudget = 4 * time.Millisecond
	uiEventProcessMax    = 256
)

var ansiStripRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

type uiEventType int

const (
	uiEventAgent uiEventType = iota
	uiEventSpinnerTick
)

type uiEventMsg struct {
	kind  uiEventType
	agent agent.Event
}

type outputLineKind int

const (
	outputLineDefault outputLineKind = iota
	outputLineSpinner
	outputLineUser
)

type outputLine struct {
	text string
	kind outputLineKind
}

type deferredDrawWake struct{}

// App is the terminal UI application.
// Rendering and input handling are serialized in a single tcell event loop.
type App struct {
	// Terminal
	screen tcell.Screen
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

	// Shared state (tests can call methods directly outside Run)
	mu               sync.Mutex
	spinnerActive    atomic.Bool
	spinnerIdx       atomic.Int32
	interruptPending atomic.Bool
	drawTimerPending atomic.Bool

	// Input state
	inputMode   InputMode
	selectTitle string
	selectOpts  []SelectOption
	selectIdx   int
	selectCb    func(a *App, value string)

	// Copy mode state (line-based selection over wrapped output lines).
	copyCursor   int
	copyAnchor   int
	copyLastYank string
	copyPrevMode InputMode

	// Display state
	logsExpanded bool
	outputScroll int  // number of lines scrolled up from bottom in output pane
	outputFollow bool // true = keep following the newest output line

	// When follow is disabled, keep the current viewport stable as new logs arrive.
	outputPrevWrapped   int
	outputPrevWrapWidth int

	// コマンド出力のダーティフラグ（EventCmdOutput のキャッシュ無効化をバッチ化）
	cmdOutputDirty bool

	// Output render cache to avoid full re-wrap on every keypress.
	outputVersion           uint64
	outputCacheVersion      uint64
	outputCacheWidth        int
	outputCacheSelected     int
	outputCacheInputMode    InputMode
	outputCacheLogsExpanded bool
	outputCacheSpinnerSig   int64
	outputCacheLines        []outputLine

	// Live input buffer for tcell-based editing
	inputLines []string
	cursorLine int
	cursorCol  int

	// Legacy multiline fields kept for compatibility with existing tests/helpers.
	multilineBuffer []string
	multilineMode   bool
	lastLineBuf     string
	typedInput      atomic.Value // current input line text (string)

	// Spinner animation frames
	spinnerFrames []string

	// Global logs (shown when no target selected)
	globalLogs []string

	// External dependencies
	CurrentProvider        string
	CurrentModel           string
	Runner                 *tools.CommandRunner
	BrainFactory           func(brain.ConfigHint) (brain.Brain, error)
	OpenRouterModelFetcher func(ctx context.Context) ([]brain.OpenRouterModel, error)

	// For tests: when set, state-change helpers may write textual output here.
	testWriter io.Writer

	// Internal event queue for the single UI loop.
	uiEvents chan uiEventMsg

	// Guard to avoid duplicate banner insertion.
	welcomePrinted bool
}

// NewApp creates a new App with the given initial targets.
func NewApp(targets []*agent.Target) *App {
	selected := -1
	if len(targets) > 0 {
		selected = 0
	}

	a := &App{
		targets:         targets,
		selected:        selected,
		agentApproveMap: make(map[int]chan<- bool),
		agentUserMsgMap: make(map[int]chan<- string),
		spinnerFrames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		inputLines:      []string{""},
		uiEvents:        make(chan uiEventMsg, 1024),
		outputFollow:    true,
		copyAnchor:      -1,
		copyPrevMode:    ModeNormal,
	}
	a.typedInput.Store("")
	return a
}

// SetScreen injects a screen instance (used by tests with simulation screen).
func (a *App) SetScreen(s tcell.Screen) {
	a.mu.Lock()
	a.screen = s
	a.mu.Unlock()
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

	a.mu.Lock()
	s := a.screen
	if s == nil {
		var err error
		s, err = tcell.NewScreen()
		if err != nil {
			a.mu.Unlock()
			return fmt.Errorf("tcell new screen: %w", err)
		}
		a.screen = s
	}
	a.ensureInputBufferLocked()
	a.setupLayout()
	a.mu.Unlock()

	if err := s.Init(); err != nil {
		return fmt.Errorf("tcell init: %w", err)
	}
	defer func() {
		s.Fini()
		a.mu.Lock()
		a.screen = nil
		a.mu.Unlock()
	}()

	s.SetStyle(tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorBlack))
	s.Clear()
	s.EnableMouse()

	if a.agentEvents != nil {
		go a.consumeEvents(ctx)
	}
	go a.runSpinner(ctx)
	go func() {
		<-ctx.Done()
		a.mu.Lock()
		s := a.screen
		a.mu.Unlock()
		if s != nil {
			_ = s.PostEvent(tcell.NewEventInterrupt(nil))
		}
	}()

	a.printWelcome()
	a.draw()
	lastDrawAt := time.Now()

	for {
		ev := s.PollEvent()
		switch tev := ev.(type) {
		case *tcell.EventResize:
			s.Sync()
			a.setupLayout()
			a.draw()
			lastDrawAt = time.Now()

		case *tcell.EventInterrupt:
			if _, ok := tev.Data().(deferredDrawWake); ok {
				a.draw()
				lastDrawAt = time.Now()
				break
			}

			processed := a.processUIEvents()
			if !processed {
				break
			}

			now := time.Now()
			elapsed := now.Sub(lastDrawAt)
			if elapsed >= uiFrameInterval {
				a.draw()
				lastDrawAt = now
			} else {
				a.scheduleDeferredDraw(uiFrameInterval - elapsed)
			}

		case *tcell.EventKey:
			if a.handleKeyEvent(tev) {
				return nil
			}
			a.draw()
			lastDrawAt = time.Now()

		case *tcell.EventMouse:
			if a.handleMouseEvent(tev) {
				a.draw()
				lastDrawAt = time.Now()
			}
		}

		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

func (a *App) enqueueUIEvent(msg uiEventMsg) {
	a.mu.Lock()
	ch := a.uiEvents
	a.mu.Unlock()

	if ch == nil {
		return
	}

	select {
	case ch <- msg:
	default:
		// Keep UI responsive under floods: drop oldest queued item.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- msg:
		default:
		}
	}

	a.requestUIInterrupt()
}

func (a *App) processUIEvents() bool {
	// Release the interrupt gate first so producers can schedule the next wakeup.
	a.interruptPending.Store(false)

	a.mu.Lock()
	ch := a.uiEvents
	a.mu.Unlock()
	if ch == nil {
		return false
	}

	processed := false
	start := time.Now()
	processedCount := 0
	for {
		select {
		case msg := <-ch:
			processed = true
			processedCount++
			switch msg.kind {
			case uiEventAgent:
				a.handleAgentEvent(msg.agent)
			case uiEventSpinnerTick:
				if a.spinnerActive.Load() {
					a.spinnerIdx.Add(1)
				}
				// コマンド出力のダーティフラグをフラッシュ（バッチ化された再描画）
				a.mu.Lock()
				if a.cmdOutputDirty {
					a.invalidateOutputCacheLocked()
					a.cmdOutputDirty = false
				}
				a.mu.Unlock()
			}
			if processedCount >= uiEventProcessMax || (processedCount%16 == 0 && time.Since(start) >= uiEventProcessBudget) {
				if len(ch) > 0 {
					a.requestUIInterrupt()
				}
				return processed
			}
		default:
			return processed
		}
	}
}

func (a *App) requestUIInterrupt() {
	a.mu.Lock()
	s := a.screen
	a.mu.Unlock()

	if s != nil && a.interruptPending.CompareAndSwap(false, true) {
		_ = s.PostEvent(tcell.NewEventInterrupt(nil))
	}
}

func (a *App) scheduleDeferredDraw(delay time.Duration) {
	if delay <= 0 {
		delay = time.Millisecond
	}
	if !a.drawTimerPending.CompareAndSwap(false, true) {
		return
	}

	time.AfterFunc(delay, func() {
		a.drawTimerPending.Store(false)
		a.mu.Lock()
		s := a.screen
		a.mu.Unlock()
		if s != nil {
			_ = s.PostEvent(tcell.NewEventInterrupt(deferredDrawWake{}))
		}
	})
}

func isCtrlEnter(e *tcell.EventKey) bool {
	if e.Key() == tcell.KeyCtrlJ {
		return true
	}
	return e.Key() == tcell.KeyEnter && (e.Modifiers()&tcell.ModCtrl) != 0
}

func (a *App) handleKeyEvent(e *tcell.EventKey) bool {
	var submitText *string

	a.mu.Lock()
	a.ensureInputBufferLocked()

	switch e.Key() {
	case tcell.KeyCtrlO:
		a.logsExpanded = !a.logsExpanded
		a.syncLegacyInputStateLocked()
		a.mu.Unlock()
		return false

	case tcell.KeyCtrlY:
		if a.inputMode == ModeCopy {
			a.yankCopySelectionLocked()
			a.exitCopyModeLocked()
		} else {
			a.enterCopyModeLocked()
		}
		a.syncLegacyInputStateLocked()
		a.mu.Unlock()
		return false

	case tcell.KeyCtrlC:
		if a.inputMode == ModeConfirmQuit {
			a.mu.Unlock()
			return true
		}
		a.inputMode = ModeConfirmQuit
		a.clearInputLocked()
		a.syncLegacyInputStateLocked()
		a.mu.Unlock()
		return false

	case tcell.KeyCtrlD:
		if a.isInputEmptyLocked() {
			a.mu.Unlock()
			return true
		}
	}

	if a.inputMode == ModeCopy {
		a.handleCopyModeKeyLocked(e)
		a.syncLegacyInputStateLocked()
		a.mu.Unlock()
		return false
	}

	switch e.Key() {
	case tcell.KeyEnter:
		if a.inputMode == ModeNormal && isCtrlEnter(e) {
			a.insertNewlineLocked()
		} else {
			text := strings.Join(a.inputLines, "\n")
			if len(a.inputLines) == 1 {
				text = a.inputLines[0]
			}
			a.clearInputLocked()
			submitText = &text
		}

	case tcell.KeyCtrlJ:
		if a.inputMode == ModeNormal {
			a.insertNewlineLocked()
		}

	case tcell.KeyCtrlN:
		if a.inputMode == ModeNormal {
			a.insertNewlineLocked()
		}

	case tcell.KeyBackspace, tcell.KeyBackspace2:
		a.backspaceLocked()

	case tcell.KeyDelete:
		a.deleteForwardLocked()

	case tcell.KeyLeft:
		a.moveLeftLocked()

	case tcell.KeyRight:
		a.moveRightLocked()

	case tcell.KeyUp:
		a.moveUpLocked()

	case tcell.KeyDown:
		a.moveDownLocked()

	case tcell.KeyPgUp:
		a.scrollOutputLocked(a.outputPageStepLocked())

	case tcell.KeyPgDn:
		a.scrollOutputLocked(-a.outputPageStepLocked())

	case tcell.KeyHome:
		if e.Modifiers()&tcell.ModCtrl != 0 {
			a.scrollOutputToTopLocked()
		} else {
			a.cursorCol = 0
		}

	case tcell.KeyEnd:
		if e.Modifiers()&tcell.ModCtrl != 0 {
			a.scrollOutputToBottomLocked()
		} else {
			a.cursorCol = runeLen(a.inputLines[a.cursorLine])
		}

	case tcell.KeyRune:
		if e.Modifiers()&tcell.ModCtrl == 0 {
			a.insertRuneLocked(e.Rune())
		}
	}

	a.syncLegacyInputStateLocked()
	a.mu.Unlock()

	if submitText != nil {
		return a.handleInputLine(*submitText)
	}
	return false
}

func (a *App) handleMouseEvent(e *tcell.EventMouse) bool {
	buttons := e.Buttons()
	if buttons == 0 {
		return false
	}

	changed := false
	a.mu.Lock()
	beforeScroll := a.outputScroll
	beforeFollow := a.outputFollow
	switch {
	case buttons&tcell.WheelUp != 0:
		a.scrollOutputLocked(3)
	case buttons&tcell.WheelDown != 0:
		a.scrollOutputLocked(-3)
	}
	changed = a.outputScroll != beforeScroll || a.outputFollow != beforeFollow
	a.mu.Unlock()
	return changed
}

func (a *App) enterCopyModeLocked() {
	if a.inputMode == ModeCopy {
		return
	}
	a.copyPrevMode = a.inputMode
	a.inputMode = ModeCopy
	a.copyAnchor = -1

	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	lines := a.wrappedOutputLinesLocked(width)
	if len(lines) == 0 {
		a.copyCursor = 0
		a.outputScroll = 0
		a.outputFollow = true
		return
	}

	cursor := len(lines) - 1 - a.outputScroll
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= len(lines) {
		cursor = len(lines) - 1
	}
	a.copyCursor = cursor
	a.ensureCopyCursorVisibleLocked(len(lines))
}

func (a *App) exitCopyModeLocked() {
	if a.inputMode != ModeCopy {
		return
	}
	restoreMode := a.copyPrevMode
	if restoreMode == ModeCopy {
		restoreMode = ModeNormal
	}
	a.inputMode = restoreMode
	a.copyPrevMode = ModeNormal
	a.copyAnchor = -1
}

func (a *App) handleCopyModeKeyLocked(e *tcell.EventKey) {
	switch e.Key() {
	case tcell.KeyEscape:
		a.exitCopyModeLocked()
		return
	case tcell.KeyUp:
		a.moveCopyCursorLocked(-1)
		return
	case tcell.KeyDown:
		a.moveCopyCursorLocked(1)
		return
	case tcell.KeyPgUp:
		a.moveCopyCursorLocked(-a.outputPageStepLocked())
		return
	case tcell.KeyPgDn:
		a.moveCopyCursorLocked(a.outputPageStepLocked())
		return
	case tcell.KeyHome:
		a.copyCursor = 0
	case tcell.KeyEnd:
		width := a.width
		if width <= 0 {
			width = defaultWidth
		}
		lines := a.wrappedOutputLinesLocked(width)
		if len(lines) > 0 {
			a.copyCursor = len(lines) - 1
		}
	case tcell.KeyRune:
		switch strings.ToLower(string(e.Rune())) {
		case "q":
			a.exitCopyModeLocked()
			return
		case " ":
			if a.copyAnchor >= 0 {
				a.copyAnchor = -1
			} else {
				a.copyAnchor = a.copyCursor
			}
			return
		case "y":
			a.yankCopySelectionLocked()
			a.exitCopyModeLocked()
			return
		}
	default:
		return
	}

	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	lines := a.wrappedOutputLinesLocked(width)
	if len(lines) <= 0 {
		a.copyCursor = 0
		return
	}
	if a.copyCursor < 0 {
		a.copyCursor = 0
	}
	if a.copyCursor >= len(lines) {
		a.copyCursor = len(lines) - 1
	}
	a.ensureCopyCursorVisibleLocked(len(lines))
}

func (a *App) moveCopyCursorLocked(delta int) {
	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	lines := a.wrappedOutputLinesLocked(width)
	if len(lines) == 0 {
		a.copyCursor = 0
		return
	}

	a.copyCursor += delta
	if a.copyCursor < 0 {
		a.copyCursor = 0
	}
	if a.copyCursor >= len(lines) {
		a.copyCursor = len(lines) - 1
	}
	a.ensureCopyCursorVisibleLocked(len(lines))
}

func (a *App) yankCopySelectionLocked() {
	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	lines := a.wrappedOutputLinesLocked(width)
	start, end, ok := a.copySelectionBoundsLocked(len(lines))
	if !ok {
		msg := "Nothing to yank."
		if t := a.activeTargetLocked(); t != nil {
			t.AddBlock(agent.NewSystemBlock(msg))
		} else {
			a.globalLogs = append(a.globalLogs, msg)
		}
		a.invalidateOutputCacheLocked()
		return
	}

	buf := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		buf = append(buf, lines[i].text)
	}
	yanked := strings.Join(buf, "\n")
	a.copyLastYank = yanked
	if a.screen != nil {
		a.screen.SetClipboard([]byte(yanked))
	}

	msg := fmt.Sprintf("Yanked %d line(s) to clipboard (terminal support dependent).", end-start+1)
	if t := a.activeTargetLocked(); t != nil {
		t.AddBlock(agent.NewSystemBlock(msg))
	} else {
		a.globalLogs = append(a.globalLogs, msg)
	}
	a.invalidateOutputCacheLocked()
}

func (a *App) copySelectionBoundsLocked(total int) (int, int, bool) {
	if total <= 0 {
		return 0, 0, false
	}

	cursor := a.copyCursor
	if cursor < 0 {
		cursor = 0
	}
	if cursor >= total {
		cursor = total - 1
	}

	anchor := a.copyAnchor
	if anchor < 0 || anchor >= total {
		anchor = cursor
	}

	start := anchor
	end := cursor
	if start > end {
		start, end = end, start
	}
	return start, end, true
}

func (a *App) ensureCopyCursorVisibleLocked(totalLines int) {
	if totalLines <= 0 {
		a.outputScroll = 0
		a.outputFollow = true
		return
	}

	w := a.width
	if w <= 0 {
		w = defaultWidth
	}
	h := a.height
	if h <= 0 {
		h = defaultHeight
	}
	outputHeight := a.outputPaneHeightLocked(w, h)
	if outputHeight <= 0 {
		return
	}

	maxScroll := totalLines - outputHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if a.outputScroll < 0 {
		a.outputScroll = 0
	}
	if a.outputScroll > maxScroll {
		a.outputScroll = maxScroll
	}

	start, end := outputWindowRange(totalLines, outputHeight, a.outputScroll)
	if a.copyCursor < start {
		newStart := a.copyCursor
		if newStart < 0 {
			newStart = 0
		}
		newEnd := newStart + outputHeight
		if newEnd > totalLines {
			newEnd = totalLines
		}
		a.outputScroll = totalLines - newEnd
	} else if a.copyCursor >= end {
		newEnd := a.copyCursor + 1
		if newEnd > totalLines {
			newEnd = totalLines
		}
		a.outputScroll = totalLines - newEnd
	}

	if a.outputScroll < 0 {
		a.outputScroll = 0
	}
	if a.outputScroll > maxScroll {
		a.outputScroll = maxScroll
	}
	a.outputFollow = a.outputScroll == 0
}

func (a *App) outputPaneHeightLocked(width, height int) int {
	inputRows := a.inputRenderRowsLocked()
	maxInputRows := height - 2 // divider + status
	if maxInputRows < 1 {
		maxInputRows = 1
	}
	if len(inputRows) > maxInputRows {
		inputRows = inputRows[len(inputRows)-maxInputRows:]
	}

	reserved := 2 + len(inputRows) // divider + status + input rows
	if reserved > height {
		reserved = height
	}
	outputHeight := height - reserved
	if outputHeight < 0 {
		outputHeight = 0
	}
	return outputHeight
}

func (a *App) inputRenderRowsLocked() []inputRenderLine {
	inputLines := cloneStrings(a.inputLines)
	if len(inputLines) == 0 {
		inputLines = []string{""}
	}

	rows := make([]inputRenderLine, 0, len(inputLines)+1)
	if hint := a.modeHintLocked(); hint != "" {
		rows = append(rows, inputRenderLine{text: hint, logical: -1})
	}
	for i, l := range inputLines {
		prefix := ""
		if i == 0 {
			prefix = "> "
		}
		rows = append(rows, inputRenderLine{
			text:    prefix + l,
			logical: i,
			prefix:  prefix,
		})
	}
	return rows
}

func (a *App) ensureInputBufferLocked() {
	if len(a.inputLines) == 0 {
		a.inputLines = []string{""}
	}
	if a.cursorLine < 0 {
		a.cursorLine = 0
	}
	if a.cursorLine >= len(a.inputLines) {
		a.cursorLine = len(a.inputLines) - 1
	}
	maxCol := runeLen(a.inputLines[a.cursorLine])
	if a.cursorCol < 0 {
		a.cursorCol = 0
	}
	if a.cursorCol > maxCol {
		a.cursorCol = maxCol
	}
}

func (a *App) isInputEmptyLocked() bool {
	for _, l := range a.inputLines {
		if l != "" {
			return false
		}
	}
	return true
}

func (a *App) clearInputLocked() {
	a.inputLines = []string{""}
	a.cursorLine = 0
	a.cursorCol = 0
}

func (a *App) currentLineRunesLocked() []rune {
	return []rune(a.inputLines[a.cursorLine])
}

func (a *App) setCurrentLineRunesLocked(r []rune) {
	a.inputLines[a.cursorLine] = string(r)
}

func (a *App) insertRuneLocked(r rune) {
	line := a.currentLineRunesLocked()
	if a.cursorCol > len(line) {
		a.cursorCol = len(line)
	}
	next := make([]rune, 0, len(line)+1)
	next = append(next, line[:a.cursorCol]...)
	next = append(next, r)
	next = append(next, line[a.cursorCol:]...)
	a.setCurrentLineRunesLocked(next)
	a.cursorCol++
}

func (a *App) insertNewlineLocked() {
	line := a.currentLineRunesLocked()
	if a.cursorCol > len(line) {
		a.cursorCol = len(line)
	}

	left := string(line[:a.cursorCol])
	right := string(line[a.cursorCol:])
	a.inputLines[a.cursorLine] = left

	insertAt := a.cursorLine + 1
	a.inputLines = append(a.inputLines, "")
	copy(a.inputLines[insertAt+1:], a.inputLines[insertAt:])
	a.inputLines[insertAt] = right

	a.cursorLine = insertAt
	a.cursorCol = 0
}

func (a *App) backspaceLocked() {
	line := a.currentLineRunesLocked()
	if a.cursorCol > len(line) {
		a.cursorCol = len(line)
	}

	if a.cursorCol > 0 {
		next := make([]rune, 0, len(line)-1)
		next = append(next, line[:a.cursorCol-1]...)
		next = append(next, line[a.cursorCol:]...)
		a.setCurrentLineRunesLocked(next)
		a.cursorCol--
		return
	}

	if a.cursorLine == 0 {
		return
	}

	prevIdx := a.cursorLine - 1
	prev := []rune(a.inputLines[prevIdx])
	cur := []rune(a.inputLines[a.cursorLine])

	// Multiline behavior: at line head, move naturally to previous line.
	merged := append(prev, cur...)
	a.inputLines[prevIdx] = string(merged)
	a.inputLines = append(a.inputLines[:a.cursorLine], a.inputLines[a.cursorLine+1:]...)
	a.cursorLine = prevIdx
	a.cursorCol = len(prev)
}

func (a *App) deleteForwardLocked() {
	line := a.currentLineRunesLocked()
	if a.cursorCol > len(line) {
		a.cursorCol = len(line)
	}

	if a.cursorCol < len(line) {
		next := make([]rune, 0, len(line)-1)
		next = append(next, line[:a.cursorCol]...)
		next = append(next, line[a.cursorCol+1:]...)
		a.setCurrentLineRunesLocked(next)
		return
	}

	if a.cursorLine+1 >= len(a.inputLines) {
		return
	}

	a.inputLines[a.cursorLine] += a.inputLines[a.cursorLine+1]
	a.inputLines = append(a.inputLines[:a.cursorLine+1], a.inputLines[a.cursorLine+2:]...)
}

func (a *App) moveLeftLocked() {
	if a.cursorCol > 0 {
		a.cursorCol--
		return
	}
	if a.cursorLine > 0 {
		a.cursorLine--
		a.cursorCol = runeLen(a.inputLines[a.cursorLine])
	}
}

func (a *App) moveRightLocked() {
	lineLen := runeLen(a.inputLines[a.cursorLine])
	if a.cursorCol < lineLen {
		a.cursorCol++
		return
	}
	if a.cursorLine+1 < len(a.inputLines) {
		a.cursorLine++
		a.cursorCol = 0
	}
}

func (a *App) moveUpLocked() {
	if a.cursorLine == 0 {
		return
	}
	a.cursorLine--
	lineLen := runeLen(a.inputLines[a.cursorLine])
	if a.cursorCol > lineLen {
		a.cursorCol = lineLen
	}
}

func (a *App) moveDownLocked() {
	if a.cursorLine+1 >= len(a.inputLines) {
		return
	}
	a.cursorLine++
	lineLen := runeLen(a.inputLines[a.cursorLine])
	if a.cursorCol > lineLen {
		a.cursorCol = lineLen
	}
}

func (a *App) syncLegacyInputStateLocked() {
	a.ensureInputBufferLocked()

	if a.cursorLine >= 0 && a.cursorLine < len(a.inputLines) {
		a.typedInput.Store(a.inputLines[a.cursorLine])
	} else {
		a.typedInput.Store("")
	}

	if len(a.inputLines) > 1 {
		a.multilineMode = true
		a.multilineBuffer = append([]string(nil), a.inputLines[:len(a.inputLines)-1]...)
		a.lastLineBuf = a.inputLines[len(a.inputLines)-1]
	} else {
		a.multilineMode = false
		if len(a.inputLines) == 1 {
			a.lastLineBuf = a.inputLines[0]
		} else {
			a.lastLineBuf = ""
		}
		a.multilineBuffer = nil
	}
}

func (a *App) outputPageStepLocked() int {
	step := a.height / 2
	if step < 3 {
		step = 3
	}
	return step
}

func (a *App) scrollOutputLocked(delta int) {
	if delta == 0 {
		return
	}
	maxScroll := a.maxOutputScrollLocked()
	prev := a.outputScroll
	a.outputScroll += delta
	if a.outputScroll < 0 {
		a.outputScroll = 0
	}
	if a.outputScroll > maxScroll {
		a.outputScroll = maxScroll
	}

	switch {
	case a.outputScroll == 0:
		a.outputFollow = true
	case a.outputScroll != prev:
		a.outputFollow = false
	}
}

func (a *App) scrollOutputToTopLocked() {
	maxScroll := a.maxOutputScrollLocked()
	a.outputScroll = maxScroll
	a.outputFollow = maxScroll == 0
}

func (a *App) scrollOutputToBottomLocked() {
	a.outputScroll = 0
	a.outputFollow = true
}

func (a *App) maxOutputScrollLocked() int {
	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	height := a.height
	if height <= 0 {
		height = defaultHeight
	}
	outputHeight := height - (2 + len(a.inputLines))
	if a.modeHintLocked() != "" {
		outputHeight--
	}
	if outputHeight < 0 {
		outputHeight = 0
	}
	lines := a.wrappedOutputLinesLocked(width)
	maxScroll := len(lines) - outputHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	return maxScroll
}

func (a *App) invalidateOutputCacheLocked() {
	a.outputVersion++
}

func (a *App) outputSpinnerSigLocked() int64 {
	if !a.spinnerActive.Load() || len(a.spinnerFrames) == 0 {
		return -1
	}
	return int64(a.spinnerIdx.Load())
}

func (a *App) wrappedOutputLinesLocked(width int) []outputLine {
	spinnerSig := a.outputSpinnerSigLocked()
	needsRebuild := a.outputCacheWidth != width ||
		a.outputCacheVersion != a.outputVersion ||
		a.outputCacheSelected != a.selected ||
		a.outputCacheInputMode != a.inputMode ||
		a.outputCacheLogsExpanded != a.logsExpanded ||
		a.outputCacheSpinnerSig != spinnerSig

	if needsRebuild {
		a.outputCacheLines = wrapOutputLines(a.buildOutputStyledLinesLocked(width), width)
		a.outputCacheWidth = width
		a.outputCacheVersion = a.outputVersion
		a.outputCacheSelected = a.selected
		a.outputCacheInputMode = a.inputMode
		a.outputCacheLogsExpanded = a.logsExpanded
		a.outputCacheSpinnerSig = spinnerSig
	}
	return a.outputCacheLines
}

func (a *App) draw() {
	a.mu.Lock()
	s := a.screen
	if s == nil {
		a.mu.Unlock()
		return
	}

	w, h := s.Size()
	if w <= 0 {
		w = defaultWidth
	}
	if h <= 0 {
		h = defaultHeight
	}
	a.width, a.height = w, h

	outputLines := a.wrappedOutputLinesLocked(w)
	hint := a.modeHintLocked()
	inputLines := cloneStrings(a.inputLines)
	cursorLine := a.cursorLine
	cursorCol := a.cursorCol
	outputScroll := a.outputScroll
	outputScrollOrig := outputScroll
	outputFollow := a.outputFollow
	outputFollowOrig := outputFollow
	prevWrapped := a.outputPrevWrapped
	prevWrapWidth := a.outputPrevWrapWidth
	a.mu.Unlock()

	if len(inputLines) == 0 {
		inputLines = []string{""}
		cursorLine, cursorCol = 0, 0
	}

	inputRows := make([]inputRenderLine, 0, len(inputLines)+1)
	if hint != "" {
		inputRows = append(inputRows, inputRenderLine{text: hint, logical: -1})
	}
	for i, l := range inputLines {
		prefix := ""
		if i == 0 {
			prefix = "> "
		}
		inputRows = append(inputRows, inputRenderLine{
			text:    prefix + l,
			logical: i,
			prefix:  prefix,
		})
	}

	cursorInputRow := 0
	for i, row := range inputRows {
		if row.logical == cursorLine {
			cursorInputRow = i
			break
		}
	}

	maxInputRows := h - 2 // divider + status
	if maxInputRows < 1 {
		maxInputRows = 1
	}
	if len(inputRows) > maxInputRows {
		trim := len(inputRows) - maxInputRows
		inputRows = inputRows[trim:]
		cursorInputRow -= trim
	}

	reserved := 2 + len(inputRows) // divider + status + input rows
	if reserved > h {
		reserved = h
	}
	outputHeight := h - reserved
	if outputHeight < 0 {
		outputHeight = 0
	}

	maxScroll := len(outputLines) - outputHeight
	if maxScroll < 0 {
		maxScroll = 0
	}

	if outputFollow {
		outputScroll = 0
	} else if prevWrapWidth == w && prevWrapped > 0 && len(outputLines) > prevWrapped {
		// Keep viewport stable while paused and new logs are appended.
		outputScroll += len(outputLines) - prevWrapped
	}

	if outputScroll < 0 {
		outputScroll = 0
	}
	if outputScroll > maxScroll {
		outputScroll = maxScroll
	}
	if outputScroll == 0 {
		outputFollow = true
	} else {
		outputFollow = false
	}

	status := ""
	copyMode := false
	copyCursor := -1
	copyStart, copyEnd := 0, 0
	copyHasRange := false
	a.mu.Lock()
	if outputScroll != outputScrollOrig || outputFollow != outputFollowOrig {
		a.outputScroll = outputScroll
		a.outputFollow = outputFollow
	}
	a.outputPrevWrapped = len(outputLines)
	a.outputPrevWrapWidth = w
	status = a.buildStatusTextLocked()
	copyMode = a.inputMode == ModeCopy
	copyCursor = a.copyCursor
	copyStart, copyEnd, copyHasRange = a.copySelectionBoundsLocked(len(outputLines))
	a.mu.Unlock()

	visibleStart, visibleEnd := outputWindowRange(len(outputLines), outputHeight, outputScroll)
	visibleOutput := []outputLine{}
	if visibleStart >= 0 && visibleEnd >= visibleStart {
		visibleOutput = outputLines[visibleStart:visibleEnd]
	} else {
		visibleStart = 0
	}
	defaultStyle := tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorBlack)
	dividerStyle := tcell.StyleDefault.Foreground(tcell.ColorGray).Background(tcell.ColorBlack)
	statusStyle := tcell.StyleDefault.Foreground(tcell.ColorLightBlue).Background(tcell.ColorBlack)
	spinnerStyle := defaultStyle.Foreground(tcell.NewRGBColor(0xaf, 0x87, 0xff))
	userLineStyle := defaultStyle.Foreground(tcell.ColorWhite).Background(tcell.NewRGBColor(0x33, 0x33, 0x44)).Bold(true)

	s.Clear()
	for y, line := range visibleOutput {
		style := defaultStyle
		switch line.kind {
		case outputLineSpinner:
			style = spinnerStyle
		case outputLineUser:
			style = userLineStyle
		}
		if copyMode {
			absIdx := visibleStart + y
			if copyHasRange && absIdx >= copyStart && absIdx <= copyEnd {
				style = style.Reverse(true)
			}
			if absIdx == copyCursor {
				style = style.Reverse(true).Underline(true)
			}
		}
		drawLine(s, y, line.text, style, w)
	}

	dividerY := outputHeight
	if dividerY >= 0 && dividerY < h {
		drawLine(s, dividerY, strings.Repeat("─", w), dividerStyle, w)
	}

	statusY := dividerY + 1
	if statusY >= 0 && statusY < h {
		drawLine(s, statusY, status, statusStyle, w)
	}

	inputStartY := statusY + 1
	for i, row := range inputRows {
		y := inputStartY + i
		if y >= h {
			break
		}
		drawLine(s, y, row.text, defaultStyle, w)
	}

	cursorVisible := cursorInputRow >= 0 && cursorInputRow < len(inputRows)
	cursorY := inputStartY + cursorInputRow
	if cursorVisible && cursorY >= 0 && cursorY < h {
		row := inputRows[cursorInputRow]
		x := 0
		if row.logical >= 0 && row.logical < len(inputLines) {
			line := inputLines[row.logical]
			if cursorCol < 0 {
				cursorCol = 0
			}
			if cursorCol > runeLen(line) {
				cursorCol = runeLen(line)
			}
			x = displayWidth(row.prefix) + displayWidth(prefixRunes(line, cursorCol))
		}
		if x < 0 {
			x = 0
		}
		if x >= w {
			x = w - 1
		}
		s.ShowCursor(x, cursorY)
	} else {
		s.HideCursor()
	}

	s.Show()
}

type inputRenderLine struct {
	text    string
	logical int
	prefix  string
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

		frame := ""
		if a.spinnerActive.Load() && len(a.spinnerFrames) > 0 {
			frame = a.spinnerFrames[int(a.spinnerIdx.Load())%len(a.spinnerFrames)]
		}

		rendered := renderBlocks(blocks, width, a.logsExpanded, frame)
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

func (a *App) buildOutputStyledLinesLocked(width int) []outputLine {
	lines := make([]outputLine, 0, 128)
	t := a.activeTargetLocked()

	if t == nil {
		if len(a.globalLogs) == 0 {
			lines = append(lines, outputLine{text: "PENTECTER", kind: outputLineDefault})
			lines = append(lines, outputLine{text: "Autonomous Penetration Testing Agent", kind: outputLineDefault})
		} else {
			for _, l := range a.globalLogs {
				lines = append(lines, outputLine{text: l, kind: outputLineDefault})
			}
		}
	} else {
		blocks := make([]*agent.DisplayBlock, len(t.Blocks))
		copy(blocks, t.Blocks)

		frame := ""
		if a.spinnerActive.Load() && len(a.spinnerFrames) > 0 {
			frame = a.spinnerFrames[int(a.spinnerIdx.Load())%len(a.spinnerFrames)]
		}

		for _, b := range blocks {
			rendered := renderBlockCached(b, width, a.logsExpanded, frame)
			rendered = ansiStripRegex.ReplaceAllString(rendered, "")
			rendered = strings.TrimSuffix(rendered, "\n")
			if rendered == "" {
				continue
			}

			kind := outputLineKindForBlock(b)
			for _, line := range strings.Split(rendered, "\n") {
				lineKind := kind
				if line == "" {
					lineKind = outputLineDefault
				}
				lines = append(lines, outputLine{text: line, kind: lineKind})
			}
		}

		if p := t.GetProposal(); p != nil {
			lines = append(lines, outputLine{text: "", kind: outputLineDefault})
			for _, l := range a.proposalLinesLocked(p) {
				lines = append(lines, outputLine{text: l, kind: outputLineDefault})
			}
		}
	}

	if a.inputMode == ModeSelect && len(a.selectOpts) > 0 {
		lines = append(lines, outputLine{text: "", kind: outputLineDefault})
		for _, l := range a.selectLinesLocked() {
			lines = append(lines, outputLine{text: l, kind: outputLineDefault})
		}
	}

	if len(lines) == 0 {
		lines = append(lines, outputLine{text: "", kind: outputLineDefault})
	}
	return lines
}

func outputLineKindForBlock(b *agent.DisplayBlock) outputLineKind {
	switch b.Type {
	case agent.BlockThinking:
		return outputLineSpinner
	case agent.BlockUserInput:
		return outputLineUser
	default:
		return outputLineDefault
	}
}

func renderBlockCached(b *agent.DisplayBlock, width int, expanded bool, spinnerFrame string) string {
	if b.RenderedCache != "" && b.CacheWidth == width && b.CacheExpanded == expanded {
		switch b.Type {
		case agent.BlockCommand:
			if b.Completed || b.CacheOutputLen == len(b.Output) {
				return b.RenderedCache
			}
		case agent.BlockThinking:
			if b.ThinkingDone {
				return b.RenderedCache
			}
		case agent.BlockAIMessage, agent.BlockMemory, agent.BlockUserInput, agent.BlockSystem:
			return b.RenderedCache
		case agent.BlockSubTask:
			if b.TaskDone {
				return b.RenderedCache
			}
		}
	}

	rendered := renderBlock(b, width, expanded, spinnerFrame)
	if rendered == "" {
		return rendered
	}

	cacheable := false
	switch b.Type {
	case agent.BlockCommand:
		cacheable = b.Completed
	case agent.BlockThinking:
		cacheable = b.ThinkingDone
	case agent.BlockAIMessage, agent.BlockMemory, agent.BlockUserInput, agent.BlockSystem:
		cacheable = true
	case agent.BlockSubTask:
		cacheable = b.TaskDone
	}

	if cacheable {
		b.RenderedCache = rendered
		b.CacheWidth = width
		b.CacheExpanded = expanded
	} else if b.Type == agent.BlockCommand && !b.Completed {
		// 未完了コマンドブロック: 出力行数でキャッシュを追跡
		b.RenderedCache = rendered
		b.CacheWidth = width
		b.CacheExpanded = expanded
		b.CacheOutputLen = len(b.Output)
	}
	return rendered
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
	case ModeCopy:
		return "copy mode [up/down, space mark, y yank, q/esc close]"
	}
	return ""
}

func drawLine(s tcell.Screen, y int, text string, style tcell.Style, width int) {
	if y < 0 {
		return
	}
	x := 0
	for _, r := range text {
		rw := runewidth.RuneWidth(r)
		if rw <= 0 {
			rw = 1
		}
		if x+rw > width {
			break
		}
		s.SetContent(x, y, r, nil, style)
		x += rw
	}
	for ; x < width; x++ {
		s.SetContent(x, y, ' ', nil, style)
	}
}

func wrapOutputLines(lines []outputLine, width int) []outputLine {
	if width <= 0 {
		return cloneOutputLines(lines)
	}

	out := make([]outputLine, 0, len(lines))
	for _, l := range lines {
		wrapped := wrapLine(l.text, width)
		for _, w := range wrapped {
			out = append(out, outputLine{text: w, kind: l.kind})
		}
	}
	if len(out) == 0 {
		return []outputLine{{text: "", kind: outputLineDefault}}
	}
	return out
}

func wrapLine(line string, width int) []string {
	if width <= 0 {
		return []string{line}
	}
	runes := []rune(line)
	if len(runes) == 0 {
		return []string{""}
	}

	out := make([]string, 0, (len(runes)+width-1)/width)
	var b strings.Builder
	curW := 0
	for _, r := range runes {
		rw := runewidth.RuneWidth(r)
		if rw < 0 {
			rw = 0
		}

		// Keep combining runes attached to current segment.
		if rw == 0 {
			b.WriteRune(r)
			continue
		}

		if curW > 0 && curW+rw > width {
			out = append(out, b.String())
			b.Reset()
			curW = 0
		}

		b.WriteRune(r)
		curW += rw
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}

func windowOutputLines(lines []outputLine, n int, scroll int) []outputLine {
	start, end := outputWindowRange(len(lines), n, scroll)
	if start < 0 || end < 0 {
		return nil
	}
	return lines[start:end]
}

func outputWindowRange(total, n, scroll int) (start, end int) {
	if n <= 0 {
		return -1, -1
	}
	if scroll < 0 {
		scroll = 0
	}
	if total <= n {
		return 0, total
	}

	end = total - scroll
	if end < 0 {
		end = 0
	}
	start = end - n
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	return start, end
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneOutputLines(in []outputLine) []outputLine {
	if len(in) == 0 {
		return nil
	}
	out := make([]outputLine, len(in))
	copy(out, in)
	return out
}

func runeLen(s string) int {
	return len([]rune(s))
}

func displayWidth(s string) int {
	return runewidth.StringWidth(s)
}

func prefixRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	rs := []rune(s)
	if n >= len(rs) {
		return s
	}
	return string(rs[:n])
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

// resetMultiline clears all multiline input state.
func (a *App) resetMultiline() {
	a.multilineBuffer = nil
	a.multilineMode = false
	a.lastLineBuf = ""
	a.typedInput.Store("")
	a.clearInputLocked()
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

// buildPrompt returns a compatibility prompt string used by legacy tests.
func (a *App) buildPrompt() string {
	if a.multilineMode {
		return ""
	}
	hint := a.modeHintLocked()
	if hint == "" {
		return "\n> "
	}
	return "\n" + hint + " > "
}

// buildStatusText returns the status line text shown below the divider.
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
	if a.outputScroll > 0 {
		parts = append(parts, fmt.Sprintf("scroll:%d (PgDn/Ctrl+End)", a.outputScroll))
	}
	if a.inputMode == ModeCopy {
		width := a.width
		if width <= 0 {
			width = defaultWidth
		}
		lines := a.wrappedOutputLinesLocked(width)
		start, end, ok := a.copySelectionBoundsLocked(len(lines))
		if ok {
			parts = append(parts, fmt.Sprintf("COPY %d-%d y:yank q:exit", start+1, end+1))
		} else {
			parts = append(parts, "COPY y:yank q:exit")
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return "  " + strings.Join(parts, "  ")
}

// refreshPrompt is a compatibility no-op (prompt redraw is handled by tcell).
func (a *App) refreshPrompt() {}

// clearPromptEcho is a compatibility no-op (no readline echo is used).
func (a *App) clearPromptEcho(string) {}

// promptEchoLines returns an approximate line count for compatibility tests.
func (a *App) promptEchoLines(typedText string) int {
	w := a.width
	if w <= 0 {
		w = defaultWidth
	}
	prompt := a.buildPrompt()
	lines := strings.Split(prompt, "\n")
	total := 0
	for i, l := range lines {
		content := l
		if i == len(lines)-1 {
			content += typedText
		}
		n := displayWidth(content)
		if n == 0 {
			total++
			continue
		}
		total += (n-1)/w + 1
	}
	return total
}

// setupLayout updates cached terminal dimensions.
func (a *App) setupLayout() {
	w, h := a.getTerminalSize()
	a.width = w
	a.height = h
}

// getTerminalSize returns the current terminal width and height.
func (a *App) getTerminalSize() (int, int) {
	if a.screen == nil {
		return defaultWidth, defaultHeight
	}
	w, h := a.screen.Size()
	if w <= 0 {
		w = defaultWidth
	}
	if h <= 0 {
		h = defaultHeight
	}
	return w, h
}

// writer returns a test writer if configured; otherwise discard.
func (a *App) writer() io.Writer {
	if a.testWriter != nil {
		return a.testWriter
	}
	return io.Discard
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
	if a.testWriter != nil {
		_, _ = fmt.Fprintln(a.testWriter, msg)
	}
	a.mu.Unlock()
}

// printWelcome stores the initial welcome banner.
func (a *App) printWelcome() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.welcomePrinted {
		return
	}
	a.welcomePrinted = true

	lines := []string{
		"⛈PENTECTER - Autonomous Penetration Testing Agent",
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
		"Commands: /targets, /model, /approve, /attackdata, /copy, /skip-recon, /fold, /status",
	)
	if a.CurrentModel != "" {
		lines = append(lines, fmt.Sprintf("Model: %s/%s", a.CurrentProvider, a.CurrentModel))
	}

	a.globalLogs = append(a.globalLogs, lines...)
	a.invalidateOutputCacheLocked()
	if a.testWriter != nil {
		for _, l := range lines {
			_, _ = fmt.Fprintln(a.testWriter, l)
		}
	}
}
