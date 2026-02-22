package tui

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/0x6d61/pentecter/internal/agent"
)

func startSimulationApp(t *testing.T, a *App) (tcell.SimulationScreen, chan error) {
	t.Helper()

	sim := tcell.NewSimulationScreen("")
	if sizer, ok := sim.(interface{ SetSize(int, int) }); ok {
		sizer.SetSize(100, 28)
	}
	a.SetScreen(sim)

	done := make(chan error, 1)
	go func() {
		done <- a.Run(context.Background())
	}()

	// Allow initial draw.
	time.Sleep(40 * time.Millisecond)
	return sim, done
}

func stopSimulationApp(t *testing.T, sim tcell.SimulationScreen, done chan error) {
	t.Helper()

	sim.InjectKey(tcell.KeyCtrlC, 0, 0)
	time.Sleep(10 * time.Millisecond)
	sim.InjectKey(tcell.KeyCtrlC, 0, 0)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("app exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for app shutdown")
	}
}

func injectKey(sim tcell.SimulationScreen, key tcell.Key, r rune) {
	sim.InjectKey(key, r, 0)
	time.Sleep(20 * time.Millisecond)
}

func injectKeyMod(sim tcell.SimulationScreen, key tcell.Key, r rune, mod tcell.ModMask) {
	sim.InjectKey(key, r, mod)
	time.Sleep(20 * time.Millisecond)
}

func simScreenText(sim tcell.SimulationScreen) string {
	cells, w, h := sim.GetContents()
	lines := make([]string, 0, h)
	for y := 0; y < h; y++ {
		var b strings.Builder
		for x := 0; x < w; x++ {
			c := cells[y*w+x]
			ch := ' '
			if len(c.Runes) > 0 {
				ch = c.Runes[0]
			}
			if ch == 0 {
				ch = ' '
			}
			b.WriteRune(ch)
		}
		lines = append(lines, strings.TrimRight(b.String(), " "))
	}
	return strings.Join(lines, "\n")
}

func findStyledSubstring(sim tcell.SimulationScreen, needle string) (tcell.Style, bool) {
	rs := []rune(needle)
	if len(rs) == 0 {
		return tcell.StyleDefault, false
	}

	cells, w, h := sim.GetContents()
	for y := 0; y < h; y++ {
		for x := 0; x <= w-len(rs); x++ {
			matched := true
			for i, r := range rs {
				c := cells[y*w+x+i]
				ch := ' '
				if len(c.Runes) > 0 {
					ch = c.Runes[0]
				}
				if ch == 0 {
					ch = ' '
				}
				if ch != r {
					matched = false
					break
				}
			}
			if matched {
				return cells[y*w+x].Style, true
			}
		}
	}
	return tcell.StyleDefault, false
}

func TestSimulation_MultilinePrompt_NoDuplicateAfterCtrlN(t *testing.T) {
	a := NewApp(nil)
	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	injectKey(sim, tcell.KeyRune, 'a')
	injectKey(sim, tcell.KeyCtrlN, 0)
	injectKey(sim, tcell.KeyRune, 'a')

	screen := simScreenText(sim)
	if c := strings.Count(screen, "> a"); c != 1 {
		t.Fatalf("expected exactly one '> a' prompt, got %d\nscreen:\n%s", c, screen)
	}
	if c := strings.Count(screen, "> "); c != 1 {
		t.Fatalf("expected exactly one prompt prefix, got %d\nscreen:\n%s", c, screen)
	}
}

func TestSimulation_MultilineBackspaceCtrlN_NoPromptCorruption(t *testing.T) {
	a := NewApp(nil)
	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	injectKey(sim, tcell.KeyRune, 'a')
	injectKey(sim, tcell.KeyCtrlN, 0)
	injectKey(sim, tcell.KeyRune, 'a')
	injectKey(sim, tcell.KeyBackspace2, 0)
	injectKey(sim, tcell.KeyCtrlN, 0)

	screen := simScreenText(sim)
	if c := strings.Count(screen, "> a"); c != 1 {
		t.Fatalf("expected exactly one '> a' prompt after backspace+multiline, got %d\nscreen:\n%s", c, screen)
	}
	if c := strings.Count(screen, "> "); c != 1 {
		t.Fatalf("expected exactly one prompt prefix after backspace+multiline, got %d\nscreen:\n%s", c, screen)
	}
}

func TestSimulation_InputRemainsStableWhenAgentEventArrives(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := NewApp([]*agent.Target{target})
	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	injectKey(sim, tcell.KeyRune, 'a')
	injectKey(sim, tcell.KeyRune, 'b')
	injectKey(sim, tcell.KeyRune, 'c')

	a.enqueueUIEvent(uiEventMsg{
		kind: uiEventAgent,
		agent: agent.Event{
			TargetID: 1,
			Type:     agent.EventLog,
			Source:   agent.SourceSystem,
			Message:  "event while typing",
		},
	})
	time.Sleep(30 * time.Millisecond)

	screen := simScreenText(sim)
	if !strings.Contains(screen, "> abc") {
		t.Fatalf("expected input buffer to remain visible as '> abc'\\nscreen:\\n%s", screen)
	}
	if c := strings.Count(screen, "> "); c != 1 {
		t.Fatalf("expected exactly one prompt prefix, got %d\\nscreen:\\n%s", c, screen)
	}
}

func TestSimulation_OutputScroll_PageUpPageDown(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := NewApp([]*agent.Target{target})
	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	for i := 1; i <= 40; i++ {
		a.enqueueUIEvent(uiEventMsg{
			kind: uiEventAgent,
			agent: agent.Event{
				TargetID: 1,
				Type:     agent.EventLog,
				Source:   agent.SourceSystem,
				Message:  "line " + strconv.Itoa(i),
			},
		})
	}
	time.Sleep(120 * time.Millisecond)

	afterFeed := simScreenText(sim)
	if !strings.Contains(afterFeed, "line 40") {
		t.Fatalf("expected latest line visible before scroll\\nscreen:\\n%s", afterFeed)
	}

	injectKey(sim, tcell.KeyPgUp, 0)
	afterUp := simScreenText(sim)
	if strings.Contains(afterUp, "line 40") {
		t.Fatalf("expected latest line hidden after PgUp\\nscreen:\\n%s", afterUp)
	}

	injectKey(sim, tcell.KeyPgDn, 0)
	time.Sleep(60 * time.Millisecond)
	afterDown := simScreenText(sim)
	if !strings.Contains(afterDown, "line 40") {
		t.Fatalf("expected latest line visible after PgDn\\nscreen:\\n%s", afterDown)
	}
}

func TestSimulation_OutputScroll_PausesFollowUntilBottom(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := NewApp([]*agent.Target{target})
	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	for i := 1; i <= 60; i++ {
		a.enqueueUIEvent(uiEventMsg{
			kind: uiEventAgent,
			agent: agent.Event{
				TargetID: 1,
				Type:     agent.EventLog,
				Source:   agent.SourceSystem,
				Message:  "line " + strconv.Itoa(i),
			},
		})
	}
	time.Sleep(120 * time.Millisecond)

	injectKey(sim, tcell.KeyPgUp, 0)

	a.mu.Lock()
	initialScroll := a.outputScroll
	initialFollow := a.outputFollow
	a.mu.Unlock()
	if initialFollow {
		t.Fatalf("expected follow mode to be disabled after PgUp")
	}
	if initialScroll <= 0 {
		t.Fatalf("expected positive scroll after PgUp, got %d", initialScroll)
	}

	for i := 61; i <= 120; i++ {
		a.enqueueUIEvent(uiEventMsg{
			kind: uiEventAgent,
			agent: agent.Event{
				TargetID: 1,
				Type:     agent.EventLog,
				Source:   agent.SourceSystem,
				Message:  "line " + strconv.Itoa(i),
			},
		})
	}
	time.Sleep(180 * time.Millisecond)

	a.mu.Lock()
	pausedScroll := a.outputScroll
	pausedFollow := a.outputFollow
	a.mu.Unlock()

	if pausedFollow {
		t.Fatal("expected follow mode to stay disabled while user is scrolled up")
	}
	if pausedScroll <= initialScroll {
		t.Fatalf("expected scroll offset to increase while paused (%d -> %d)", initialScroll, pausedScroll)
	}

	pausedScreen := simScreenText(sim)
	if strings.Contains(pausedScreen, "line 120") {
		t.Fatalf("expected newest line hidden while paused\\nscreen:\\n%s", pausedScreen)
	}

	injectKeyMod(sim, tcell.KeyEnd, 0, tcell.ModCtrl)
	time.Sleep(60 * time.Millisecond)

	a.mu.Lock()
	resumedScroll := a.outputScroll
	resumedFollow := a.outputFollow
	a.mu.Unlock()
	if !resumedFollow {
		t.Fatal("expected follow mode after Ctrl+End")
	}
	if resumedScroll != 0 {
		t.Fatalf("expected scroll offset 0 after Ctrl+End, got %d", resumedScroll)
	}

	resumedScreen := simScreenText(sim)
	if !strings.Contains(resumedScreen, "line 120") {
		t.Fatalf("expected newest line visible after Ctrl+End\\nscreen:\\n%s", resumedScreen)
	}
}

func TestSimulation_UserInputBlockHasBackgroundStyle(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.AddBlock(agent.NewUserInputBlock("styled input"))
	a := NewApp([]*agent.Target{target})

	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	style, ok := findStyledSubstring(sim, "> styled input")
	if !ok {
		t.Fatalf("expected user input line to be visible\\nscreen:\\n%s", simScreenText(sim))
	}

	_, bg, attr := style.Decompose()
	wantBG := tcell.NewRGBColor(0x33, 0x33, 0x44)
	if bg != wantBG {
		t.Fatalf("expected user input background %v, got %v", wantBG, bg)
	}
	if attr&tcell.AttrBold == 0 {
		t.Fatalf("expected user input line to be bold, attrs=%v", attr)
	}
}

func TestSimulation_ThinkingBlockHasSpinnerStyle(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.AddBlock(agent.NewThinkingBlock())
	a := NewApp([]*agent.Target{target})
	a.spinnerActive.Store(true)

	sim, done := startSimulationApp(t, a)
	defer stopSimulationApp(t, sim, done)

	style, ok := findStyledSubstring(sim, "Thinking...")
	if !ok {
		t.Fatalf("expected thinking line to be visible\\nscreen:\\n%s", simScreenText(sim))
	}

	fg, _, _ := style.Decompose()
	wantFG := tcell.NewRGBColor(0xaf, 0x87, 0xff)
	if fg != wantFG {
		t.Fatalf("expected spinner foreground %v, got %v", wantFG, fg)
	}
}
