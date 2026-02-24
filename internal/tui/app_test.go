package tui

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
)

func newAppWithBuffer(targets []*agent.Target) (*App, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	a := NewApp(targets)
	a.testWriter = buf
	return a, buf
}

func TestBuildPrompt(t *testing.T) {
	a, _ := newAppWithBuffer(nil)

	if got := a.buildPrompt(); got != "> " {
		t.Fatalf("normal prompt mismatch: %q", got)
	}

	a.inputMode = ModeConfirmQuit
	if got := a.buildPrompt(); got != "Quit Pentecter? [y/n] > " {
		t.Fatalf("confirm prompt mismatch: %q", got)
	}

	a.inputMode = ModeSelect
	a.selectOpts = []SelectOption{{Label: "x", Value: "x"}, {Label: "y", Value: "y"}}
	if got := a.buildPrompt(); got != "select [1-2/q] > " {
		t.Fatalf("select prompt mismatch: %q", got)
	}

	a.inputMode = ModeNormal
	a.spinnerActive.Store(true)
	a.spinnerIdx.Store(0)
	if got := a.buildPrompt(); got != "⠋ Thinking...\n> " {
		t.Fatalf("spinner prompt mismatch: %q", got)
	}
}

func TestPrintWelcome_NoTargets(t *testing.T) {
	a, buf := newAppWithBuffer(nil)
	a.printWelcome()

	out := buf.String()
	if !strings.Contains(out, "PENTECTER - Autonomous Penetration Testing Agent") {
		t.Fatal("missing banner")
	}
	if !strings.Contains(out, "Commands: /targets, /model, /attackdata, /skip-recon, /fold, /status") {
		t.Fatal("missing command list")
	}
	if !strings.Contains(out, "Keys: Ctrl+O") {
		t.Fatal("missing key help")
	}
}

func TestPrintWelcome_OnlyOnce(t *testing.T) {
	a, buf := newAppWithBuffer(nil)
	a.printWelcome()
	first := buf.String()
	a.printWelcome()
	second := buf.String()

	if first != second {
		t.Fatal("welcome should be printed once")
	}
}

func TestLogSystem_Global(t *testing.T) {
	a, _ := newAppWithBuffer(nil)
	a.logSystem("hello")

	if len(a.globalLogs) == 0 || a.globalLogs[len(a.globalLogs)-1] != "hello" {
		t.Fatalf("unexpected global logs: %#v", a.globalLogs)
	}
}

func TestLogSystem_TargetBlock(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a, _ := newAppWithBuffer([]*agent.Target{target})
	a.logSystem("msg")

	if len(target.Blocks) != 1 {
		t.Fatalf("expected one target block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Type != agent.BlockSystem {
		t.Fatalf("expected system block, got %v", target.Blocks[0].Type)
	}
}

func TestBuildStatusText(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a, _ := newAppWithBuffer([]*agent.Target{target})
	a.CurrentProvider = "anthropic"
	a.CurrentModel = "claude-sonnet-4-6"

	status := a.buildStatusText()
	if !strings.Contains(status, "10.0.0.1") {
		t.Fatalf("status missing target: %q", status)
	}
	if !strings.Contains(status, "anthropic/claude-sonnet-4-6") {
		t.Fatalf("status missing model: %q", status)
	}
}

func TestToggleThinkingFold(t *testing.T) {
	a, _ := newAppWithBuffer(nil)
	if !a.thinkingExpanded {
		t.Fatal("thinkingExpanded should start as true")
	}

	a.toggleThinkingFold()
	if a.thinkingExpanded {
		t.Fatal("thinkingExpanded should be false after toggle")
	}

	a.toggleThinkingFold()
	if !a.thinkingExpanded {
		t.Fatal("thinkingExpanded should be true after second toggle")
	}
}

func TestRun_TestModeExitsOnContext(t *testing.T) {
	a, _ := newAppWithBuffer(nil)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.Run(ctx)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting Run to exit")
	}
}
