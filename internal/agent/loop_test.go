package agent_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// mockBrain は Brain インターフェースのモック。
type mockBrain struct {
	actions []*schema.Action
	idx     int
	inputs  []brain.Input // Think() に渡された Input を記録
	errors  []error       // non-nil entries cause Think() to return error
}

func (m *mockBrain) Think(_ context.Context, input brain.Input) (*schema.Action, error) {
	m.inputs = append(m.inputs, input)
	if m.idx < len(m.errors) && m.errors[m.idx] != nil {
		err := m.errors[m.idx]
		m.idx++
		return nil, err
	}
	if m.idx >= len(m.actions) {
		return &schema.Action{Thought: "done", Action: schema.ActionComplete}, nil
	}
	a := m.actions[m.idx]
	m.idx++
	return a, nil
}

func (m *mockBrain) ExtractTarget(_ context.Context, userText string) (string, string, error) {
	return "", userText, nil
}

func (m *mockBrain) Provider() string { return "mock" }

// newTestLoop はテスト用 Loop を構築する（空レジストリ + 基本ブラックリスト）。
func newTestLoop(target *agent.Target, mb *mockBrain) (*agent.Loop, chan agent.Event, chan bool, chan string) {
	falseVal := false
	reg := tools.NewRegistry()
	// テスト用に echo を自動承認ツールとして登録
	reg.Register(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
		Output: tools.OutputConfig{
			Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5,
		},
	})
	bl := tools.NewBlacklist(nil)
	store := tools.NewLogStore()
	runner := tools.NewCommandRunner(reg, bl, store)

	events := make(chan agent.Event, 32)
	approve := make(chan bool, 1)
	userMsg := make(chan string, 1)
	loop := agent.NewLoop(target, mb, runner, events, approve, userMsg)
	return loop, events, approve, userMsg
}

func TestLoop_Run_ThinkAndComplete(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "analyzing", Action: schema.ActionThink},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_RunCommand_AutoExec(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "echo test", Action: schema.ActionRun, Command: "echo hello-team"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_Proposal_Approve(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "run exploit", Action: schema.ActionPropose, Command: "msfconsole -r exploit.rc"},
		},
	}

	loop, events, approve, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventProposal {
				approve <- true
			}
			if e.Type == agent.EventComplete {
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for proposal/complete")
		}
	}
}

func TestLoop_Run_Proposal_AutoApprove(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "run exploit", Action: schema.ActionPropose, Command: "echo auto-approved"},
		},
	}

	// AutoApprove ON のランナーを構築
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name: "echo", ProposalRequired: &falseVal,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})
	runner := tools.NewCommandRunner(reg, tools.NewBlacklist(nil), tools.NewLogStore())
	runner.SetAutoApprove(true)

	events := make(chan agent.Event, 32)
	approve := make(chan bool, 1)
	userMsg := make(chan string, 1)
	loop := agent.NewLoop(target, mb, runner, events, approve, userMsg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	gotAutoApproved := false
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventLog && strings.Contains(e.Message, "Auto-approved") {
				gotAutoApproved = true
			}
			if e.Type == agent.EventComplete {
				if !gotAutoApproved {
					t.Error("expected Auto-approved log before complete")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_SetBrain_AffectsRunningLoop(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	// Original brain: think then wait for user
	originalBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "original thinking", Action: schema.ActionThink},
		},
	}

	loop, events, _, _ := newTestLoop(target, originalBrain)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	// Wait for first think, then swap brain
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// After complete, verify originalBrain was called
				if len(originalBrain.inputs) == 0 {
					t.Error("expected original brain to be called")
				}
				// SetBrain should not panic on a completed loop
				newBrain := &mockBrain{}
				loop.SetBrain(newBrain)
				return
			}
		case <-deadline:
			t.Fatal("timeout")
		}
	}
}

func TestLoop_Run_Proposal_Deny(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "risky exploit", Action: schema.ActionPropose, Command: "msfconsole --exploit"},
		},
	}

	loop, events, approve, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventProposal {
				approve <- false
			}
			if e.Type == agent.EventComplete {
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for deny/complete")
		}
	}
}

func TestLoop_Run_Memory_RecordAndSnapshot(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	mb := &mockBrain{
		actions: []*schema.Action{
			// 1回目: Memory を記録
			{Thought: "found vuln", Action: schema.ActionMemory, Memory: &schema.Memory{
				Type:        schema.MemoryVulnerability,
				Title:       "CVE-2021-41773",
				Description: "Apache 2.4.49 Path Traversal",
				Severity:    "critical",
			}},
			// 2回目: Think（この時点で snapshot に memory が含まれるはず）
			{Thought: "analyzing memory", Action: schema.ActionThink},
			// 3回目: Complete（mockBrain のデフォルト）
		},
	}

	// Memory Store 付きの Loop を構築
	memDir := t.TempDir()
	memStore := memory.NewStore(memDir)

	loop, events, _, _ := newTestLoop(target, mb)
	loop.WithMemory(memStore)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	// EventComplete を待つ
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// 3回目の Think() に渡された Memory フィールドに CVE が含まれるか検証
				// inputs[0] = 1回目(memory記録), inputs[1] = 2回目(think), inputs[2] = 3回目(complete)
				if len(mb.inputs) < 3 {
					t.Fatalf("expected at least 3 Think() calls, got %d", len(mb.inputs))
				}
				// 2回目以降の Memory フィールドに CVE が含まれるはず
				mem := mb.inputs[2].Memory
				if !strings.Contains(mem, "CVE-2021-41773") {
					t.Errorf("Memory field should contain CVE content, got:\n%s", mem)
				}
				// snapshot には memory が含まれないこと（独立フィールドに分離済み）
				snapshot := mb.inputs[2].TargetSnapshot
				if strings.Contains(snapshot, "CVE-2021-41773") {
					t.Errorf("TargetSnapshot should NOT contain memory content after separation, got:\n%s", snapshot)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_AddTarget_EmitsEvent(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "found new host", Action: schema.ActionAddTarget, Target: "10.0.0.99"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	gotAddTarget := false
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventAddTarget && e.NewHost == "10.0.0.99" {
				gotAddTarget = true
			}
			if e.Type == agent.EventComplete {
				if !gotAddTarget {
					t.Error("expected EventAddTarget with host 10.0.0.99 before complete")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_BrainError_Retries(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	// 2 errors then success → should recover
	mb := &mockBrain{
		actions: []*schema.Action{
			nil, // slot 0: error
			nil, // slot 1: error
			{Thought: "recovered", Action: schema.ActionThink}, // slot 2: success
			// slot 3+: default complete
		},
		errors: []error{
			fmt.Errorf("connection refused"),
			fmt.Errorf("timeout"),
			nil, // success
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// Recovered after 2 errors
				return
			}
		case <-deadline:
			t.Fatal("timeout: expected recovery after retries")
		}
	}
}

func TestLoop_Run_BrainError_MaxRetries_Fails(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	// 3 consecutive errors → should fail
	mb := &mockBrain{
		errors: []error{
			fmt.Errorf("error 1"),
			fmt.Errorf("error 2"),
			fmt.Errorf("error 3"),
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(8 * time.Second)
	gotError := false
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventError {
				gotError = true
			}
			// After max retries, loop should stop (no more events)
			if gotError {
				// Wait a bit more to ensure no EventComplete comes
				time.Sleep(200 * time.Millisecond)
				if target.Status != agent.StatusFailed {
					t.Errorf("expected StatusFailed, got %v", target.Status)
				}
				return
			}
		case <-deadline:
			if gotError {
				return
			}
			t.Fatal("timeout: expected EventError after max retries")
		}
	}
}

func TestLoop_Run_Stalled_WaitsForUser(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	// 3 consecutive commands that produce failure output (Signal A: exit code + Signal B: pattern),
	// then recover after user input
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "scan 1", Action: schema.ActionRun, Command: "echo 0 hosts up"},
			{Thought: "scan 2", Action: schema.ActionRun, Command: "echo Host seems down"},
			{Thought: "scan 3", Action: schema.ActionRun, Command: "echo Connection refused"},
			// After user guidance, brain should continue
			{Thought: "trying new approach", Action: schema.ActionRun, Command: "echo PORT 80 open"},
		},
	}

	loop, events, _, userMsg := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go loop.Run(ctx)

	gotStalled := false
	deadline := time.After(12 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventStalled {
				gotStalled = true
				// Send user guidance to resume
				userMsg <- "try a different approach"
			}
			if e.Type == agent.EventComplete {
				if !gotStalled {
					t.Error("expected EventStalled before EventComplete")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for stall detection and recovery")
		}
	}
}

func newTestRunner() *tools.CommandRunner {
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name: "echo", ProposalRequired: &falseVal,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})
	return tools.NewCommandRunner(reg, tools.NewBlacklist(nil), tools.NewLogStore())
}

func TestTeam_Start_ParallelExecution(t *testing.T) {
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{actions: []*schema.Action{{Action: schema.ActionRun, Command: "echo parallel"}}},
		Runner: runner,
	})

	// 3 ターゲットを事前追加
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		team.AddTarget(ip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	team.Start(ctx)

	deadline := time.After(8 * time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-deadline:
			return
		}
	}
}

func TestTeam_AddTarget_DynamicStart(t *testing.T) {
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{actions: []*schema.Action{{Action: schema.ActionThink, Thought: "dynamic"}}},
		Runner: runner,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start() してから AddTarget → 即座に Loop が起動する
	team.Start(ctx)
	target, approveCh, userMsgCh := team.AddTarget("10.0.0.99")

	if target.Host != "10.0.0.99" {
		t.Errorf("Host: got %q, want 10.0.0.99", target.Host)
	}
	if target.ID != 1 {
		t.Errorf("ID: got %d, want 1", target.ID)
	}
	if approveCh == nil || userMsgCh == nil {
		t.Fatal("channels should not be nil")
	}

	// EventComplete を待つ（mockBrain は Think→Complete）
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete && e.TargetID == target.ID {
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for dynamic target to complete")
		}
	}
}

func TestTeam_SetBrain_ChangesForNewTargets(t *testing.T) {
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	originalBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "original brain thinking", Action: schema.ActionThink},
		},
	}
	newBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "new brain thinking", Action: schema.ActionThink},
		},
	}

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  originalBrain,
		Runner: runner,
	})

	// Change the brain before adding targets
	team.SetBrain(newBrain)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	team.Start(ctx)

	// Add a target after SetBrain — it should use the new brain
	target, _, _ := team.AddTarget("10.0.0.50")

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete && e.TargetID == target.ID {
				// The new brain should have been called, not the original
				if len(newBrain.inputs) == 0 {
					t.Error("expected newBrain.Think() to be called, but it was not")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete after SetBrain")
		}
	}
}

func TestTeam_Loops_ReturnsAllLoops(t *testing.T) {
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{},
		Runner: runner,
	})

	// Initially no loops
	loops := team.Loops()
	if len(loops) != 0 {
		t.Errorf("Loops() before AddTarget: got %d, want 0", len(loops))
	}

	// Add targets
	team.AddTarget("10.0.0.1")
	team.AddTarget("10.0.0.2")
	team.AddTarget("10.0.0.3")

	loops = team.Loops()
	if len(loops) != 3 {
		t.Errorf("Loops() after 3 AddTarget: got %d, want 3", len(loops))
	}
}

func TestTeam_Loops_CountMatchesAfterDynamicAdd(t *testing.T) {
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{},
		Runner: runner,
	})

	// Add 2 targets before Start
	team.AddTarget("10.0.0.1")
	team.AddTarget("10.0.0.2")

	if len(team.Loops()) != 2 {
		t.Errorf("Loops() count: got %d, want 2", len(team.Loops()))
	}

	// Add 1 more target (without Start — no goroutine launched but loop is registered)
	team.AddTarget("10.0.0.3")

	if len(team.Loops()) != 3 {
		t.Errorf("Loops() count after dynamic add: got %d, want 3", len(team.Loops()))
	}
}

func TestLoop_Run_TurnCount_PassedToBrain(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "turn 1", Action: schema.ActionThink},
			{Thought: "turn 2", Action: schema.ActionThink},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// 3回の Think() 呼び出し: turn 1, turn 2, complete
				if len(mb.inputs) < 3 {
					t.Fatalf("expected at least 3 Think() calls, got %d", len(mb.inputs))
				}
				// TurnCount は1から始まりインクリメントされる
				if mb.inputs[0].TurnCount != 1 {
					t.Errorf("Turn 1: TurnCount = %d, want 1", mb.inputs[0].TurnCount)
				}
				if mb.inputs[1].TurnCount != 2 {
					t.Errorf("Turn 2: TurnCount = %d, want 2", mb.inputs[1].TurnCount)
				}
				if mb.inputs[2].TurnCount != 3 {
					t.Errorf("Turn 3: TurnCount = %d, want 3", mb.inputs[2].TurnCount)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_PendingUserMsg_DeliveredNextTurn(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	// Action 1: run echo (during execution, user sends message)
	// Action 2: think (should receive the pending user message)
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "running command", Action: schema.ActionRun, Command: "echo hello"},
			{Thought: "got user msg", Action: schema.ActionThink},
		},
	}

	loop, events, _, userMsg := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	sentMsg := false
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			// When we see the command output from echo, send a user message
			// so it gets picked up by post-exec drain
			if e.Type == agent.EventCmdOutput && !sentMsg {
				// Send user message while command is running / just after
				select {
				case userMsg <- "change approach please":
					sentMsg = true
				default:
				}
			}
			if e.Type == agent.EventComplete {
				if !sentMsg {
					t.Skip("could not send user message during execution")
				}
				// Check that the pending message was delivered in a subsequent Think() call
				foundUserMsg := false
				for _, inp := range mb.inputs {
					if inp.UserMessage == "change approach please" {
						foundUserMsg = true
						break
					}
				}
				if !foundUserMsg {
					t.Error("expected pending user message to be delivered to Brain.Think()")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_BuildHistory_EmptyHistory(t *testing.T) {
	// Test that a loop with no command history produces empty buildHistory output.
	// We verify this by checking that the first Brain.Think() call receives empty CommandHistory.
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "analyzing", Action: schema.ActionThink},
			// next call → default complete
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// The first Think() call should have empty CommandHistory
				if len(mb.inputs) < 1 {
					t.Fatal("expected at least 1 Think() call")
				}
				if mb.inputs[0].CommandHistory != "" {
					t.Errorf("first Think() CommandHistory: got %q, want empty string", mb.inputs[0].CommandHistory)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_CallMCP_NoManager(t *testing.T) {
	// MCP マネージャーが未設定の場合、call_mcp はエラーをログしてループ継続
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "browse target", Action: schema.ActionCallMCP,
				MCPServer: "playwright", MCPTool: "browser_navigate",
				MCPArgs: map[string]any{"url": "http://10.0.0.1/"}},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	gotMCPError := false
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventLog && strings.Contains(e.Message, "MCP not configured") {
				gotMCPError = true
			}
			if e.Type == agent.EventComplete {
				if !gotMCPError {
					t.Error("expected MCP not configured error before complete")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// --- SubTask integration tests ---

// newTestLoopWithTaskManager はテスト用の Loop + TaskManager を構築する。
// すべてのサブタスクが Smart になったため、デフォルトの mockBrain を TaskManager に渡す。
func newTestLoopWithTaskManager(target *agent.Target, mb *mockBrain) (*agent.Loop, *agent.TaskManager, chan agent.Event, chan bool, chan string) {
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name: "echo", ProposalRequired: &falseVal,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})
	reg.Register(&tools.ToolDef{
		Name: "sleep", ProposalRequired: &falseVal,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})
	bl := tools.NewBlacklist(nil)
	store := tools.NewLogStore()
	runner := tools.NewCommandRunner(reg, bl, store)

	events := make(chan agent.Event, 64)
	approve := make(chan bool, 1)
	userMsg := make(chan string, 1)

	// Smart サブタスク用のデフォルト mockBrain
	subBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo subtask-output"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}
	taskMgr := agent.NewTaskManager(runner, nil, events, subBrain)

	loop := agent.NewLoop(target, mb, runner, events, approve, userMsg).
		WithTaskManager(taskMgr)
	return loop, taskMgr, events, approve, userMsg
}

func TestLoop_Run_SpawnTask_Wait(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			// 1st: spawn_task
			{Thought: "spawning bg task", Action: schema.ActionSpawnTask,
				Command: "echo spawn-test", TaskGoal: "test spawn"},
			// 2nd: wait (no task_id = wait any)
			{Thought: "waiting for task", Action: schema.ActionWait},
			// 3rd: complete (default from mockBrain)
		},
	}

	loop, _, events, _, _ := newTestLoopWithTaskManager(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)

	gotSubTaskComplete := false
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventSubTaskComplete {
				gotSubTaskComplete = true
			}
			if e.Type == agent.EventComplete {
				if !gotSubTaskComplete {
					t.Error("expected EventSubTaskComplete before EventComplete")
				}
				// Verify 3rd Think() call receives task output in ToolOutput
				if len(mb.inputs) < 3 {
					t.Fatalf("expected at least 3 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[2].ToolOutput
				if !strings.Contains(toolOutput, "task-1") {
					t.Errorf("3rd Think() ToolOutput should reference task-1, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_KillTask(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			// 1st: spawn_task with a long-running command
			{Thought: "spawning long task", Action: schema.ActionSpawnTask,
				Command: "sleep 30", TaskGoal: "long task"},
			// 2nd: kill_task (task-1)
			{Thought: "killing task", Action: schema.ActionKillTask, TaskID: "task-1"},
			// 3rd: complete (default from mockBrain)
		},
	}

	loop, _, events, _, _ := newTestLoopWithTaskManager(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// Verify Brain received cancellation confirmation
				if len(mb.inputs) < 3 {
					t.Fatalf("expected at least 3 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[2].ToolOutput
				if !strings.Contains(toolOutput, "task-1") {
					t.Errorf("3rd Think() ToolOutput should reference task-1, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "cancelled") && !strings.Contains(toolOutput, "Cancel") {
					t.Errorf("3rd Think() ToolOutput should mention cancellation, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Complete_WaitsForUserMsg(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	// 1st: complete (PWNED), then user sends "Write a report"
	// 2nd: think("Report generated"), 3rd: complete again + context cancel
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "pwned the target", Action: schema.ActionComplete},
			{Thought: "Report generated", Action: schema.ActionThink},
			// 3rd call → default complete (mockBrain returns ActionComplete when idx >= len(actions))
		},
	}

	loop, events, _, userMsg := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)

	gotFirstComplete := false
	gotSecondComplete := false
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete && !gotFirstComplete {
				gotFirstComplete = true
				// Verify status is PWNED
				if target.Status != agent.StatusPwned {
					t.Errorf("expected StatusPwned after first complete, got %v", target.Status)
				}
				// Send user message to resume the loop
				go func() {
					userMsg <- "Write a report"
				}()
			} else if e.Type == agent.EventComplete && gotFirstComplete {
				gotSecondComplete = true
				// After second complete, cancel context to break out of waitForUserMsg
				cancel()
			}
			if gotSecondComplete {
				// Verify that Brain received the user message
				foundUserMsg := false
				for _, inp := range mb.inputs {
					if inp.UserMessage == "Write a report" {
						foundUserMsg = true
						break
					}
				}
				if !foundUserMsg {
					t.Error("expected 'Write a report' to be delivered to Brain.Think()")
				}
				// Verify at least 3 Think() calls: complete, think, complete
				if len(mb.inputs) < 3 {
					t.Errorf("expected at least 3 Think() calls, got %d", len(mb.inputs))
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for second EventComplete after PWNED resume")
		}
	}
}

func TestLoop_Run_SpawnTask_CompletionPush(t *testing.T) {
	// 完了済みサブタスクの結果が drainCompletedTasks() で自動的に ToolOutput に注入されること
	target := agent.NewTarget(1, "10.0.0.1")

	mb := &mockBrain{
		actions: []*schema.Action{
			// 1st: think (この前に doneCh に完了タスクを注入済み → drainCompletedTasks で取得)
			{Thought: "analyzing results", Action: schema.ActionThink},
			// 2nd: complete (default from mockBrain)
		},
	}

	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)

	// 事前に完了済みサブタスクを TaskManager に注入
	completedTask := agent.NewSubTask("task-push-1", agent.TaskKindSmart, "test completion push")
	completedTask.Status = agent.TaskStatusCompleted
	completedTask.AppendOutput("push-test-output line 1")
	completedTask.AppendOutput("push-test-output line 2")
	completedTask.Complete()

	taskMgr.InjectTask("task-push-1", completedTask)
	// doneCh に完了を通知（Loop が DrainCompleted で取得できるようにする）
	taskMgr.InjectDone("task-push-1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// completion push が Think() の ToolOutput に含まれること
				found := false
				for _, inp := range mb.inputs {
					if strings.Contains(inp.ToolOutput, "SubTask Completed: task-push-1") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected completion push in ToolOutput, inputs:\n")
					for i, inp := range mb.inputs {
						t.Errorf("  [%d] ToolOutput: %s", i, inp.ToolOutput)
					}
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

func TestLoop_Run_SpawnTask_NoManager(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			// spawn_task action without TaskManager configured
			{Thought: "try spawning", Action: schema.ActionSpawnTask,
				Command: "echo test", TaskGoal: "test no manager"},
			// complete (default from mockBrain)
		},
	}

	// Use newTestLoop (no TaskManager)
	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	gotError := false
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventLog && strings.Contains(e.Message, "TaskManager not configured") {
				gotError = true
			}
			if e.Type == agent.EventComplete {
				if !gotError {
					t.Error("expected 'TaskManager not configured' error log before complete")
				}
				// Verify Brain received the error in ToolOutput
				if len(mb.inputs) >= 2 {
					toolOutput := mb.inputs[1].ToolOutput
					if !strings.Contains(toolOutput, "TaskManager not configured") {
						t.Errorf("2nd Think() ToolOutput should contain error, got: %s", toolOutput)
					}
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// --- Phase 3: Block-based event tests ---

// collectEvents はチャネルから EventComplete まで全イベントを収集する。
func collectEvents(t *testing.T, events <-chan agent.Event, timeout time.Duration) []agent.Event {
	t.Helper()
	var collected []agent.Event
	deadline := time.After(timeout)
	for {
		select {
		case e := <-events:
			collected = append(collected, e)
			if e.Type == agent.EventComplete || e.Type == agent.EventError {
				return collected
			}
		case <-deadline:
			t.Fatalf("timeout collecting events (got %d events)", len(collected))
			return collected
		}
	}
}

// hasEventType は指定した EventType のイベントが含まれるか判定する。
func hasEventType(events []agent.Event, typ agent.EventType) bool {
	for _, e := range events {
		if e.Type == typ {
			return true
		}
	}
	return false
}

// findEvent は最初に見つかった指定 EventType のイベントを返す。
func findEvent(events []agent.Event, typ agent.EventType) (agent.Event, bool) {
	for _, e := range events {
		if e.Type == typ {
			return e, true
		}
	}
	return agent.Event{}, false
}

func TestLoop_Emit_ThinkStart_BeforeThink(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "analyzing", Action: schema.ActionThink},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	if !hasEventType(collected, agent.EventThinkStart) {
		t.Error("expected EventThinkStart to be emitted")
	}

	// EventThinkStart should come after EventTurnStart
	turnIdx := -1
	thinkStartIdx := -1
	for i, e := range collected {
		if e.Type == agent.EventTurnStart && turnIdx == -1 {
			turnIdx = i
		}
		if e.Type == agent.EventThinkStart && thinkStartIdx == -1 {
			thinkStartIdx = i
		}
	}
	if turnIdx >= 0 && thinkStartIdx >= 0 && thinkStartIdx <= turnIdx {
		t.Errorf("EventThinkStart (idx=%d) should come after EventTurnStart (idx=%d)", thinkStartIdx, turnIdx)
	}
}

func TestLoop_Emit_ThinkDone_AfterThink(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "analyzing", Action: schema.ActionThink},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	if !hasEventType(collected, agent.EventThinkDone) {
		t.Error("expected EventThinkDone to be emitted")
	}

	// EventThinkDone should have a non-negative Duration
	e, ok := findEvent(collected, agent.EventThinkDone)
	if ok && e.Duration < 0 {
		t.Errorf("EventThinkDone Duration should be >= 0, got %v", e.Duration)
	}

	// EventThinkDone should come after EventThinkStart
	thinkStartIdx := -1
	thinkDoneIdx := -1
	for i, e := range collected {
		if e.Type == agent.EventThinkStart && thinkStartIdx == -1 {
			thinkStartIdx = i
		}
		if e.Type == agent.EventThinkDone && thinkDoneIdx == -1 {
			thinkDoneIdx = i
		}
	}
	if thinkStartIdx >= 0 && thinkDoneIdx >= 0 && thinkDoneIdx <= thinkStartIdx {
		t.Errorf("EventThinkDone (idx=%d) should come after EventThinkStart (idx=%d)", thinkDoneIdx, thinkStartIdx)
	}
}

func TestLoop_Emit_CmdStart_BeforeExec(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "run scan", Action: schema.ActionRun, Command: "echo hello-cmd"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	e, ok := findEvent(collected, agent.EventCmdStart)
	if !ok {
		t.Fatal("expected EventCmdStart to be emitted")
	}
	if e.Message != "echo hello-cmd" {
		t.Errorf("EventCmdStart Message: got %q, want %q", e.Message, "echo hello-cmd")
	}
}

func TestLoop_Emit_CmdOutput_DuringExec(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "run echo", Action: schema.ActionRun, Command: "echo cmd-output-test"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	if !hasEventType(collected, agent.EventCmdOutput) {
		t.Error("expected EventCmdOutput to be emitted")
	}

	// Verify OutputLine is set on CmdOutput events
	for _, e := range collected {
		if e.Type == agent.EventCmdOutput {
			if e.OutputLine == "" {
				t.Error("EventCmdOutput should have non-empty OutputLine")
			}
		}
	}
}

func TestLoop_Emit_CmdDone_AfterExec(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "run echo", Action: schema.ActionRun, Command: "echo done-test"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	e, ok := findEvent(collected, agent.EventCmdDone)
	if !ok {
		t.Fatal("expected EventCmdDone to be emitted")
	}

	// ExitCode should be 0 for successful echo
	if e.ExitCode != 0 {
		t.Errorf("EventCmdDone ExitCode: got %d, want 0", e.ExitCode)
	}

	// Duration should be > 0
	if e.Duration <= 0 {
		t.Errorf("EventCmdDone Duration should be > 0, got %v", e.Duration)
	}

	// CmdDone should come after CmdStart
	cmdStartIdx := -1
	cmdDoneIdx := -1
	for i, ev := range collected {
		if ev.Type == agent.EventCmdStart && cmdStartIdx == -1 {
			cmdStartIdx = i
		}
		if ev.Type == agent.EventCmdDone && cmdDoneIdx == -1 {
			cmdDoneIdx = i
		}
	}
	if cmdStartIdx >= 0 && cmdDoneIdx >= 0 && cmdDoneIdx <= cmdStartIdx {
		t.Errorf("EventCmdDone (idx=%d) should come after EventCmdStart (idx=%d)", cmdDoneIdx, cmdStartIdx)
	}
}

func TestLoop_Emit_EventOrder_ThinkThenCmd(t *testing.T) {
	// 1ターン目で Think → 2ターン目で Run → Complete
	// イベント順: TurnStart, ThinkStart, ThinkDone, ..., TurnStart, ThinkStart, ThinkDone, CmdStart, CmdOutput, CmdDone, ...
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "thinking first", Action: schema.ActionThink},
			{Thought: "now running", Action: schema.ActionRun, Command: "echo order-test"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	// Both ThinkStart and CmdStart should exist
	if !hasEventType(collected, agent.EventThinkStart) {
		t.Error("expected EventThinkStart")
	}
	if !hasEventType(collected, agent.EventCmdStart) {
		t.Error("expected EventCmdStart")
	}

	// Block-based EventCmdDone should be emitted
	if !hasEventType(collected, agent.EventCmdDone) {
		t.Error("expected EventCmdDone to be emitted")
	}
}

func TestLoop_Emit_BlockEvents_ForCommand(t *testing.T) {
	// Verify that block-based events are emitted for command execution
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "scan", Action: schema.ActionRun, Command: "echo block-test"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 4*time.Second)

	// Block-based EventCmdStart should be present with the command text
	cmdStartFound := false
	for _, e := range collected {
		if e.Type == agent.EventCmdStart && e.Message == "echo block-test" {
			cmdStartFound = true
			break
		}
	}
	if !cmdStartFound {
		t.Error("expected EventCmdStart with command text to be emitted")
	}

	// Block-based EventCmdDone should be present
	if !hasEventType(collected, agent.EventCmdDone) {
		t.Error("expected EventCmdDone to be emitted")
	}

	// Legacy "Thinking..." EventLog should NOT be present (replaced by ThinkStart)
	for _, e := range collected {
		if e.Type == agent.EventLog && e.Message == "Thinking..." {
			t.Error("legacy 'Thinking...' EventLog should be removed (replaced by EventThinkStart)")
		}
	}
}

func TestLoop_Emit_SubTaskStart(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "spawn subtask", Action: schema.ActionSpawnTask,
				Command: "echo subtask-start-test", TaskGoal: "test subtask start"},
			{Thought: "waiting", Action: schema.ActionWait},
		},
	}

	loop, _, events, _, _ := newTestLoopWithTaskManager(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)

	collected := collectEvents(t, events, 8*time.Second)

	e, ok := findEvent(collected, agent.EventSubTaskStart)
	if !ok {
		t.Fatal("expected EventSubTaskStart to be emitted")
	}
	if e.TaskID == "" {
		t.Error("EventSubTaskStart should have non-empty TaskID")
	}
	if e.Message != "test subtask start" {
		t.Errorf("EventSubTaskStart Message: got %q, want %q", e.Message, "test subtask start")
	}
}

// --- AddTarget 重複チェックテスト ---

func TestTeam_AddTarget_Duplicate_ReturnsSameTarget(t *testing.T) {
	// 同じホストを2回追加した場合、2回目は既存の Target を返し、
	// Loop が新たに作成されないことを検証する。
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{},
		Runner: runner,
	})

	// 1回目: 新規追加
	target1, approveCh1, userMsgCh1 := team.AddTarget("10.0.0.1")
	if target1 == nil {
		t.Fatal("first AddTarget should return non-nil target")
	}
	if approveCh1 == nil || userMsgCh1 == nil {
		t.Fatal("first AddTarget should return non-nil channels")
	}

	// 2回目: 同じホストを追加（重複）
	target2, approveCh2, userMsgCh2 := team.AddTarget("10.0.0.1")

	// 同じ Target が返ること
	if target2 == nil {
		t.Fatal("duplicate AddTarget should return non-nil target")
	}
	if target2.ID != target1.ID {
		t.Errorf("duplicate AddTarget: target ID mismatch: got %d, want %d", target2.ID, target1.ID)
	}
	if target2.Host != target1.Host {
		t.Errorf("duplicate AddTarget: host mismatch: got %q, want %q", target2.Host, target1.Host)
	}

	// 重複時はチャネルが nil であること（既存の Loop が使われるため）
	if approveCh2 != nil {
		t.Error("duplicate AddTarget: approveCh should be nil")
	}
	if userMsgCh2 != nil {
		t.Error("duplicate AddTarget: userMsgCh should be nil")
	}

	// Loop は1つだけであること
	loops := team.Loops()
	if len(loops) != 1 {
		t.Errorf("Loops() count: got %d, want 1", len(loops))
	}
}

func TestTeam_AddTarget_DifferentHosts_CreatesMultiple(t *testing.T) {
	// 異なるホストを追加した場合はそれぞれ独立した Target/Loop が作成されることを検証。
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{},
		Runner: runner,
	})

	target1, ch1a, ch1u := team.AddTarget("10.0.0.1")
	target2, ch2a, ch2u := team.AddTarget("10.0.0.2")
	target3, ch3a, ch3u := team.AddTarget("10.0.0.3")

	// それぞれ異なる Target であること
	if target1.ID == target2.ID || target2.ID == target3.ID {
		t.Errorf("different hosts should have different IDs: %d, %d, %d", target1.ID, target2.ID, target3.ID)
	}

	// 全てのチャネルが非 nil であること（新規作成なので）
	if ch1a == nil || ch1u == nil || ch2a == nil || ch2u == nil || ch3a == nil || ch3u == nil {
		t.Error("all channels for different hosts should be non-nil")
	}

	// Loop は3つであること
	loops := team.Loops()
	if len(loops) != 3 {
		t.Errorf("Loops() count: got %d, want 3", len(loops))
	}
}

func TestTeam_AddTarget_Duplicate_AfterStart(t *testing.T) {
	// Start() 済みの状態でも重複チェックが機能することを検証。
	events := make(chan agent.Event, 128)
	runner := newTestRunner()

	team := agent.NewTeam(agent.TeamConfig{
		Events: events,
		Brain:  &mockBrain{actions: []*schema.Action{{Action: schema.ActionThink, Thought: "test"}}},
		Runner: runner,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	team.Start(ctx)

	// Start 後に同じホストを2回追加
	target1, _, _ := team.AddTarget("192.168.1.1")
	target2, approveCh2, userMsgCh2 := team.AddTarget("192.168.1.1")

	// 同じ Target が返ること
	if target2.ID != target1.ID {
		t.Errorf("duplicate AddTarget after Start: target ID mismatch: got %d, want %d", target2.ID, target1.ID)
	}

	// 重複時はチャネルが nil
	if approveCh2 != nil || userMsgCh2 != nil {
		t.Error("duplicate AddTarget after Start: channels should be nil")
	}

	// Loop は1つだけ
	if len(team.Loops()) != 1 {
		t.Errorf("Loops() count after duplicate: got %d, want 1", len(team.Loops()))
	}
}
