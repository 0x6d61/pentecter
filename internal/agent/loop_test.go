package agent_test

import (
	"context"
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
}

func (m *mockBrain) Think(_ context.Context, input brain.Input) (*schema.Action, error) {
	m.inputs = append(m.inputs, input)
	if m.idx >= len(m.actions) {
		return &schema.Action{Thought: "done", Action: schema.ActionComplete}, nil
	}
	a := m.actions[m.idx]
	m.idx++
	return a, nil
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
				// 3回目の Think() に渡された snapshot に memory が含まれるか検証
				// inputs[0] = 1回目(memory記録), inputs[1] = 2回目(think), inputs[2] = 3回目(complete)
				if len(mb.inputs) < 3 {
					t.Fatalf("expected at least 3 Think() calls, got %d", len(mb.inputs))
				}
				// 2回目以降の snapshot に CVE が含まれるはず
				snapshot := mb.inputs[2].TargetSnapshot
				if !strings.Contains(snapshot, "CVE-2021-41773") {
					t.Errorf("snapshot should contain memory content, got:\n%s", snapshot)
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
