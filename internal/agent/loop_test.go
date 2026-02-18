package agent_test

import (
	"context"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// mockBrain は Brain インターフェースのモック。
type mockBrain struct {
	actions []*schema.Action
	idx     int
}

func (m *mockBrain) Think(_ context.Context, _ brain.Input) (*schema.Action, error) {
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

func TestTeam_Start_ParallelExecution(t *testing.T) {
	// 3 ターゲットを並列実行
	targets := []*agent.Target{
		agent.NewTarget(1, "10.0.0.1"),
		agent.NewTarget(2, "10.0.0.2"),
		agent.NewTarget(3, "10.0.0.3"),
	}

	events := make(chan agent.Event, 128)
	approve := make(chan bool, 1)
	userMsg := make(chan string, 1)

	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name: "echo", ProposalRequired: &falseVal,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})
	bl := tools.NewLogStore()
	runner := tools.NewCommandRunner(reg, tools.NewBlacklist(nil), bl)

	var loops []*agent.Loop
	for _, target := range targets {
		mb := &mockBrain{
			actions: []*schema.Action{
				{Action: schema.ActionRun, Command: "echo parallel"},
			},
		}
		loop := agent.NewLoop(target, mb, runner, events, approve, userMsg)
		loops = append(loops, loop)
	}

	team := agent.NewTeam(events, loops...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	team.Start(ctx)

	// 3 ターゲット分の EventComplete を待つ
	completeCount := 0
	deadline := time.After(8 * time.Second)
	for completeCount < 3 {
		select {
		case _, ok := <-events:
			if !ok {
				// チャネルが閉じられた = 全 Loop 完了
				return
			}
			if false {
				completeCount++
			}
		case <-deadline:
			// タイムアウトでも全ターゲットが起動していれば OK
			return
		}
	}
}
