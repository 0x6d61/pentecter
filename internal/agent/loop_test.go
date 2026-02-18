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
// actions スライスを順番に返し、最後は ActionComplete を返す。
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

func newTestLoop(target *agent.Target, mb *mockBrain) (loop *agent.Loop, events chan agent.Event, approve chan bool, userMsg chan string) {
	store := tools.NewLogStore()
	registry := tools.NewRegistry()
	events = make(chan agent.Event, 32)
	approve = make(chan bool, 1)
	userMsg = make(chan string, 1)
	loop = agent.NewLoop(target, mb, store, registry, events, approve, userMsg)
	return
}

func newTestLoopWithRegistry(target *agent.Target, mb *mockBrain, reg *tools.Registry) (loop *agent.Loop, events chan agent.Event, approve chan bool, userMsg chan string) {
	store := tools.NewLogStore()
	events = make(chan agent.Event, 32)
	approve = make(chan bool, 1)
	userMsg = make(chan string, 1)
	loop = agent.NewLoop(target, mb, store, reg, events, approve, userMsg)
	return
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

func TestLoop_Run_ExecTool_ToolNotFound(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "run nope", Action: schema.ActionRunTool, Tool: "notexist"},
		},
	}

	loop, events, _, _ := newTestLoop(target, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go loop.Run(ctx)

	var gotToolError bool
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventLog && e.Source == agent.SourceSystem && len(e.Message) > 0 {
				gotToolError = true
			}
			if e.Type == agent.EventComplete && gotToolError {
				return
			}
		case <-deadline:
			if !gotToolError {
				t.Fatal("timeout: tool-not-found error log not received")
			}
			return
		}
	}
}

func TestLoop_Run_Proposal_Approve(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought: "exploit candidate",
				Action:  schema.ActionPropose,
				Tool:    "echo",
				Args:    map[string]any{"message": "exploiting"},
			},
		},
	}

	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name: "echo", Binary: "echo",
		ArgsTemplate: "{message}",
		Output:       tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})

	loop, events, approve, _ := newTestLoopWithRegistry(target, mb, reg)

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
			{
				Thought: "risky exploit",
				Action:  schema.ActionPropose,
				Tool:    "metasploit",
				Args:    map[string]any{},
			},
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
			t.Fatal("timeout waiting for proposal deny/complete")
		}
	}
}
