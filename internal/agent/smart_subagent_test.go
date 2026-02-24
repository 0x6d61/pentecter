package agent_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// newSmartTestRunner は SmartSubAgent テスト用の CommandRunner を構築する。
func newSmartTestRunner() *tools.CommandRunner {
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 5,
			TailLines: 5,
		},
	})
	return tools.NewCommandRunner(reg, tools.NewBlacklist(nil), tools.NewLogStore())
}

// slowMockBrain は Think() の度に少し待つ mockBrain。キャンセルテスト用。
type slowMockBrain struct {
	actions []*schema.Action
	idx     int64
	delay   time.Duration
}

func (m *slowMockBrain) Think(ctx context.Context, _ brain.Input) (*schema.Action, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(m.delay):
	}

	i := int(atomic.AddInt64(&m.idx, 1) - 1)
	if i >= len(m.actions) {
		return &schema.Action{Thought: "done", Action: schema.ActionComplete}, nil
	}
	return m.actions[i], nil
}

func (m *slowMockBrain) ExtractTarget(_ context.Context, userText string) (string, string, error) {
	return "", userText, nil
}

func (m *slowMockBrain) Provider() string { return "slow-mock" }

func TestSmartSubAgent_Run_MultiTurn(t *testing.T) {
	// mockBrain: run "echo step1" → memory (vulnerability) → complete
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought: "scanning services",
				Action:  schema.ActionRun,
				Command: "echo step1",
			},
			{
				Thought: "found vulnerability",
				Action:  schema.ActionMemory,
				Memory: &schema.Memory{
					Type:        schema.MemoryVulnerability,
					Title:       "Open SSH",
					Description: "SSH on port 22 allows password auth",
					Severity:    "high",
				},
			},
			{
				Thought: "assessment done",
				Action:  schema.ActionComplete,
			},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-1", agent.TaskKindSmart, "enumerate services")
	task.MaxTurns = 10

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	// タスク完了を待つ
	select {
	case <-task.Done():
		// OK
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	// ステータス検証
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}

	// ターン数検証: run + memory + complete = 3 turns
	if task.TurnCount != 3 {
		t.Errorf("TurnCount: got %d, want 3", task.TurnCount)
	}

	// Findings 検証: memory アクションで記録された内容が含まれること
	findingsJoined := strings.Join(task.Findings, " ")
	if !strings.Contains(findingsJoined, "Open SSH") {
		t.Errorf("Findings should contain 'Open SSH', got: %v", task.Findings)
	}

	// FullOutput 検証
	output := task.FullOutput()
	if !strings.Contains(output, "step1") {
		t.Errorf("FullOutput should contain 'step1', got: %q", output)
	}
	if !strings.Contains(output, "scanning services") {
		t.Errorf("FullOutput should contain thought text 'scanning services', got: %q", output)
	}

	// done チャネルが閉じていることを確認（select が即時通過する）
	select {
	case <-task.Done():
		// OK: channel is closed
	default:
		t.Error("done channel should be closed after completion")
	}
}

func TestSmartSubAgent_Run_MaxTurnsReached(t *testing.T) {
	// mockBrain が常に ActionThink を返す（complete しない）
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "thinking 1", Action: schema.ActionThink},
			{Thought: "thinking 2", Action: schema.ActionThink},
			{Thought: "thinking 3", Action: schema.ActionThink},
			{Thought: "thinking 4", Action: schema.ActionThink},
			{Thought: "thinking 5", Action: schema.ActionThink},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-2", agent.TaskKindSmart, "infinite thinker")
	task.MaxTurns = 3

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
		// OK
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete on MaxTurns")
	}

	// MaxTurns に到達して完了
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}

	if task.TurnCount != 3 {
		t.Errorf("TurnCount: got %d, want 3", task.TurnCount)
	}
}

func TestSmartSubAgent_Run_BrainError(t *testing.T) {
	// mockBrain がエラーを返す
	mb := &mockBrain{
		errors: []error{
			fmt.Errorf("brain connection failed"),
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-3", agent.TaskKindSmart, "error test")
	task.MaxTurns = 5

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
		// OK
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete on error")
	}

	if task.Status != agent.TaskStatusFailed {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusFailed)
	}

	if !strings.Contains(task.Error, "brain connection failed") {
		t.Errorf("Error should contain 'brain connection failed', got: %q", task.Error)
	}
}

func TestSmartSubAgent_Run_ContextCancel(t *testing.T) {
	// slowMockBrain を使って各 Think() で 50ms 待つ
	// 20 ターン × 50ms = 1秒 なので、200ms 後にキャンセルすれば途中で止まる
	actions := make([]*schema.Action, 20)
	for i := range actions {
		actions[i] = &schema.Action{
			Thought: fmt.Sprintf("thinking %d", i+1),
			Action:  schema.ActionThink,
		}
	}
	mb := &slowMockBrain{
		actions: actions,
		delay:   50 * time.Millisecond,
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-4", agent.TaskKindSmart, "cancel test")
	task.MaxTurns = 20

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	ctx, cancel := context.WithCancel(context.Background())

	go sa.Run(ctx, task, "10.0.0.5")

	// 200ms 後にキャンセル（3-4 ターン程度実行されるはず）
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-task.Done():
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete on cancel")
	}

	// キャンセルまたは失敗（Brain がコンテキストエラーを返す場合）
	if task.Status != agent.TaskStatusCancelled && task.Status != agent.TaskStatusFailed {
		t.Errorf("Status: got %q, want cancelled or failed", task.Status)
	}

	// MaxTurns には到達していないはず
	if task.TurnCount >= 20 {
		t.Errorf("TurnCount should be less than 20 (cancelled early), got %d", task.TurnCount)
	}
}

func TestSmartSubAgent_UpdatesAttackDataTree(t *testing.T) {
	// SmartSubAgent が nmap 出力を AttackDataTree にパースすることを検証
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought: "running nmap",
				Action:  schema.ActionRun,
				Command: "nmap -sV 10.0.0.5",
			},
			{
				Thought: "done",
				Action:  schema.ActionComplete,
			},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)

	task := agent.NewSubTask("smart-recon", agent.TaskKindSmart, "test recon tree update")
	task.MaxTurns = 5

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, tree, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout")
	}

	// nmap command was run, but since `echo` registry is used, actual output won't contain nmap XML.
	// The important thing is that the code path was hit without panics.
	// A more complete test would need a mock runner that returns nmap XML output.
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want completed", task.Status)
	}
}

func TestSmartSubAgent_Run_TaskInstructionEveryTurn(t *testing.T) {
	// Create a SubAgent that runs 3 turns: run → run → complete
	mb := &mockBrain{
		actions: []*schema.Action{
			{Action: schema.ActionRun, Command: "echo turn1"},
			{Action: schema.ActionRun, Command: "echo turn2"},
			{Action: schema.ActionComplete, Thought: "done"},
		},
	}
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 32)
	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	task := agent.NewSubTask("test-persist", agent.TaskKindSmart, "Test persistent instructions")
	task.Command = "These are my detailed workflow instructions"
	task.MaxTurns = 10

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	// All 3 Think() calls should have TaskInstruction set
	if len(mb.inputs) < 3 {
		t.Fatalf("expected at least 3 Think() calls, got %d", len(mb.inputs))
	}
	for i, inp := range mb.inputs {
		if inp.TaskInstruction != "These are my detailed workflow instructions" {
			t.Errorf("Turn %d: TaskInstruction should be set, got %q", i+1, inp.TaskInstruction)
		}
	}
}

func TestSmartSubAgent_SearchKnowledge(t *testing.T) {
	// Test that SmartSubAgent handles search_knowledge action
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought:        "searching for exploit info",
				Action:         schema.ActionSearchKnowledge,
				KnowledgeQuery: "vsftpd 2.3.4 exploit",
			},
			{
				Thought: "done",
				Action:  schema.ActionComplete,
			},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-knowledge-1", agent.TaskKindSmart, "test search_knowledge")
	task.MaxTurns = 10

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")
	// No knowledge store → should get error message

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want completed", task.Status)
	}

	// Without knowledge store, the output should mention "not configured"
	output := task.FullOutput()
	if !strings.Contains(output, "not configured") {
		t.Errorf("Output should contain 'not configured' when knowledge store is nil, got: %q", output)
	}
}

func TestSmartSubAgent_ReadKnowledge(t *testing.T) {
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought:       "reading article",
				Action:        schema.ActionReadKnowledge,
				KnowledgePath: "pentesting-web/sql-injection/README.md",
			},
			{
				Thought: "done",
				Action:  schema.ActionComplete,
			},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-knowledge-2", agent.TaskKindSmart, "test read_knowledge")
	task.MaxTurns = 10

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want completed", task.Status)
	}

	output := task.FullOutput()
	if !strings.Contains(output, "not configured") {
		t.Errorf("Output should contain 'not configured' when knowledge store is nil, got: %q", output)
	}
}

func TestSmartSubAgent_AgentKindInEvents(t *testing.T) {
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	task := agent.NewSubTask("smart-kind-1", agent.TaskKindSmart, "test agent kind")
	task.MaxTurns = 10

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "").
		WithAgentKind(agent.AgentKindRecon)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	// Collect events and check that AgentKind is set
	var foundReconKind bool
	for {
		select {
		case e := <-events:
			if e.AgentKind == agent.AgentKindRecon {
				foundReconKind = true
			}
		default:
			goto done
		}
	}
done:
	if !foundReconKind {
		t.Error("Expected at least one event with AgentKind=recon")
	}
}

func TestSmartSubAgent_BlacklistedCommand(t *testing.T) {
	// Brain が rm -rf / を返す → ブラックリストで阻止されること
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought: "cleaning up",
				Action:  schema.ActionRun,
				Command: "rm -rf /",
			},
			{
				Thought: "done",
				Action:  schema.ActionComplete,
			},
		},
	}

	// ブラックリスト付き runner を構築
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 5,
			TailLines: 5,
		},
	})
	runner := tools.NewCommandRunner(reg, tools.NewBlacklist([]string{`rm\s+-rf\s+/`}), tools.NewLogStore())

	events := make(chan agent.Event, 64)
	task := agent.NewSubTask("smart-bl-1", agent.TaskKindSmart, "test blacklist blocking")
	task.MaxTurns = 10

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, nil, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	// タスクは complete すべき（blacklist でブロック後、次ターンで complete）
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want completed", task.Status)
	}

	// 出力にブラックリストエラーが含まれること
	output := task.FullOutput()
	if !strings.Contains(output, "blacklist") {
		t.Errorf("Output should contain 'blacklist' error, got: %q", output)
	}

	// イベントにブラックリストブロックのログが含まれること
	var foundBlockedLog bool
	for {
		select {
		case e := <-events:
			if strings.Contains(e.Message, "blacklisted command blocked") {
				foundBlockedLog = true
			}
		default:
			goto checkDone
		}
	}
checkDone:
	if !foundBlockedLog {
		t.Error("Expected event log containing 'blacklisted command blocked'")
	}
}

func TestSmartSubAgent_ReconSpawnCallback(t *testing.T) {
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought: "running nmap scan",
				Action:  schema.ActionRun,
				Command: "nmap -sV 10.0.0.5",
			},
			{
				Thought: "done",
				Action:  schema.ActionComplete,
			},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	var callbackCalled bool
	task := agent.NewSubTask("smart-callback-1", agent.TaskKindSmart, "test recon callback")
	task.MaxTurns = 10

	// AttackDataTree を提供（reconSpawnCb は nmap コマンド実行時のみ呼ばれる）
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)
	sa := agent.NewSmartSubAgent(mb, runner, nil, events, tree, "10.0.0.5", "").
		WithReconSpawnCallback(func(ctx context.Context) {
			callbackCalled = true
		})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	if !callbackCalled {
		t.Error("reconSpawnCb should have been called after ActionRun")
	}
}

func TestSmartSubAgent_CompleteAttack_NotBlockedByGlobalPending(t *testing.T) {
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 32)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 3)
	tree.AddPort(80, "http", "Apache") // pending web recon remains on unrelated port
	tree.AddPort(22, "ssh", "OpenSSH")

	task := agent.NewSubTask("smart-complete-attack", agent.TaskKindSmart, "attack ssh")
	task.MaxTurns = 3
	task.Metadata = agent.TaskMetadata{Phase: "attack", Port: 22, Service: "ssh"}

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, tree, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	if task.Status != agent.TaskStatusCompleted {
		t.Fatalf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}
	if strings.Contains(task.FullOutput(), "Cannot complete") {
		t.Fatalf("attack task should not be blocked by unrelated pending tasks, output=%q", task.FullOutput())
	}
}

func TestSmartSubAgent_CompleteWebRecon_ScopedToOwnPortPending(t *testing.T) {
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 32)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(443, "http", "nginx")

	// Mark only port 80 recon complete; port 443 remains pending.
	port80 := tree.FindPortNode(80)
	if port80 == nil {
		t.Fatal("expected port 80 node")
	}
	port80.SetAttackDataStatusForTest(agent.TaskEndpointEnum, agent.StatusComplete)
	port80.SetAttackDataStatusForTest(agent.TaskVhostDiscov, agent.StatusComplete)

	task := agent.NewSubTask("smart-complete-web-recon", agent.TaskKindSmart, "web recon complete")
	task.MaxTurns = 3
	task.Metadata = agent.TaskMetadata{Phase: "web_recon", Port: 80, Service: "http"}

	sa := agent.NewSmartSubAgent(mb, runner, nil, events, tree, "10.0.0.5", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go sa.Run(ctx, task, "10.0.0.5")

	select {
	case <-task.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for SmartSubAgent to complete")
	}

	if task.Status != agent.TaskStatusCompleted {
		t.Fatalf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}
	if strings.Contains(task.FullOutput(), "Cannot complete web_recon on port 80") {
		t.Fatalf("web_recon completion should not be blocked by other ports' pending tasks, output=%q", task.FullOutput())
	}
}
