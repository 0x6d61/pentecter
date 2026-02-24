package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

type coordinatorBrain struct{}

func (coordinatorBrain) Think(context.Context, brain.Input) (*schema.Action, error) {
	// Subtask を継続させるだけでよい（spawn 成功確認が目的）。
	return &schema.Action{Action: schema.ActionThink}, nil
}

func (coordinatorBrain) ExtractTarget(_ context.Context, userText string) (string, string, error) {
	return "", userText, nil
}

func (coordinatorBrain) Provider() string { return "coordinator-test" }

func newCoordinatorTaskManager(events chan<- Event) *TaskManager {
	falseVal := false
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name:             "echo",
		ProposalRequired: &falseVal,
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 3,
			TailLines: 3,
		},
	})
	runner := tools.NewCommandRunner(reg, tools.NewBlacklist(nil), tools.NewLogStore())
	return NewTaskManager(runner, nil, events, coordinatorBrain{}, nil)
}

func TestMainCoordinator_PortDiscoveredHTTP_RoutesToWebRecon(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")

	uiEvents := make(chan Event, 64)
	domainEvents := make(chan DomainEvent, 8)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    newCoordinatorTaskManager(uiEvents),
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	domainEvents <- PortDiscovered{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            80,
		Service:         "http",
		Banner:          "Apache",
	}

	foundRouteLog := false
	deadline := time.After(3 * time.Second)
	for !foundRouteLog {
		select {
		case e := <-uiEvents:
			if strings.Contains(e.Message, "routed HTTP port") {
				foundRouteLog = true
			}
		case <-deadline:
			t.Fatal("expected coordinator routing log")
		}
	}
	if tree.Active() != 1 {
		t.Fatalf("Active = %d, want 1 after routing", tree.Active())
	}
}

func TestMainCoordinator_PortDiscoveredNonHTTP_NoRouting(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH")

	uiEvents := make(chan Event, 32)
	domainEvents := make(chan DomainEvent, 4)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    newCoordinatorTaskManager(uiEvents),
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	domainEvents <- PortDiscovered{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            22,
		Service:         "ssh",
		Banner:          "OpenSSH",
	}

	select {
	case e := <-uiEvents:
		t.Fatalf("unexpected coordinator event for non-HTTP service: %s", e.Message)
	case <-time.After(300 * time.Millisecond):
		// expected
	}
	if tree.Active() != 0 {
		t.Fatalf("Active = %d, want 0 for non-HTTP", tree.Active())
	}
}

func TestMainCoordinator_ServiceIdentified_RoutesToAttack(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 7.2")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 8)
	tm := newCoordinatorTaskManager(uiEvents)
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		AttackData:   tree,
		TaskMgr:      tm,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	domainEvents <- ServiceIdentified{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            22,
		Service:         "ssh",
		CVEs:            []string{"CVE-2016-0777"},
		AttackVectors:   []string{"credential brute force"},
		Notes:           "OpenSSH 7.2 research result",
	}

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.attackByPort[22]
		return ok
	}, "expected AttackAgent spawn for service_identified")

	taskID := coordinator.attackByPort[22]
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatalf("spawned task %s not found", taskID)
	}
	if task.Metadata.Phase != "attack" {
		t.Fatalf("task phase = %q, want attack", task.Metadata.Phase)
	}
	if task.Metadata.Service != "ssh" {
		t.Fatalf("task service = %q, want ssh", task.Metadata.Service)
	}
	if !strings.Contains(task.Command, "CVE-2016-0777") {
		t.Fatalf("attack prompt should include CVE context, got: %q", task.Command)
	}
}

func TestMainCoordinator_DuplicatePortDiscovered_DoesNotDoubleSpawn(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")

	uiEvents := make(chan Event, 64)
	domainEvents := make(chan DomainEvent, 8)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    newCoordinatorTaskManager(uiEvents),
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	evt := PortDiscovered{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            80,
		Service:         "http",
		Banner:          "Apache",
	}
	domainEvents <- evt
	domainEvents <- evt

	waitUntil(t, 3*time.Second, func() bool { return tree.Active() == 1 }, "expected first spawn to start")
	// 重複イベントでも active は 1 のまま（重複 spawn しない）
	time.Sleep(100 * time.Millisecond)
	if tree.Active() != 1 {
		t.Fatalf("Active = %d, want 1 (duplicate event should not double-spawn)", tree.Active())
	}
}

func TestMainCoordinator_ServiceIdentified_Duplicate_DoesNotDoubleSpawnAttack(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(21, "ftp", "vsftpd")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 8)
	tm := newCoordinatorTaskManager(uiEvents)
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		AttackData:   tree,
		TaskMgr:      tm,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	evt := ServiceIdentified{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            21,
		Service:         "ftp",
		CVEs:            []string{"CVE-2011-2523"},
	}
	domainEvents <- evt
	domainEvents <- evt

	waitUntil(t, 3*time.Second, func() bool {
		return len(tm.AllTasks(1)) >= 1
	}, "expected at least one attack task")
	time.Sleep(100 * time.Millisecond)
	if got := len(tm.AllTasks(1)); got != 1 {
		t.Fatalf("task count = %d, want 1", got)
	}
}

func TestMainCoordinator_DeferredPort_RetriedOnWebReconAgentComplete(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 1, 0) // max_parallel=1
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(8080, "http", "Jetty")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 16)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    newCoordinatorTaskManager(uiEvents),
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	// 1つ目は開始される（active=1）
	domainEvents <- PortDiscovered{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            80,
		Service:         "http",
		Banner:          "Apache",
	}
	waitUntil(t, 3*time.Second, func() bool { return tree.Active() == 1 }, "first HTTP recon should start")

	// 2つ目は max_parallel で defer される
	domainEvents <- PortDiscovered{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            8080,
		Service:         "http",
		Banner:          "Jetty",
	}
	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.deferredHTTP[8080]
		return ok
	}, "port 8080 should be deferred")

	// スロットを開ける
	tree.CompleteAllPortTasks(80)
	if tree.Active() != 0 {
		t.Fatalf("Active = %d, want 0 after completion", tree.Active())
	}

	// WebReconAgent 完了イベントで deferred retry
	domainEvents <- AgentComplete{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindWebRecon),
		AgentID:         "task-80",
		AgentType:       string(AgentKindWebRecon),
		Summary:         "done",
	}

	waitUntil(t, 3*time.Second, func() bool {
		_, stillDeferred := coordinator.deferredHTTP[8080]
		return tree.Active() == 1 && !stillDeferred
	}, "deferred port should be retried when slot is free")
}

func TestMainCoordinator_WebReconComplete_RoutesToWebAttack(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 8)
	tm := newCoordinatorTaskManager(uiEvents)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    tm,
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
		TaskMgr:      tm,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	domainEvents <- WebReconComplete{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindWebRecon),
		Port:            80,
		Endpoints: []EndpointInfo{
			{Host: "10.0.0.1", Port: 80, Path: "/login"},
		},
		Params: []ParamInfo{
			{Host: "10.0.0.1", Port: 80, Path: "/login", Name: "username", ParamType: "query"},
		},
		Vhosts: []string{"admin.10.0.0.1"},
	}

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.webAttackByPort[80]
		return ok
	}, "expected WebAttackAgent spawn for web recon completion")

	taskID := coordinator.webAttackByPort[80]
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatalf("spawned task %s not found", taskID)
	}
	if task.Metadata.Phase != "web_attack" {
		t.Fatalf("task phase = %q, want web_attack", task.Metadata.Phase)
	}
}

func TestMainCoordinator_WebReconComplete_Duplicate_DoesNotDoubleSpawnWebAttack(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 8)
	tm := newCoordinatorTaskManager(uiEvents)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    tm,
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
		TaskMgr:      tm,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	evt := WebReconComplete{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindWebRecon),
		Port:            80,
	}
	domainEvents <- evt
	domainEvents <- evt

	waitUntil(t, 3*time.Second, func() bool {
		return len(tm.AllTasks(1)) >= 1
	}, "expected at least one web attack task")
	time.Sleep(100 * time.Millisecond)
	if got := len(tm.AllTasks(1)); got != 1 {
		t.Fatalf("task count = %d, want 1", got)
	}
}

func TestMainCoordinator_WebAttackComplete_AllowsRespawn(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 16)
	tm := newCoordinatorTaskManager(uiEvents)
	rr := NewReconRunner(ReconRunnerConfig{
		Tree:       tree,
		TaskMgr:    tm,
		Events:     uiEvents,
		TargetHost: "10.0.0.1",
		TargetID:   1,
	})
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		ReconRunner:  rr,
		AttackData:   tree,
		TaskMgr:      tm,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	first := WebReconComplete{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindWebRecon),
		Port:            80,
	}
	domainEvents <- first

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.webAttackByPort[80]
		return ok
	}, "expected first web attack spawn")
	firstTaskID := coordinator.webAttackByPort[80]

	domainEvents <- AgentComplete{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindWebAttack),
		AgentID:         firstTaskID,
		AgentType:       string(AgentKindWebAttack),
		Summary:         "done",
	}

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.webAttackByPort[80]
		return !ok
	}, "expected web attack slot cleared")

	domainEvents <- first
	waitUntil(t, 3*time.Second, func() bool {
		id, ok := coordinator.webAttackByPort[80]
		return ok && id != "" && id != firstTaskID
	}, "expected web attack respawn after completion")
}

func TestMainCoordinator_AttackComplete_AllowsRespawn(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(21, "ftp", "vsftpd")

	uiEvents := make(chan Event, 128)
	domainEvents := make(chan DomainEvent, 16)
	tm := newCoordinatorTaskManager(uiEvents)
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		AttackData:   tree,
		TaskMgr:      tm,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	first := ServiceIdentified{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindRecon),
		Port:            21,
		Service:         "ftp",
		CVEs:            []string{"CVE-2011-2523"},
	}
	domainEvents <- first

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.attackByPort[21]
		return ok
	}, "expected first attack spawn")
	firstTaskID := coordinator.attackByPort[21]

	domainEvents <- AgentComplete{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindAttack),
		AgentID:         firstTaskID,
		AgentType:       string(AgentKindAttack),
		Summary:         "done",
	}

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.attackByPort[21]
		return !ok
	}, "expected attack slot cleared")

	domainEvents <- first
	waitUntil(t, 3*time.Second, func() bool {
		id, ok := coordinator.attackByPort[21]
		return ok && id != "" && id != firstTaskID
	}, "expected attack respawn after completion")
}

func TestBuildWebAttackPrompt(t *testing.T) {
	prompt := buildWebAttackPrompt(
		"10.0.0.1",
		80,
		[]EndpointInfo{{Path: "/login"}},
		[]ParamInfo{{Path: "/login", Name: "username", ParamType: "query"}},
		[]string{"admin.10.0.0.1"},
	)
	if !strings.Contains(prompt, "/login") {
		t.Fatal("expected endpoint in prompt")
	}
	if !strings.Contains(prompt, "username") {
		t.Fatal("expected parameter in prompt")
	}
	if !strings.Contains(prompt, "Do NOT run broad web reconnaissance tools") {
		t.Fatal("expected prohibition for broad web recon tools")
	}
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}
