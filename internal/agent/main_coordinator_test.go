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
	if !strings.Contains(prompt, "Attack plan (endpoint + parameter based)") {
		t.Fatal("expected endpoint/parameter based attack planning section")
	}
}

func TestMainCoordinator_VulnFound_UpdatesTree(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")

	uiEvents := make(chan Event, 64)
	domainEvents := make(chan DomainEvent, 8)
	coordinator := NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     1,
		TargetHost:   "10.0.0.1",
		DomainEvents: domainEvents,
		Events:       uiEvents,
		AttackData:   tree,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go coordinator.Run(ctx)

	domainEvents <- VulnFound{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindWebAttack),
		Port:            80,
		Path:            "", // should map to "/" for HTTP port root
		Param:           "id",
		VulnType:        "sqli",
		Evidence:        "SQL syntax error near quote",
		Severity:        "high",
	}

	waitUntil(t, 3*time.Second, func() bool {
		node := tree.FindPortNode(80)
		return node != nil && len(node.Findings) > 0
	}, "expected finding to be recorded from VulnFound")

	node := tree.FindPortNode(80)
	if node == nil || len(node.Findings) == 0 {
		t.Fatal("expected findings on port 80")
	}
	got := node.Findings[0]
	if got.Category != "sqli" {
		t.Fatalf("finding category = %q, want sqli", got.Category)
	}
	if got.Param != "id" {
		t.Fatalf("finding param = %q, want id", got.Param)
	}
	if len(node.Insights) == 0 {
		t.Fatal("expected insight from VulnFound")
	}
}

func TestMainCoordinator_CredentialFound_RoutesPivotAttack(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(21, "ftp", "vsftpd")
	tree.AddPort(22, "ssh", "OpenSSH 7.2")
	tree.AddInsight("10.0.0.1", 22, Insight{
		Source: "hacktricks",
		Topic:  "CVE-2016-0777",
		Detail: "Potential roaming vulnerability in older OpenSSH clients",
	})

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

	domainEvents <- CredentialFound{
		DomainEventBase: NewDomainEventBase(1, "10.0.0.1", AgentKindAttack),
		Port:            21,
		Service:         "ftp",
		Username:        "root",
		Password:        "toor",
	}

	waitUntil(t, 3*time.Second, func() bool {
		_, ok := coordinator.attackByPort[22]
		return ok
	}, "expected credential pivot to spawn attack task for port 22")

	if _, exists := coordinator.attackByPort[21]; exists {
		t.Fatal("credential origin port should not be pivot target")
	}

	taskID := coordinator.attackByPort[22]
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatalf("spawned pivot task %s not found", taskID)
	}
	if task.Metadata.Phase != "attack" {
		t.Fatalf("task phase = %q, want attack", task.Metadata.Phase)
	}
	if !strings.Contains(task.Command, "Known reusable credentials") {
		t.Fatalf("attack prompt should include credential section, got: %q", task.Command)
	}
	if !strings.Contains(task.Command, "root:toor") {
		t.Fatalf("attack prompt should include pivot credential, got: %q", task.Command)
	}
	if !strings.Contains(task.Command, "HackTricks-driven priorities") {
		t.Fatalf("attack prompt should include HackTricks priority guidance, got: %q", task.Command)
	}
}

func TestBuildAttackPrompt_ServiceSpecificAndCreds(t *testing.T) {
	prompt := buildAttackPrompt("10.0.0.1", ServiceIdentified{
		Port:          22,
		Service:       "ssh",
		CVEs:          []string{"CVE-2016-0777"},
		AttackVectors: []string{"credential brute force"},
		Notes:         "HackTricks note: test roaming bug and weak auth",
	}, []Credential{
		{Service: "ssh", Username: "admin", Password: "admin123", Source: "attack"},
	})

	if !strings.Contains(prompt, "Service-specific attack logic") {
		t.Fatal("expected service-specific section")
	}
	if !strings.Contains(prompt, "Known reusable credentials") {
		t.Fatal("expected credentials section")
	}
	if !strings.Contains(prompt, "admin:admin123") {
		t.Fatal("expected credential value in prompt")
	}
	if !strings.Contains(prompt, "HackTricks-driven priorities") {
		t.Fatal("expected HackTricks guidance in prompt")
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
