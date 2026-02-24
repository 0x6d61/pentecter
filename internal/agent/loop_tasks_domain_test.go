package agent

import (
	"context"
	"testing"
)

func TestDrainCompletedTasks_WebReconComplete_OnlyWhenNoPending(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.0.0.1", 80, "/", "/api", 200) // child pending remains
	port := tree.Ports[0]
	if !tree.StartPortRecon(port) {
		t.Fatal("StartPortRecon should succeed")
	}

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-web-1", TaskKindSmart, "web recon 80")
	task.Metadata = TaskMetadata{Phase: "web_recon", Port: 80, Service: "http"}
	task.Status = TaskStatusCompleted
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	hasAgentComplete := false
	hasWebReconComplete := false
	for _, evt := range events {
		switch evt.(type) {
		case AgentComplete:
			hasAgentComplete = true
		case WebReconComplete:
			hasWebReconComplete = true
		}
	}
	if !hasAgentComplete {
		t.Fatal("expected AgentComplete event")
	}
	if hasWebReconComplete {
		t.Fatal("WebReconComplete should not be emitted while pending tasks remain")
	}
}

func TestDrainCompletedTasks_WebReconComplete_WhenNoPending(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.0.0.1", 80, "/", "/login", 200)
	tree.AddParameter("10.0.0.1", 80, "/login", "username", "query")
	// 子ノードに pending が残っていると WebReconComplete は emit されないため、
	// このケースでは「最終完了相当」として child task を complete に寄せる。
	if len(tree.Ports[0].Children) > 0 {
		child := tree.Ports[0].Children[0]
		child.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
		child.SetAttackDataStatusForTest(TaskParamFuzz, StatusComplete)
		child.SetAttackDataStatusForTest(TaskValueFuzz, StatusComplete)
		child.SetAttackDataStatusForTest(TaskProfiling, StatusComplete)
	}
	port := tree.Ports[0]
	if !tree.StartPortRecon(port) {
		t.Fatal("StartPortRecon should succeed")
	}

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-web-2", TaskKindSmart, "web recon 80")
	task.Metadata = TaskMetadata{Phase: "web_recon", Port: 80, Service: "http"}
	task.Status = TaskStatusCompleted
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	hasWebReconComplete := false
	hasEndpoint := false
	hasParam := false
	for _, evt := range events {
		if wr, ok := evt.(WebReconComplete); ok {
			hasWebReconComplete = true
			for _, ep := range wr.Endpoints {
				if ep.Path == "/login" {
					hasEndpoint = true
					break
				}
			}
			for _, p := range wr.Params {
				if p.Path == "/login" && p.Name == "username" {
					hasParam = true
					break
				}
			}
		}
	}
	if !hasWebReconComplete {
		t.Fatal("expected WebReconComplete event when no pending tasks remain")
	}
	if !hasEndpoint {
		t.Fatal("expected endpoint snapshot in WebReconComplete")
	}
	if !hasParam {
		t.Fatal("expected parameter snapshot in WebReconComplete")
	}
}

func TestDrainCompletedTasks_WebReconFailed_EmitsAgentCompleteOnly(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	port := tree.Ports[0]
	if !tree.StartPortRecon(port) {
		t.Fatal("StartPortRecon should succeed")
	}

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-web-failed", TaskKindSmart, "web recon failed")
	task.Metadata = TaskMetadata{Phase: "web_recon", Port: 80, Service: "http"}
	task.Status = TaskStatusFailed
	task.Error = "mock failure"
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	hasAgentComplete := false
	hasWebReconComplete := false
	for _, evt := range events {
		switch evt.(type) {
		case AgentComplete:
			hasAgentComplete = true
		case WebReconComplete:
			hasWebReconComplete = true
		}
	}
	if !hasAgentComplete {
		t.Fatal("expected AgentComplete for failed web_recon task")
	}
	if hasWebReconComplete {
		t.Fatal("WebReconComplete should not be emitted for failed web_recon task")
	}
}

func TestDrainCompletedTasks_ReconTask_DoesNotEmitReconCompleteDomainEvent(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH")

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-recon-1", TaskKindSmart, "recon")
	task.Metadata = TaskMetadata{Phase: "recon"}
	task.Status = TaskStatusCompleted
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	for _, evt := range events {
		if _, ok := evt.(ReconComplete); ok {
			t.Fatal("ReconComplete should not be emitted from drainCompletedTasks for recon task completion")
		}
	}
}

func TestDrainCompletedTasks_ReconTask_EmitsServiceIdentified(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 7.2")

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-recon-2", TaskKindSmart, "recon")
	task.Metadata = TaskMetadata{Phase: "recon"}
	task.Status = TaskStatusCompleted
	task.Findings = []string{"[note] ssh research: CVE-2016-0777 potential information leak"}
	task.AppendOutput("OpenSSH 7.2 identified on port 22")
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	for _, evt := range events {
		if si, ok := evt.(ServiceIdentified); ok {
			if si.Port != 22 {
				t.Fatalf("ServiceIdentified.Port = %d, want 22", si.Port)
			}
			if si.Service != "ssh" {
				t.Fatalf("ServiceIdentified.Service = %q, want ssh", si.Service)
			}
			if len(si.CVEs) == 0 || si.CVEs[0] != "CVE-2016-0777" {
				t.Fatalf("ServiceIdentified.CVEs = %v, want [CVE-2016-0777]", si.CVEs)
			}
			return
		}
	}
	t.Fatal("expected ServiceIdentified event for completed recon task")
}

func TestDrainCompletedTasks_WebAttackTask_EmitsAgentComplete(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-web-attack-1", TaskKindSmart, "web attack 80")
	task.Metadata = TaskMetadata{Phase: "web_attack", Port: 80, Service: "http"}
	task.Status = TaskStatusCompleted
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	for _, evt := range events {
		if ac, ok := evt.(AgentComplete); ok {
			if ac.AgentType != string(AgentKindWebAttack) {
				t.Fatalf("AgentType = %q, want %q", ac.AgentType, AgentKindWebAttack)
			}
			if ac.AgentID != "task-web-attack-1" {
				t.Fatalf("AgentID = %q, want task-web-attack-1", ac.AgentID)
			}
			return
		}
	}
	t.Fatal("expected AgentComplete event for web_attack task")
}

func TestDrainCompletedTasks_AttackTask_EmitsAgentComplete(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(21, "ftp", "vsftpd")

	loop, tm, domainEvents := newDomainDrainTestLoop(tree)
	task := NewSubTask("task-attack-1", TaskKindSmart, "attack 21")
	task.Metadata = TaskMetadata{Phase: "attack", Port: 21, Service: "ftp"}
	task.Status = TaskStatusCompleted
	task.Complete()
	tm.InjectTask(task.ID, task)
	tm.InjectDone(task.ID)

	_ = loop.drainCompletedTasks(context.Background())
	events := drainDomainEvents(domainEvents)

	for _, evt := range events {
		if ac, ok := evt.(AgentComplete); ok {
			if ac.AgentType != string(AgentKindAttack) {
				t.Fatalf("AgentType = %q, want %q", ac.AgentType, AgentKindAttack)
			}
			if ac.AgentID != "task-attack-1" {
				t.Fatalf("AgentID = %q, want task-attack-1", ac.AgentID)
			}
			return
		}
	}
	t.Fatal("expected AgentComplete event for attack task")
}

func newDomainDrainTestLoop(tree *AttackDataTree) (*Loop, *TaskManager, chan DomainEvent) {
	uiEvents := make(chan Event, 32)
	tm := NewTaskManager(nil, nil, uiEvents, nil, nil)
	target := NewTarget(1, tree.Host)
	domainEvents := make(chan DomainEvent, 16)
	loop := &Loop{
		target:       target,
		taskMgr:      tm,
		attackData:   tree,
		domainEvents: domainEvents,
		events:       uiEvents,
	}
	return loop, tm, domainEvents
}

func drainDomainEvents(ch chan DomainEvent) []DomainEvent {
	var out []DomainEvent
	for {
		select {
		case evt := <-ch:
			out = append(out, evt)
		default:
			return out
		}
	}
}
