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
	for _, evt := range events {
		if _, ok := evt.(WebReconComplete); ok {
			hasWebReconComplete = true
		}
	}
	if !hasWebReconComplete {
		t.Fatal("expected WebReconComplete event when no pending tasks remain")
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
