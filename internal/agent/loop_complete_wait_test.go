package agent

import (
	"context"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/pkg/schema"
)

type completeOnlyBrain struct{}

func (completeOnlyBrain) Think(context.Context, brain.Input) (*schema.Action, error) {
	return &schema.Action{
		Thought: "done",
		Action:  schema.ActionComplete,
	}, nil
}

func (completeOnlyBrain) ExtractTarget(_ context.Context, userText string) (string, string, error) {
	return "", userText, nil
}

func (completeOnlyBrain) Provider() string { return "complete-only-test" }

func TestLoop_ActionComplete_DrainsCompletedTasksWhileWaiting(t *testing.T) {
	target := NewTarget(1, "10.0.0.1")
	events := make(chan Event, 32)
	userMsg := make(chan string, 1)
	domainEvents := make(chan DomainEvent, 16)
	taskMgr := NewTaskManager(nil, nil, events, nil, nil)

	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")
	if !tree.StartPortRecon(tree.Ports[0]) {
		t.Fatal("StartPortRecon should succeed")
	}

	loop := &Loop{
		target:       target,
		br:           completeOnlyBrain{},
		taskMgr:      taskMgr,
		attackData:   tree,
		events:       events,
		userMsg:      userMsg,
		domainEvents: domainEvents, // keep local; do not start coordinator in this test
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		loop.Run(ctx)
		close(done)
	}()

	waitForEvent(t, events, EventComplete, 2*time.Second)

	task := NewSubTask("task-web-1", TaskKindSmart, "web recon 80")
	task.Metadata = TaskMetadata{Phase: "web_recon", Port: 80, Service: "http"}
	task.Status = TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask(task.ID, task)
	taskMgr.InjectDone(task.ID)

	waitForDomainEventType(t, domainEvents, "agent_complete", 2*time.Second)

	cancel()
	<-done
}

func waitForEvent(t *testing.T, events <-chan Event, eventType EventType, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case e := <-events:
			if e.Type == eventType {
				return
			}
		case <-deadline:
			t.Fatalf("timeout waiting for event %s", eventType)
		}
	}
}

func waitForDomainEventType(t *testing.T, events <-chan DomainEvent, eventType string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case e := <-events:
			if e.DomainEventType() == eventType {
				return
			}
		case <-deadline:
			t.Fatalf("timeout waiting for domain event %s", eventType)
		}
	}
}
