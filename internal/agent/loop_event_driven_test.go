package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/pkg/schema"
)

type scriptedBrain struct {
	mu       sync.Mutex
	thinkCnt int
	decideFn func(input brain.Input) *schema.Action
	provider string
}

func (b *scriptedBrain) Think(_ context.Context, input brain.Input) (*schema.Action, error) {
	b.mu.Lock()
	b.thinkCnt++
	fn := b.decideFn
	b.mu.Unlock()
	if fn == nil {
		return &schema.Action{Action: schema.ActionThink}, nil
	}
	return fn(input), nil
}

func (b *scriptedBrain) ExtractTarget(_ context.Context, userText string) (string, string, error) {
	return "", userText, nil
}

func (b *scriptedBrain) Provider() string {
	if b.provider != "" {
		return b.provider
	}
	return "scripted-test"
}

func (b *scriptedBrain) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.thinkCnt
}

func TestLoop_EventDriven_NoTrigger_NoThink(t *testing.T) {
	target := NewTarget(1, "10.0.0.1")
	events := make(chan Event, 64)
	userMsg := make(chan string, 2)
	brain := &scriptedBrain{
		decideFn: func(_ brain.Input) *schema.Action {
			return &schema.Action{Action: schema.ActionThink}
		},
	}

	loop := NewLoop(target, brain, nil, events, nil, userMsg).
		WithEventDrivenMain(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.Run(ctx)
		close(done)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	if got := brain.Count(); got != 0 {
		t.Fatalf("Think call count = %d, want 0 when no trigger exists", got)
	}
}

func TestLoop_EventDriven_UserInput_TriggersThinkAndAllowsRun(t *testing.T) {
	target := NewTarget(1, "10.0.0.1")
	events := make(chan Event, 128)
	userMsg := make(chan string, 4)
	brain := &scriptedBrain{
		decideFn: func(input brain.Input) *schema.Action {
			if input.UserMessage != "" {
				return &schema.Action{
					Thought: "I will try to run a command",
					Action:  schema.ActionRun,
					Command: "nmap -sV 10.0.0.1",
				}
			}
			return &schema.Action{Action: schema.ActionThink}
		},
	}

	loop := NewLoop(target, brain, nil, events, nil, userMsg).
		WithEventDrivenMain(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.Run(ctx)
		close(done)
	}()

	userMsg <- "scan please"

	deadline := time.After(3 * time.Second)
	foundRunAttemptLog := false
	foundLegacyBlockedLog := false
	for !foundRunAttemptLog {
		select {
		case e := <-events:
			if e.Type == EventLog && strings.Contains(e.Message, "CommandRunner not configured - cannot execute run action") {
				foundRunAttemptLog = true
			}
			if e.Type == EventLog && strings.Contains(e.Message, "command execution is disabled in event-driven mode") {
				foundLegacyBlockedLog = true
			}
		case <-deadline:
			t.Fatal("timeout waiting for run attempt log")
		}
	}

	cancel()
	<-done

	if foundLegacyBlockedLog {
		t.Fatal("unexpected legacy blocked-run behavior in event-driven mode")
	}

	if got := brain.Count(); got < 1 {
		t.Fatalf("Think call count = %d, want >= 1 after user input", got)
	}
}

func TestLoop_EventDriven_TaskCompletion_TriggersThink(t *testing.T) {
	target := NewTarget(1, "10.0.0.1")
	events := make(chan Event, 128)
	userMsg := make(chan string, 2)
	taskMgr := NewTaskManager(nil, nil, events, nil, nil)
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH")

	brain := &scriptedBrain{
		decideFn: func(_ brain.Input) *schema.Action {
			return &schema.Action{Action: schema.ActionThink}
		},
	}

	loop := NewLoop(target, brain, nil, events, nil, userMsg).
		WithTaskManager(taskMgr).
		WithAttackData(tree).
		WithEventDrivenMain(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.Run(ctx)
		close(done)
	}()

	task := NewSubTask("task-evt-1", TaskKindSmart, "recon")
	task.Metadata = TaskMetadata{Phase: "recon"}
	task.Status = TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask(task.ID, task)
	taskMgr.InjectDone(task.ID)

	deadline := time.After(3 * time.Second)
	for brain.Count() == 0 {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for think triggered by completed subtask")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}

	cancel()
	<-done
}

func TestLoop_EventDriven_EmitsReconCompleteWithoutMainCommands(t *testing.T) {
	target := NewTarget(1, "10.0.0.1")
	events := make(chan Event, 128)
	userMsg := make(chan string, 1)
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH")
	tree.SetChecklist(22, &ServiceChecklist{
		Items: []ChecklistItem{
			{ID: "searchsploit", Description: "searchsploit ssh", Done: true},
		},
	})
	brain := &scriptedBrain{
		decideFn: func(_ brain.Input) *schema.Action {
			return &schema.Action{Action: schema.ActionThink}
		},
	}

	loop := NewLoop(target, brain, nil, events, nil, userMsg).
		WithAttackData(tree).
		WithEventDrivenMain(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.Run(ctx)
		close(done)
	}()

	deadline := time.After(3 * time.Second)
	foundReconComplete := false
	for !foundReconComplete {
		select {
		case e := <-events:
			if e.Type == EventReconComplete {
				foundReconComplete = true
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventReconComplete in event-driven mode")
		}
	}

	cancel()
	<-done
}

func TestLoop_EventDriven_DrainUserMsg_NoDoubleSkillExpansion(t *testing.T) {
	tmp := t.TempDir()
	fooSkill := "name: foo\nprompt: |\n  /bar\n"
	barSkill := "name: bar\nprompt: |\n  final-expanded\n"
	if err := os.WriteFile(filepath.Join(tmp, "foo.yaml"), []byte(fooSkill), 0o600); err != nil {
		t.Fatalf("write foo skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "bar.yaml"), []byte(barSkill), 0o600); err != nil {
		t.Fatalf("write bar skill: %v", err)
	}
	reg := skills.NewRegistry()
	if err := reg.LoadDir(tmp); err != nil {
		t.Fatalf("load skills: %v", err)
	}

	target := NewTarget(1, "10.0.0.1")
	events := make(chan Event, 128)
	userMsg := make(chan string, 4)
	seen := make(chan string, 4)
	brain := &scriptedBrain{
		decideFn: func(input brain.Input) *schema.Action {
			seen <- input.UserMessage
			return &schema.Action{Action: schema.ActionThink}
		},
	}

	loop := NewLoop(target, brain, nil, events, nil, userMsg).
		WithSkills(reg).
		WithEventDrivenMain(true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.Run(ctx)
		close(done)
	}()

	userMsg <- "kick"
	userMsg <- "/foo"

	var msgs []string
	deadline := time.After(3 * time.Second)
	for len(msgs) < 2 {
		select {
		case msg := <-seen:
			msgs = append(msgs, msg)
		case <-deadline:
			t.Fatalf("timeout waiting for thought inputs, got=%v", msgs)
		}
	}

	cancel()
	<-done

	if msgs[1] != "/bar" {
		t.Fatalf("second expanded message = %q, want /bar (single expansion)", msgs[1])
	}
}
