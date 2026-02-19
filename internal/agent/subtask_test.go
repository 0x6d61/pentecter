package agent_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
)

func TestSubTask_AppendOutput_ReadNewOutput(t *testing.T) {
	st := agent.NewSubTask("task-1", agent.TaskKindRunner, "scan target")

	st.AppendOutput("line1")
	st.AppendOutput("line2")
	st.AppendOutput("line3")

	lines := st.ReadNewOutput()
	if len(lines) != 3 {
		t.Fatalf("ReadNewOutput: got %d lines, want 3", len(lines))
	}
	if lines[0] != "line1" || lines[1] != "line2" || lines[2] != "line3" {
		t.Errorf("ReadNewOutput: got %v, want [line1 line2 line3]", lines)
	}

	// ReadNewOutput does NOT advance cursor, so calling again returns same lines
	lines2 := st.ReadNewOutput()
	if len(lines2) != 3 {
		t.Errorf("second ReadNewOutput without advance: got %d lines, want 3", len(lines2))
	}
}

func TestSubTask_AdvanceReadCursor(t *testing.T) {
	st := agent.NewSubTask("task-1", agent.TaskKindRunner, "scan target")

	st.AppendOutput("line1")
	st.AppendOutput("line2")

	// Read and advance
	lines := st.ReadNewOutput()
	if len(lines) != 2 {
		t.Fatalf("ReadNewOutput: got %d lines, want 2", len(lines))
	}
	st.AdvanceReadCursor()

	// Append more
	st.AppendOutput("line3")
	st.AppendOutput("line4")

	// Should only get new lines
	lines = st.ReadNewOutput()
	if len(lines) != 2 {
		t.Fatalf("ReadNewOutput after advance: got %d lines, want 2", len(lines))
	}
	if lines[0] != "line3" || lines[1] != "line4" {
		t.Errorf("ReadNewOutput after advance: got %v, want [line3 line4]", lines)
	}
}

func TestSubTask_FullOutput(t *testing.T) {
	st := agent.NewSubTask("task-1", agent.TaskKindRunner, "scan target")

	st.AppendOutput("line1")
	st.AppendOutput("line2")
	st.AppendOutput("line3")

	full := st.FullOutput()
	expected := "line1\nline2\nline3"
	if full != expected {
		t.Errorf("FullOutput: got %q, want %q", full, expected)
	}
}

func TestSubTask_Summary_Runner(t *testing.T) {
	st := agent.NewSubTask("task-1", agent.TaskKindRunner, "scan target")
	st.Status = agent.TaskStatusRunning

	st.AppendOutput("line1")
	st.AppendOutput("line2")
	st.AppendOutput("line3")
	st.AppendOutput("line4")
	st.AppendOutput("line5")

	summary := st.Summary()
	// Format: "[task-1] running (5 output lines): scan target"
	if !strings.Contains(summary, "task-1") {
		t.Errorf("Summary should contain task ID, got: %s", summary)
	}
	if !strings.Contains(summary, "running") {
		t.Errorf("Summary should contain status, got: %s", summary)
	}
	if !strings.Contains(summary, "5 output lines") {
		t.Errorf("Summary should contain output line count, got: %s", summary)
	}
	if !strings.Contains(summary, "scan target") {
		t.Errorf("Summary should contain goal, got: %s", summary)
	}
}

func TestSubTask_Summary_Smart(t *testing.T) {
	st := agent.NewSubTask("task-2", agent.TaskKindSmart, "enumerate services")
	st.Status = agent.TaskStatusRunning
	st.MaxTurns = 10
	st.TurnCount = 3

	st.AppendOutput("line1")
	st.AppendOutput("line2")
	st.AppendOutput("line3")
	st.AppendOutput("line4")
	st.AppendOutput("line5")

	summary := st.Summary()
	// Format: "[task-2] running (turn 3/10, 5 output lines): enumerate services"
	if !strings.Contains(summary, "task-2") {
		t.Errorf("Summary should contain task ID, got: %s", summary)
	}
	if !strings.Contains(summary, "turn 3/10") {
		t.Errorf("Summary should contain turn info, got: %s", summary)
	}
	if !strings.Contains(summary, "5 output lines") {
		t.Errorf("Summary should contain output line count, got: %s", summary)
	}
	if !strings.Contains(summary, "enumerate services") {
		t.Errorf("Summary should contain goal, got: %s", summary)
	}
}

func TestSubTask_ConcurrentAccess(t *testing.T) {
	st := agent.NewSubTask("task-1", agent.TaskKindRunner, "concurrent test")

	var wg sync.WaitGroup
	// Multiple writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				st.AppendOutput("line")
			}
		}(i)
	}

	// One reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = st.ReadNewOutput()
			st.AdvanceReadCursor()
			_ = st.FullOutput()
			_ = st.Summary()
		}
	}()

	wg.Wait()

	// After all goroutines finish, verify total output lines = 10 * 100 = 1000
	full := st.FullOutput()
	lineCount := strings.Count(full, "line")
	if lineCount != 1000 {
		t.Errorf("ConcurrentAccess: got %d lines, want 1000", lineCount)
	}
}

func TestSubTask_Done_Channel(t *testing.T) {
	st := agent.NewSubTask("task-1", agent.TaskKindRunner, "test done")

	// done channel should not be closed initially
	select {
	case <-st.Done():
		t.Fatal("Done() should not be closed before Complete()")
	default:
		// OK - not closed
	}

	st.Complete()

	// done channel should be closed now
	select {
	case <-st.Done():
		// OK - closed
	default:
		t.Fatal("Done() should be closed after Complete()")
	}
}
