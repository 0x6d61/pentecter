package agent_test

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/tools"
)

func TestNewTarget_InitialState(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")

	if tgt.ID != 1 {
		t.Errorf("ID: got %d, want 1", tgt.ID)
	}
	if tgt.Host != "10.0.0.1" {
		t.Errorf("Host: got %s, want 10.0.0.1", tgt.Host)
	}
	if tgt.Status != agent.StatusIdle {
		t.Errorf("Status: got %s, want %s", tgt.Status, agent.StatusIdle)
	}
	if len(tgt.Logs) != 0 {
		t.Errorf("Logs: got %d entries, want 0", len(tgt.Logs))
	}
	if tgt.Proposal != nil {
		t.Errorf("Proposal: got non-nil, want nil")
	}
}

func TestTarget_AddLog(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.AddLog(agent.SourceAI, "Starting recon")
	tgt.AddLog(agent.SourceTool, "nmap -sV 10.0.0.1")

	if len(tgt.Logs) != 2 {
		t.Fatalf("Logs count: got %d, want 2", len(tgt.Logs))
	}
	if tgt.Logs[0].Source != agent.SourceAI {
		t.Errorf("Log[0].Source: got %s, want %s", tgt.Logs[0].Source, agent.SourceAI)
	}
	if tgt.Logs[0].Message != "Starting recon" {
		t.Errorf("Log[0].Message: got %s, want Starting recon", tgt.Logs[0].Message)
	}
	if tgt.Logs[0].Time.IsZero() {
		t.Errorf("Log[0].Time: should not be zero")
	}
}

func TestTarget_SetProposal_PausesTarget(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.Status = agent.StatusScanning

	p := &agent.Proposal{
		Description: "Run exploit",
		Tool:        "metasploit",
		Args:        []string{"exploit/multi/handler"},
	}
	tgt.SetProposal(p)

	if tgt.Proposal == nil {
		t.Fatal("Proposal: got nil, want non-nil")
	}
	if tgt.Status != agent.StatusPaused {
		t.Errorf("Status after SetProposal: got %s, want %s", tgt.Status, agent.StatusPaused)
	}
}

func TestTarget_ClearProposal(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.SetProposal(&agent.Proposal{Description: "test proposal"})
	tgt.ClearProposal()

	if tgt.Proposal != nil {
		t.Errorf("Proposal after ClearProposal: got non-nil, want nil")
	}
}

func TestStatus_Icon(t *testing.T) {
	cases := []struct {
		status agent.Status
		want   string
	}{
		{agent.StatusIdle, "○"},
		{agent.StatusScanning, "◎"},
		{agent.StatusRunning, "▶"},
		{agent.StatusPaused, "⏸"},
		{agent.StatusPwned, "⚡"},
		{agent.StatusFailed, "✗"},
	}

	for _, c := range cases {
		got := c.status.Icon()
		if got != c.want {
			t.Errorf("Status(%s).Icon(): got %s, want %s", c.status, got, c.want)
		}
	}
}

func TestStatus_Icon_UnknownStatus(t *testing.T) {
	unknown := agent.Status("UNKNOWN")
	got := unknown.Icon()
	if got != "?" {
		t.Errorf("Status(UNKNOWN).Icon(): got %q, want %q", got, "?")
	}

	// Also test with completely arbitrary status string
	arbitrary := agent.Status("SOMETHING_ELSE")
	got2 := arbitrary.Icon()
	if got2 != "?" {
		t.Errorf("Status(SOMETHING_ELSE).Icon(): got %q, want %q", got2, "?")
	}

	// Empty string status
	empty := agent.Status("")
	got3 := empty.Icon()
	if got3 != "?" {
		t.Errorf("Status(\"\").Icon(): got %q, want %q", got3, "?")
	}
}

func TestTarget_AddEntities_Basic(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")

	entities := []tools.Entity{
		{Type: tools.EntityPort, Value: "80/tcp"},
		{Type: tools.EntityPort, Value: "443/tcp"},
		{Type: tools.EntityCVE, Value: "CVE-2021-41773"},
	}
	tgt.AddEntities(entities)

	if len(tgt.Entities) != 3 {
		t.Fatalf("Entities count: got %d, want 3", len(tgt.Entities))
	}
	if tgt.Entities[0].Type != tools.EntityPort || tgt.Entities[0].Value != "80/tcp" {
		t.Errorf("Entities[0]: got %v, want port:80/tcp", tgt.Entities[0])
	}
	if tgt.Entities[2].Type != tools.EntityCVE || tgt.Entities[2].Value != "CVE-2021-41773" {
		t.Errorf("Entities[2]: got %v, want cve:CVE-2021-41773", tgt.Entities[2])
	}
}

func TestTarget_AddEntities_Deduplication(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")

	entities := []tools.Entity{
		{Type: tools.EntityPort, Value: "80/tcp"},
		{Type: tools.EntityPort, Value: "443/tcp"},
	}
	tgt.AddEntities(entities)

	// Add same entities again — should be deduplicated
	tgt.AddEntities(entities)

	if len(tgt.Entities) != 2 {
		t.Errorf("Entities count after dedup: got %d, want 2", len(tgt.Entities))
	}
}

func TestTarget_AddEntities_DeduplicationWithinSameBatch(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")

	// Add entities that have duplicates within the same batch
	entities := []tools.Entity{
		{Type: tools.EntityPort, Value: "80/tcp"},
		{Type: tools.EntityPort, Value: "80/tcp"}, // duplicate in same batch
		{Type: tools.EntityPort, Value: "443/tcp"},
	}
	tgt.AddEntities(entities)

	if len(tgt.Entities) != 2 {
		t.Errorf("Entities count: got %d, want 2 (dedup within batch)", len(tgt.Entities))
	}
}

func TestTarget_AddEntities_WithExistingEntities(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")

	// Pre-existing entities
	first := []tools.Entity{
		{Type: tools.EntityPort, Value: "22/tcp"},
		{Type: tools.EntityIP, Value: "10.0.0.2"},
	}
	tgt.AddEntities(first)

	// Add more entities, some overlapping
	second := []tools.Entity{
		{Type: tools.EntityPort, Value: "22/tcp"},  // duplicate with existing
		{Type: tools.EntityPort, Value: "80/tcp"},   // new
		{Type: tools.EntityCVE, Value: "CVE-2023-1234"}, // new
	}
	tgt.AddEntities(second)

	if len(tgt.Entities) != 4 {
		t.Errorf("Entities count: got %d, want 4", len(tgt.Entities))
	}

	// Verify order: existing entities first, then new ones
	expected := []struct {
		typ   tools.EntityType
		value string
	}{
		{tools.EntityPort, "22/tcp"},
		{tools.EntityIP, "10.0.0.2"},
		{tools.EntityPort, "80/tcp"},
		{tools.EntityCVE, "CVE-2023-1234"},
	}
	for i, exp := range expected {
		if i >= len(tgt.Entities) {
			t.Fatalf("missing entity at index %d", i)
		}
		if tgt.Entities[i].Type != exp.typ || tgt.Entities[i].Value != exp.value {
			t.Errorf("Entities[%d]: got %s:%s, want %s:%s",
				i, tgt.Entities[i].Type, tgt.Entities[i].Value, exp.typ, exp.value)
		}
	}
}

func TestTarget_AddEntities_EmptySlice(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.AddEntities([]tools.Entity{
		{Type: tools.EntityPort, Value: "80/tcp"},
	})

	// Add empty slice — should not change anything
	tgt.AddEntities(nil)
	if len(tgt.Entities) != 1 {
		t.Errorf("Entities count after adding nil: got %d, want 1", len(tgt.Entities))
	}

	tgt.AddEntities([]tools.Entity{})
	if len(tgt.Entities) != 1 {
		t.Errorf("Entities count after adding empty slice: got %d, want 1", len(tgt.Entities))
	}
}

func TestTarget_SetProposal_Nil_DoesNotPause(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.Status = agent.StatusScanning

	// Setting nil proposal should not change status to PAUSED
	tgt.SetProposal(nil)

	if tgt.Status != agent.StatusScanning {
		t.Errorf("Status after SetProposal(nil): got %s, want %s", tgt.Status, agent.StatusScanning)
	}
	if tgt.Proposal != nil {
		t.Errorf("Proposal after SetProposal(nil): got %v, want nil", tgt.Proposal)
	}
}

func TestTarget_SetProposal_Nil_AfterExistingProposal(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.Status = agent.StatusScanning

	// Set a real proposal first
	tgt.SetProposal(&agent.Proposal{Description: "test"})
	if tgt.Status != agent.StatusPaused {
		t.Fatalf("Status after SetProposal: got %s, want %s", tgt.Status, agent.StatusPaused)
	}

	// Now set nil — should clear proposal but status remains PAUSED
	// (because SetProposal(nil) only sets Proposal field, doesn't change status)
	tgt.SetProposal(nil)
	if tgt.Proposal != nil {
		t.Errorf("Proposal after SetProposal(nil): got %v, want nil", tgt.Proposal)
	}
	// Status should remain PAUSED (SetProposal(nil) does not change status)
	if tgt.Status != agent.StatusPaused {
		t.Errorf("Status should remain PAUSED after SetProposal(nil), got %s", tgt.Status)
	}
}
