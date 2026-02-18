package agent_test

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
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
	tgt.AddLog(agent.SourceAI, "偵察を開始します")
	tgt.AddLog(agent.SourceTool, "nmap -sV 10.0.0.1")

	if len(tgt.Logs) != 2 {
		t.Fatalf("Logs count: got %d, want 2", len(tgt.Logs))
	}
	if tgt.Logs[0].Source != agent.SourceAI {
		t.Errorf("Log[0].Source: got %s, want %s", tgt.Logs[0].Source, agent.SourceAI)
	}
	if tgt.Logs[0].Message != "偵察を開始します" {
		t.Errorf("Log[0].Message: got %s, want 偵察を開始します", tgt.Logs[0].Message)
	}
	if tgt.Logs[0].Time.IsZero() {
		t.Errorf("Log[0].Time: should not be zero")
	}
}

func TestTarget_SetProposal_PausesTarget(t *testing.T) {
	tgt := agent.NewTarget(1, "10.0.0.1")
	tgt.Status = agent.StatusScanning

	p := &agent.Proposal{
		Description: "エクスプロイトを実行",
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
	tgt.SetProposal(&agent.Proposal{Description: "テスト提案"})
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
