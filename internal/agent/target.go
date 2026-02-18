// Package agent defines the data model for pentest targets and session state.
package agent

import "time"

// Status represents the current operational state of a target host.
type Status string

const (
	StatusIdle     Status = "IDLE"
	StatusScanning Status = "SCANNING"
	StatusRunning  Status = "RUNNING"
	StatusPaused   Status = "PAUSED"
	StatusPwned    Status = "PWNED"
	StatusFailed   Status = "FAILED"
)

// Icon returns the single-character icon used in the TUI list view.
func (s Status) Icon() string {
	switch s {
	case StatusIdle:
		return "○"
	case StatusScanning:
		return "◎"
	case StatusRunning:
		return "▶"
	case StatusPaused:
		return "⏸"
	case StatusPwned:
		return "⚡"
	case StatusFailed:
		return "✗"
	default:
		return "?"
	}
}

// LogSource identifies the origin of a log entry.
type LogSource string

const (
	SourceAI     LogSource = "AI  "
	SourceTool   LogSource = "TOOL"
	SourceSystem LogSource = "SYS "
	SourceUser   LogSource = "USER"
)

// LogEntry is a single timestamped message in a target's session log.
type LogEntry struct {
	Time    time.Time
	Source  LogSource
	Message string
}

// Proposal is a pending action queued by the Brain and awaiting user approval.
type Proposal struct {
	Description string
	Tool        string
	Args        []string
}

// Target represents a discovered host and the full state of its pentest session.
type Target struct {
	ID       int
	IP       string
	Status   Status
	Logs     []LogEntry
	Proposal *Proposal
}

// NewTarget creates a new Target with default idle state.
func NewTarget(id int, ip string) *Target {
	return &Target{
		ID:     id,
		IP:     ip,
		Status: StatusIdle,
		Logs:   make([]LogEntry, 0),
	}
}

// AddLog appends a timestamped entry to this target's session log.
func (t *Target) AddLog(source LogSource, message string) {
	t.Logs = append(t.Logs, LogEntry{
		Time:    time.Now(),
		Source:  source,
		Message: message,
	})
}

// SetProposal queues a pending action and transitions status to PAUSED.
func (t *Target) SetProposal(p *Proposal) {
	t.Proposal = p
	if p != nil {
		t.Status = StatusPaused
	}
}

// ClearProposal removes the pending proposal without changing status.
func (t *Target) ClearProposal() {
	t.Proposal = nil
}
