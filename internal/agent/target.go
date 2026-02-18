// Package agent defines the data model for pentest targets and session state.
package agent

import (
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

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
// Host は IP アドレスまたはドメイン名（例: "10.0.0.5", "example.com"）。
type Target struct {
	ID     int
	Host   string // IP アドレスまたはドメイン名
	Status Status
	Logs     []LogEntry
	Proposal *Proposal
	// Entities はツール出力から抽出された発見済みエンティティ（ナレッジグラフ）。
	// Brain のスナップショット生成に使われる。
	Entities []tools.Entity
}

// AddEntities は新しいエンティティを重複なしで追加する。
func (t *Target) AddEntities(entities []tools.Entity) {
	seen := make(map[string]bool, len(t.Entities))
	for _, e := range t.Entities {
		seen[string(e.Type)+":"+e.Value] = true
	}
	for _, e := range entities {
		key := string(e.Type) + ":" + e.Value
		if !seen[key] {
			seen[key] = true
			t.Entities = append(t.Entities, e)
		}
	}
}

// NewTarget は新しい Target をデフォルト状態で作成する。
// host は IP アドレスまたはドメイン名（例: "10.0.0.5", "example.com"）。
func NewTarget(id int, host string) *Target {
	return &Target{
		ID:     id,
		Host:   host,
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
