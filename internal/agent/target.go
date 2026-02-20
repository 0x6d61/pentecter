// Package agent defines the data model for pentest targets and session state.
package agent

import (
	"sync"

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

// Proposal is a pending action queued by the Brain and awaiting user approval.
type Proposal struct {
	Description string
	Tool        string
	Args        []string
}

// Target represents a discovered host and the full state of its pentest session.
// Host は IP アドレスまたはドメイン名（例: "10.0.0.5", "example.com"）。
//
// mu は Status, Proposal, Entities フィールドを保護する RWMutex。
// Loop goroutine は SetStatusSafe / SetProposal / ClearProposal / AddEntities で書き込み、
// TUI goroutine は GetStatus / GetProposal / SnapshotEntities で安全に読み取る。
// Blocks は TUI goroutine のみが読み書きするため mu の保護対象外。
type Target struct {
	mu       sync.RWMutex
	ID       int
	Host     string // IP アドレスまたはドメイン名
	Status   Status
	Blocks   []*DisplayBlock // grouped display blocks (TUI-only, no mutex needed)
	Proposal *Proposal
	// Entities はツール出力から抽出された発見済みエンティティ（ナレッジグラフ）。
	// Brain のスナップショット生成に使われる。
	Entities []tools.Entity
}

// GetStatus は Status をスレッドセーフに返す。
func (t *Target) GetStatus() Status {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Status
}

// SetStatusSafe は Status をスレッドセーフに設定する。Loop goroutine から使用。
func (t *Target) SetStatusSafe(s Status) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Status = s
}

// GetProposal は Proposal をスレッドセーフに返す。
func (t *Target) GetProposal() *Proposal {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Proposal
}

// SnapshotEntities はエンティティのコピーをスレッドセーフに返す。
func (t *Target) SnapshotEntities() []tools.Entity {
	t.mu.RLock()
	defer t.mu.RUnlock()
	cp := make([]tools.Entity, len(t.Entities))
	copy(cp, t.Entities)
	return cp
}

// AddEntities は新しいエンティティを重複なしで追加する。
func (t *Target) AddEntities(entities []tools.Entity) {
	t.mu.Lock()
	defer t.mu.Unlock()
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
		Blocks: make([]*DisplayBlock, 0),
	}
}

// AddBlock appends a display block to this target's block list.
func (t *Target) AddBlock(b *DisplayBlock) {
	t.Blocks = append(t.Blocks, b)
}

// LastBlock returns the most recent display block, or nil.
func (t *Target) LastBlock() *DisplayBlock {
	if len(t.Blocks) == 0 {
		return nil
	}
	return t.Blocks[len(t.Blocks)-1]
}

// SetProposal queues a pending action and transitions status to PAUSED.
func (t *Target) SetProposal(p *Proposal) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Proposal = p
	if p != nil {
		t.Status = StatusPaused
	}
}

// ClearProposal removes the pending proposal without changing status.
func (t *Target) ClearProposal() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Proposal = nil
}
