package agent

import (
	"context"
	"sync"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/internal/tools"
)

// TeamConfig は Team の構築パラメーター。
type TeamConfig struct {
	Events      chan Event
	Brain       brain.Brain
	Runner      *tools.CommandRunner
	SkillsReg   *skills.Registry   // nil = スキル無効
	MemoryStore *memory.Store      // nil = メモリ無効
	MCPManager  *mcp.MCPManager    // nil = MCP 無効
	SubBrain    brain.Brain        // SmartSubAgent 用の小型 Brain（nil = SmartSubAgent 不可）
}

// Team は複数の Agent Loop を並列実行するオーケストレーター。
// 各 Loop は独立した goroutine で動き、events チャネルを通じて TUI に通知する。
// AddTarget で実行中に新ターゲットを動的に追加できる（横展開対応）。
type Team struct {
	loops       []*Loop
	events      chan Event
	br          brain.Brain
	runner      *tools.CommandRunner
	skillsReg   *skills.Registry
	memoryStore *memory.Store
	mcpMgr      *mcp.MCPManager
	taskMgr     *TaskManager // 全 Loop で共有
	subBrain    brain.Brain
	nextID      int
	ctx         context.Context // Start() で保存
	mu          sync.Mutex
}

// NewTeam は TeamConfig から Team を構築する。
func NewTeam(cfg TeamConfig) *Team {
	t := &Team{
		events:      cfg.Events,
		br:          cfg.Brain,
		runner:      cfg.Runner,
		skillsReg:   cfg.SkillsReg,
		memoryStore: cfg.MemoryStore,
		mcpMgr:      cfg.MCPManager,
		subBrain:    cfg.SubBrain,
	}
	// TaskManager を作成（全 Loop で共有）
	t.taskMgr = NewTaskManager(cfg.Runner, cfg.MCPManager, cfg.Events, cfg.SubBrain)
	return t
}

// AddTarget は新ターゲットを追加し、Start() 済みなら即座に Loop を起動する。
// TUI またはイベントハンドラーから呼び出す。
// 同じホストが既に存在する場合は既存の Target を返し、チャネルは nil を返す。
// 呼び出し側は nil チャネルで重複を検知できる。
func (t *Team) AddTarget(host string) (*Target, chan<- bool, chan<- string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 重複チェック: 同じホストが既に存在する場合は既存の Target を返す
	for _, loop := range t.loops {
		if loop.target.Host == host {
			return loop.target, nil, nil
		}
	}

	t.nextID++
	target := NewTarget(t.nextID, host)

	approveCh := make(chan bool, 1)
	userMsgCh := make(chan string, 4)

	loop := NewLoop(target, t.br, t.runner, t.events, approveCh, userMsgCh).
		WithSkills(t.skillsReg).
		WithMemory(t.memoryStore).
		WithMCP(t.mcpMgr).
		WithTaskManager(t.taskMgr)

	t.loops = append(t.loops, loop)

	// Start() 済みなら即座に起動
	if t.ctx != nil {
		go loop.Run(t.ctx)
	}

	return target, approveCh, userMsgCh
}

// Start は ctx を保存し、既存の全 Loop を並列起動する。
// ctx のキャンセルで全 Loop が停止する。
func (t *Team) Start(ctx context.Context) {
	t.mu.Lock()
	t.ctx = ctx
	pending := make([]*Loop, len(t.loops))
	copy(pending, t.loops)
	t.mu.Unlock()

	for _, loop := range pending {
		go loop.Run(ctx)
	}
}

// SetBrain は Team の Brain を差し替える。以降の AddTarget で新しい Brain が使われる。
// 既に実行中の Loop には影響しない。
func (t *Team) SetBrain(br brain.Brain) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.br = br
}

// Loops は管理している全 Loop を返す（TUI のターゲットリスト表示用）。
func (t *Team) Loops() []*Loop {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.loops
}

// TaskManager は TaskManager を返す（TUI からアクセス用）。
func (t *Team) TaskManager() *TaskManager {
	return t.taskMgr
}
