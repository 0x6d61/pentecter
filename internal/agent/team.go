package agent

import (
	"context"
	"sync"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/knowledge"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/internal/tools"
)

// TeamConfig describes dependencies for Team.
type TeamConfig struct {
	Events           chan Event
	Brain            brain.Brain
	Runner           *tools.CommandRunner
	SkillsReg        *skills.Registry
	MemoryStore      *memory.Store
	MCPManager       *mcp.MCPManager
	SubBrain         brain.Brain
	ReconBrain       brain.Brain
	KnowledgeStore   *knowledge.Store
	MaxParallelRecon int

	// EventDrivenMain enables think-on-event mode for the main loop.
	EventDrivenMain bool
}

// Team orchestrates loops for multiple targets.
type Team struct {
	loops            []*Loop
	events           chan Event
	br               brain.Brain
	runner           *tools.CommandRunner
	skillsReg        *skills.Registry
	memoryStore      *memory.Store
	mcpMgr           *mcp.MCPManager
	taskMgr          *TaskManager
	subBrain         brain.Brain
	reconBrain       brain.Brain
	knowledgeStore   *knowledge.Store
	maxParallelRecon int
	eventDrivenMain  bool
	nextID           int
	ctx              context.Context
	mu               sync.Mutex
}

// NewTeam creates a Team.
func NewTeam(cfg TeamConfig) *Team {
	t := &Team{
		events:           cfg.Events,
		br:               cfg.Brain,
		runner:           cfg.Runner,
		skillsReg:        cfg.SkillsReg,
		memoryStore:      cfg.MemoryStore,
		mcpMgr:           cfg.MCPManager,
		subBrain:         cfg.SubBrain,
		reconBrain:       cfg.ReconBrain,
		knowledgeStore:   cfg.KnowledgeStore,
		maxParallelRecon: cfg.MaxParallelRecon,
		eventDrivenMain:  cfg.EventDrivenMain,
	}
	t.taskMgr = NewTaskManager(cfg.Runner, cfg.MCPManager, cfg.Events, cfg.SubBrain, cfg.ReconBrain)
	return t
}

// AddTarget registers a target and prepares its loop.
func (t *Team) AddTarget(host string) (*Target, chan<- bool, chan<- string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, loop := range t.loops {
		if loop.target.Host == host {
			return loop.target, nil, nil
		}
	}

	t.nextID++
	target := NewTarget(t.nextID, host)

	approveCh := make(chan bool, 1)
	userMsgCh := make(chan string, 4)
	attackData := NewAttackDataTree(host, t.maxParallelRecon, 0)

	loop := NewLoop(target, t.br, t.runner, t.events, approveCh, userMsgCh).
		WithSkills(t.skillsReg).
		WithMemory(t.memoryStore).
		WithMCP(t.mcpMgr).
		WithTaskManager(t.taskMgr).
		WithKnowledge(t.knowledgeStore).
		WithAttackData(attackData).
		WithEventDrivenMain(t.eventDrivenMain)

	t.loops = append(t.loops, loop)
	if t.ctx != nil {
		go loop.Run(t.ctx)
	}

	return target, approveCh, userMsgCh
}

// Start starts all loops under ctx.
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

// SetBrain updates main brain for existing loops and future targets.
func (t *Team) SetBrain(br brain.Brain) {
	t.mu.Lock()
	t.br = br
	loops := make([]*Loop, len(t.loops))
	copy(loops, t.loops)
	t.mu.Unlock()

	for _, loop := range loops {
		loop.SetBrain(br)
	}
}

// Loops returns a copy of loop slice.
func (t *Team) Loops() []*Loop {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]*Loop, len(t.loops))
	copy(cp, t.loops)
	return cp
}

// TaskManager returns the shared task manager.
func (t *Team) TaskManager() *TaskManager {
	return t.taskMgr
}
