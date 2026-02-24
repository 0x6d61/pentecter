package agent

import (
	"context"
	"fmt"
	"strings"
)

// MainCoordinatorConfig は MainCoordinator の構築パラメーター。
type MainCoordinatorConfig struct {
	TargetID     int
	TargetHost   string
	DomainEvents <-chan DomainEvent
	Events       chan<- Event
	ReconRunner  *ReconRunner
	AttackData   *AttackDataTree
}

// MainCoordinator はドメインイベントを受け取り、ルールベースで専門エージェントへ委譲する。
// 注意: これは段階的移行用の最小実装で、既存 Loop と並行稼働する。
type MainCoordinator struct {
	targetID     int
	targetHost   string
	domainEvents <-chan DomainEvent
	events       chan<- Event
	reconRunner  *ReconRunner
	attackData   *AttackDataTree
	deferredHTTP map[int]struct{}
}

// NewMainCoordinator は MainCoordinator を構築する。
func NewMainCoordinator(cfg MainCoordinatorConfig) *MainCoordinator {
	return &MainCoordinator{
		targetID:     cfg.TargetID,
		targetHost:   cfg.TargetHost,
		domainEvents: cfg.DomainEvents,
		events:       cfg.Events,
		reconRunner:  cfg.ReconRunner,
		attackData:   cfg.AttackData,
		deferredHTTP: make(map[int]struct{}),
	}
}

// Run はドメインイベントループを実行する。
func (mc *MainCoordinator) Run(ctx context.Context) {
	if mc == nil || mc.domainEvents == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-mc.domainEvents:
			if !ok {
				return
			}
			mc.handle(ctx, evt)
		}
	}
}

func (mc *MainCoordinator) handle(ctx context.Context, evt DomainEvent) {
	switch e := evt.(type) {
	case PortDiscovered:
		mc.handlePortDiscovered(ctx, e)
	case WebReconComplete:
		mc.emitLog(fmt.Sprintf("MainCoordinator received WebReconComplete %s:%d (endpoints=%d params=%d vhosts=%d)",
			e.Host, e.Port, len(e.Endpoints), len(e.Params), len(e.Vhosts)))
		mc.retryDeferredHTTP(ctx)
	case AgentComplete:
		if e.AgentType == string(AgentKindWebRecon) {
			mc.retryDeferredHTTP(ctx)
		}
	case ReconComplete:
		mc.emitLog(fmt.Sprintf("MainCoordinator received ReconComplete %s (ports=%d)", e.Host, len(e.Ports)))
	}
}

func (mc *MainCoordinator) handlePortDiscovered(ctx context.Context, evt PortDiscovered) {
	if !isHTTPService(evt.Service) {
		return
	}
	if mc.reconRunner == nil || mc.attackData == nil {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip HTTP routing for %s:%d (recon runner unavailable)", evt.Host, evt.Port))
		return
	}
	portNode := mc.attackData.FindPortNode(evt.Port)
	if portNode == nil {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip HTTP routing for %s:%d (port node missing)", evt.Host, evt.Port))
		return
	}
	switch mc.reconRunner.TrySpawnWebReconForPort(ctx, portNode) {
	case ReconSpawnStarted:
		delete(mc.deferredHTTP, evt.Port)
		mc.emitLog(fmt.Sprintf("MainCoordinator routed HTTP port %s:%d (%s) -> WebReconAgent", evt.Host, evt.Port, evt.Service))
	case ReconSpawnDeferredMaxParallel:
		mc.deferredHTTP[evt.Port] = struct{}{}
		mc.emitLog(fmt.Sprintf("MainCoordinator deferred HTTP port %s:%d (%s): waiting for free recon slot", evt.Host, evt.Port, evt.Service))
	case ReconSpawnNoPending:
		delete(mc.deferredHTTP, evt.Port)
	case ReconSpawnFailed:
		delete(mc.deferredHTTP, evt.Port)
		mc.emitLog(fmt.Sprintf("MainCoordinator failed to route HTTP port %s:%d (%s)", evt.Host, evt.Port, evt.Service))
	}
}

func (mc *MainCoordinator) retryDeferredHTTP(ctx context.Context) {
	if len(mc.deferredHTTP) == 0 || mc.reconRunner == nil || mc.attackData == nil {
		return
	}
	for port := range mc.deferredHTTP {
		portNode := mc.attackData.FindPortNode(port)
		if portNode == nil {
			delete(mc.deferredHTTP, port)
			continue
		}
		switch mc.reconRunner.TrySpawnWebReconForPort(ctx, portNode) {
		case ReconSpawnStarted:
			delete(mc.deferredHTTP, port)
			mc.emitLog(fmt.Sprintf("MainCoordinator retried deferred HTTP port %s:%d successfully", mc.targetHost, port))
		case ReconSpawnDeferredMaxParallel:
			// keep deferred
		case ReconSpawnNoPending, ReconSpawnFailed:
			delete(mc.deferredHTTP, port)
		}
	}
}

func (mc *MainCoordinator) emitLog(msg string) {
	if mc.events == nil {
		return
	}
	select {
	case mc.events <- Event{
		TargetID: mc.targetID,
		Type:     EventLog,
		Source:   SourceSystem,
		Message:  msg,
	}:
	default:
	}
}

func isHTTPService(service string) bool {
	switch strings.ToLower(service) {
	case "http", "https", "http-proxy", "https-alt":
		return true
	default:
		return false
	}
}
