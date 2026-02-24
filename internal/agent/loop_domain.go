package agent

import (
	"context"
	"strings"
)

type portSnapshot struct {
	Service string
	Banner  string
}

func (l *Loop) ensureDomainCoordinator(ctx context.Context) {
	if l == nil || l.attackData == nil || l.taskMgr == nil || l.domainEvents != nil {
		return
	}
	l.domainEvents = make(chan DomainEvent, 64)
	l.coordinator = NewMainCoordinator(MainCoordinatorConfig{
		TargetID:     l.target.ID,
		TargetHost:   l.target.Host,
		DomainEvents: l.domainEvents,
		Events:       l.events,
		ReconRunner:  l.reconRunner,
		AttackData:   l.attackData,
		TaskMgr:      l.taskMgr,
	})
	go l.coordinator.Run(ctx)
	l.emit(Event{
		Type:    EventLog,
		Source:  SourceSystem,
		Message: "MainCoordinator started (domain event bus enabled)",
	})
}

func (l *Loop) emitDomainEvent(ctx context.Context, evt DomainEvent) bool {
	if l == nil || l.domainEvents == nil {
		return false
	}
	select {
	case l.domainEvents <- evt:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l *Loop) snapshotPorts() map[int]portSnapshot {
	if l == nil || l.attackData == nil {
		return nil
	}
	ports := l.attackData.SnapshotPorts()
	if len(ports) == 0 {
		return nil
	}
	out := make(map[int]portSnapshot, len(ports))
	for _, p := range ports {
		out[p.Port] = portSnapshot{
			Service: p.Service,
			Banner:  p.Banner,
		}
	}
	return out
}

func (l *Loop) emitPortDiscoveredDelta(ctx context.Context, before map[int]portSnapshot, kind AgentKind) {
	if l == nil || l.attackData == nil || l.domainEvents == nil {
		return
	}
	for _, p := range l.attackData.SnapshotPorts() {
		prev, existed := before[p.Port]
		if existed && strings.EqualFold(prev.Service, p.Service) {
			continue
		}
		l.emitDomainEvent(ctx, PortDiscovered{
			DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, kind),
			Port:            p.Port,
			Service:         p.Service,
			Banner:          p.Banner,
		})
	}
}

func (l *Loop) buildReconPortInfos() []PortReconInfo {
	if l == nil || l.attackData == nil {
		return nil
	}
	ports := l.attackData.SnapshotPorts()
	out := make([]PortReconInfo, 0, len(ports))
	for _, p := range ports {
		out = append(out, PortReconInfo(p))
	}
	return out
}
