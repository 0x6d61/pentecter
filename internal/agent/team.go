package agent

import (
	"context"
	"sync"
)

// Team は複数の Agent Loop を並列実行するオーケストレーター。
// 各 Loop は独立した goroutine で動き、events チャネルを通じて TUI に通知する。
type Team struct {
	loops  []*Loop
	events chan Event // 全 Loop のイベントを集約する共有チャネル
}

// NewTeam は loops を持つ Team を返す。
// events チャネルは TUI が読み取る。
func NewTeam(events chan Event, loops ...*Loop) *Team {
	return &Team{
		loops:  loops,
		events: events,
	}
}

// Start は全 Loop を並列起動する。
// ctx のキャンセルで全 Loop が停止するまで待機し、待機は非ブロッキング（goroutine）。
func (t *Team) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for _, loop := range t.loops {
		wg.Add(1)
		go func(l *Loop) {
			defer wg.Done()
			l.Run(ctx)
		}(loop)
	}
	// 全 Loop 完了後に events を閉じる
	go func() {
		wg.Wait()
		// チャネルを閉じると TUI 側で終了を検知できる
		// ただし TUI が先に閉じる可能性もあるため、recover で対処
		defer func() { recover() }() //nolint:errcheck
		close(t.events)
	}()
}

// Loops は管理している全 Loop を返す（TUI のターゲットリスト表示用）。
func (t *Team) Loops() []*Loop {
	return t.loops
}
