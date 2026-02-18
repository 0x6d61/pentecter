package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// Loop は Brain・ToolRunner・TUI を接続するオーケストレーター。
//
// ループの流れ:
//   Brain.Think(snapshot) → action
//   action == run_tool  → Runner.Run() → 生出力をTUIへ → 結果を次ループへ
//   action == propose   → TUIにProposalを表示 → ユーザー承認待ち → 承認なら実行
//   action == think     → 思考をTUIログに表示してループ継続
//   action == complete  → ループ終了
type Loop struct {
	target   *Target
	br       brain.Brain
	runner   *tools.Runner
	registry *tools.Registry

	// TUI との通信チャネル
	events  chan<- Event  // Agent → TUI（ログ・提案・完了）
	approve <-chan bool   // TUI → Agent（Proposal の承認/拒否）
	userMsg <-chan string // TUI → Agent（ユーザーのチャット入力）

	lastToolOutput string // 前回ツール実行の切り捨て済み出力（次の Think に渡す）
}

// NewLoop は Loop を構築する。
//
// events : Agent がログや提案を送るチャネル（TUI が受信）
// approve: TUI からの承認/拒否（true=承認, false=拒否）
// userMsg: TUI からのユーザーメッセージ
func NewLoop(
	target *Target,
	br brain.Brain,
	runner *tools.Runner,
	registry *tools.Registry,
	events chan<- Event,
	approve <-chan bool,
	userMsg <-chan string,
) *Loop {
	return &Loop{
		target:   target,
		br:       br,
		runner:   runner,
		registry: registry,
		events:   events,
		approve:  approve,
		userMsg:  userMsg,
	}
}

// Run はエージェントループを実行する。ctx のキャンセルで停止する。
// 別 goroutine で呼び出すこと。
func (l *Loop) Run(ctx context.Context) {
	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Agent 起動: %s", l.target.IP)})
	l.target.Status = StatusScanning

	for {
		select {
		case <-ctx.Done():
			l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "Agent 停止（コンテキストキャンセル）"})
			return
		default:
		}

		// ユーザーメッセージを非ブロッキングで取得
		userMsg := l.drainUserMsg()

		// Brain に思考させる
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "思考中..."})

		action, err := l.br.Think(ctx, brain.Input{
			TargetSnapshot: l.buildSnapshot(),
			ToolOutput:     l.lastToolOutput,
			UserMessage:    userMsg,
		})
		if err != nil {
			l.emit(Event{Type: EventError, Message: fmt.Sprintf("Brain エラー: %v", err)})
			l.target.Status = StatusFailed
			return
		}

		// Brain の思考をログに記録
		if action.Thought != "" {
			l.emit(Event{Type: EventLog, Source: SourceAI, Message: action.Thought})
			l.target.AddLog(SourceAI, action.Thought)
		}

		switch action.Action {
		case schema.ActionRunTool:
			l.execTool(ctx, action)

		case schema.ActionPropose:
			if !l.handlePropose(ctx, action) {
				return // ctx キャンセル
			}

		case schema.ActionThink:
			// 思考のみ、次のループへ

		case schema.ActionComplete:
			l.target.Status = StatusPwned
			l.emit(Event{Type: EventComplete, Message: "アセスメント完了"})
			return

		default:
			l.emit(Event{Type: EventLog, Source: SourceSystem,
				Message: fmt.Sprintf("不明なアクション: %q", action.Action)})
		}
	}
}

// execTool はツールを実行し、生出力を TUI にストリームして結果を保存する。
func (l *Loop) execTool(ctx context.Context, action *schema.Action) {
	def, ok := l.registry.Get(action.Tool)
	if !ok {
		msg := fmt.Sprintf("ツール %q が registry に見つかりません（tools/*.yaml を確認）", action.Tool)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: msg})
		l.target.AddLog(SourceSystem, msg)
		l.lastToolOutput = "Error: " + msg
		return
	}

	cmdStr := action.Tool + " " + strings.Join(action.Args, " ")
	l.emit(Event{Type: EventLog, Source: SourceTool, Message: cmdStr})
	l.target.AddLog(SourceTool, cmdStr)
	l.target.Status = StatusRunning

	linesCh, resultCh := l.runner.Run(ctx, def, l.target.IP, action.Args)

	// 生出力を TUI にリアルタイムストリーム
	for line := range linesCh {
		if line.Content == "" {
			continue
		}
		l.emit(Event{Type: EventLog, Source: SourceTool, Message: line.Content})
		l.target.AddLog(SourceTool, line.Content)
	}

	result := <-resultCh
	if result.Err != nil {
		errMsg := fmt.Sprintf("実行エラー: %v", result.Err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.target.AddLog(SourceSystem, errMsg)
		l.lastToolOutput = "Error: " + result.Err.Error()
		l.target.Status = StatusScanning
		return
	}

	// Entity をナレッジグラフに追加
	l.target.AddEntities(result.Entities)
	l.lastToolOutput = result.Truncated
	l.target.Status = StatusScanning
}

// handlePropose は重要アクションを TUI に提案し、ユーザーの承認を待つ。
// ctx がキャンセルされた場合は false を返す。
func (l *Loop) handlePropose(ctx context.Context, action *schema.Action) bool {
	p := &Proposal{
		Description: action.Thought,
		Tool:        action.Tool,
		Args:        action.Args,
	}
	l.target.SetProposal(p)
	l.emit(Event{Type: EventProposal, Proposal: p})

	select {
	case approved := <-l.approve:
		l.target.ClearProposal()
		if approved {
			l.target.AddLog(SourceUser, "✓ 承認: "+p.Description)
			l.execTool(ctx, action)
		} else {
			l.target.AddLog(SourceUser, "✗ 拒否: "+p.Description)
			l.lastToolOutput = "ユーザーが拒否しました: " + p.Description
			l.target.Status = StatusScanning
		}
		return true

	case <-ctx.Done():
		l.target.ClearProposal()
		return false
	}
}

// drainUserMsg はユーザーメッセージチャネルを非ブロッキングで読む。
func (l *Loop) drainUserMsg() string {
	select {
	case msg := <-l.userMsg:
		return msg
	default:
		return ""
	}
}

// buildSnapshot は Brain に渡すターゲットの現在状態（JSON）を生成する。
// 生テキストではなく構造化データのみを渡すことでコンテキスト圧迫を防ぐ。
func (l *Loop) buildSnapshot() string {
	// Entity をタイプ別に集約
	entityMap := map[string][]string{}
	for _, e := range l.target.Entities {
		t := string(e.Type)
		entityMap[t] = append(entityMap[t], e.Value)
	}

	snapshot := map[string]any{
		"ip":       l.target.IP,
		"status":   string(l.target.Status),
		"entities": entityMap,
	}

	b, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Sprintf(`{"ip":%q,"error":"snapshot marshal failed"}`, l.target.IP)
	}
	return string(b)
}

// emit は Event を TUI に送る（ノンブロッキング、バッファが溢れたら捨てる）。
func (l *Loop) emit(e Event) {
	select {
	case l.events <- e:
	default:
		// TUI が処理しきれない場合は捨てる（ログのドロップは許容）
	}
}
