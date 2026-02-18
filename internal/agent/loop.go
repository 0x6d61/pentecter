package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// Loop は Brain・CommandRunner・TUI を接続するオーケストレーター。
//
// ループの流れ:
//
//	Brain.Think(snapshot) → action
//	action == run     → CommandRunner.Run() → 自動実行 or needsProposal チェック
//	action == propose → TUIにProposalを表示 → ユーザー承認 → CommandRunner.ForceRun()
//	action == memory  → ナレッジグラフに記録
//	action == think   → 思考をTUIログに表示してループ継続
//	action == complete → ループ終了
type Loop struct {
	target       *Target
	br           brain.Brain
	runner       *tools.CommandRunner
	skillsReg    *skills.Registry  // スキルテンプレート（nil = 無効）
	memoryStore  *memory.Store     // 発見物の永続化（nil = 無効）

	// TUI との通信チャネル
	events  chan<- Event  // Agent → TUI
	approve <-chan bool   // TUI → Agent（Proposal 承認/拒否）
	userMsg <-chan string // TUI → Agent（チャット入力）

	lastToolOutput string
}

// NewLoop は Loop を構築する。
func NewLoop(
	target *Target,
	br brain.Brain,
	runner *tools.CommandRunner,
	events chan<- Event,
	approve <-chan bool,
	userMsg <-chan string,
) *Loop {
	return &Loop{
		target:  target,
		br:      br,
		runner:  runner,
		events:  events,
		approve: approve,
		userMsg: userMsg,
	}
}

// WithSkills は Skills レジストリをセットする（メソッドチェーン用）。
func (l *Loop) WithSkills(reg *skills.Registry) *Loop {
	l.skillsReg = reg
	return l
}

// WithMemory は Memory Store をセットする（メソッドチェーン用）。
func (l *Loop) WithMemory(store *memory.Store) *Loop {
	l.memoryStore = store
	return l
}

// Run はエージェントループを実行する。別 goroutine で呼び出すこと。
func (l *Loop) Run(ctx context.Context) {
	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Agent 起動: %s", l.target.Host)})
	l.target.Status = StatusScanning

	for {
		select {
		case <-ctx.Done():
			l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "Agent 停止"})
			return
		default:
		}

		userMsg := l.drainUserMsg()

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

		if action.Thought != "" {
			l.emit(Event{Type: EventLog, Source: SourceAI, Message: action.Thought})
			l.target.AddLog(SourceAI, action.Thought)
		}

		switch action.Action {
		case schema.ActionRun:
			l.runCommand(ctx, action.Command)

		case schema.ActionPropose:
			if !l.handlePropose(ctx, action.Command, action.Thought) {
				return
			}

		case schema.ActionMemory:
			l.recordMemory(action.Memory)

		case schema.ActionAddTarget:
			if action.Target != "" {
				l.emit(Event{Type: EventAddTarget, NewHost: action.Target})
				msg := fmt.Sprintf("横展開: 新ターゲット %s を追加", action.Target)
				l.emit(Event{Type: EventLog, Source: SourceAI, Message: msg})
				l.target.AddLog(SourceAI, msg)
			}

		case schema.ActionThink:
			// 思考のみ

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

// runCommand は CommandRunner でコマンドを実行する。
// needsProposal が true のとき Brain が誤って run を使った場合の安全ネット。
func (l *Loop) runCommand(ctx context.Context, command string) {
	if command == "" {
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: "run: command が空です"})
		return
	}

	l.emit(Event{Type: EventLog, Source: SourceTool, Message: command})
	l.target.AddLog(SourceTool, command)
	l.target.Status = StatusRunning

	needsProposal, linesCh, resultCh, err := l.runner.Run(ctx, command)
	if err != nil {
		errMsg := fmt.Sprintf("実行エラー: %v", err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.target.AddLog(SourceSystem, errMsg)
		l.lastToolOutput = "Error: " + err.Error()
		l.target.Status = StatusScanning
		return
	}

	if needsProposal {
		// Brain が run を使ったが要承認ツール → 安全ネットとして propose に格上げ
		l.target.Status = StatusScanning
		l.handlePropose(ctx, command, "ホスト直接実行のため承認が必要です")
		return
	}

	l.streamAndCollect(ctx, linesCh, resultCh)
}

// handlePropose は Proposal を TUI に表示し承認を待つ。
func (l *Loop) handlePropose(ctx context.Context, command, description string) bool {
	p := &Proposal{
		Description: description,
		Tool:        command,
		Args:        nil,
	}
	l.target.SetProposal(p)
	l.emit(Event{Type: EventProposal, Proposal: p})

	select {
	case approved := <-l.approve:
		l.target.ClearProposal()
		if approved {
			l.target.AddLog(SourceUser, "✓ 承認: "+description)
			l.target.Status = StatusRunning
			linesCh, resultCh := l.runner.ForceRun(ctx, command)
			l.streamAndCollect(ctx, linesCh, resultCh)
		} else {
			l.target.AddLog(SourceUser, "✗ 拒否: "+description)
			l.lastToolOutput = "ユーザーが拒否: " + description
			l.target.Status = StatusScanning
		}
		return true
	case <-ctx.Done():
		l.target.ClearProposal()
		return false
	}
}

// recordMemory は Brain の発見物をナレッジグラフに記録する。
func (l *Loop) recordMemory(m *schema.Memory) {
	if m == nil {
		return
	}
	msg := fmt.Sprintf("[%s] %s: %s", m.Type, m.Title, m.Description)
	l.emit(Event{Type: EventLog, Source: SourceAI, Message: "📝 " + msg})
	l.target.AddLog(SourceAI, "📝 "+msg)

	// Memory Store に永続化
	if l.memoryStore != nil {
		if err := l.memoryStore.Record(l.target.Host, m); err != nil {
			l.emit(Event{Type: EventLog, Source: SourceSystem,
				Message: fmt.Sprintf("Memory 書き込みエラー: %v", err)})
		}
	}
}

// streamAndCollect は実行結果をストリームして TUI に表示する。
func (l *Loop) streamAndCollect(ctx context.Context, linesCh <-chan tools.OutputLine, resultCh <-chan *tools.ToolResult) {
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
	} else {
		l.target.AddEntities(result.Entities)
		l.lastToolOutput = result.Truncated
	}
	l.target.Status = StatusScanning
}

// drainUserMsg はユーザーメッセージを取得し、スキル呼び出し（/skill-name）なら展開する。
func (l *Loop) drainUserMsg() string {
	select {
	case msg := <-l.userMsg:
		if l.skillsReg != nil {
			expanded := l.skillsReg.Expand(msg)
			if expanded != msg {
				l.emit(Event{Type: EventLog, Source: SourceSystem,
					Message: fmt.Sprintf("スキル展開: %s", msg)})
			}
			return expanded
		}
		return msg
	default:
		return ""
	}
}

func (l *Loop) buildSnapshot() string {
	entityMap := map[string][]string{}
	for _, e := range l.target.Entities {
		t := string(e.Type)
		entityMap[t] = append(entityMap[t], e.Value)
	}
	snapshot := map[string]any{
		"host":     l.target.Host,
		"status":   string(l.target.Status),
		"entities": entityMap,
	}

	// Memory Store から過去の発見物を読み込み、Brain のコンテキストに含める
	if l.memoryStore != nil {
		if mem := l.memoryStore.Read(l.target.Host); mem != "" {
			snapshot["memory"] = mem
		}
	}

	b, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Sprintf(`{"host":%q}`, l.target.Host)
	}
	return string(b)
}

func (l *Loop) emit(e Event) {
	e.TargetID = l.target.ID
	select {
	case l.events <- e:
	default:
	}
}
