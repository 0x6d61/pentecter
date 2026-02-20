package agent

import "time"

// BlockType identifies the kind of display block.
type BlockType int

const (
	BlockCommand   BlockType = iota // command + collapsible output
	BlockThinking                   // spinner -> completed in Xs
	BlockAIMessage                  // markdown-rendered AI response
	BlockMemory                     // severity + title
	BlockSubTask                    // spinner -> goal + duration
	BlockUserInput                  // highlighted user input
	BlockSystem                     // system message
)

// DisplayBlock is a grouped rendering unit for the TUI viewport.
// Each block type uses a subset of fields.
type DisplayBlock struct {
	Type      BlockType
	CreatedAt time.Time

	// BlockCommand fields
	Command   string
	Output    []string
	ExitCode  int
	Completed bool
	Duration  time.Duration

	// BlockThinking fields
	ThoughtPreview string
	ThinkingDone   bool
	ThinkDuration  time.Duration

	// BlockAIMessage fields
	Message string

	// BlockMemory fields
	Severity string
	Title    string

	// BlockSubTask fields
	TaskID       string
	TaskGoal     string
	TaskDone     bool
	TaskDuration time.Duration

	// BlockUserInput fields
	UserText string

	// BlockSystem fields
	SystemMsg string

	// Render cache fields (TUI performance optimization)
	RenderedCache string // cached render output
	CacheWidth    int    // width when cache was set
	CacheExpanded bool   // expanded state when cache was set
}

// NewCommandBlock はコマンド実行ブロックを作成する。
func NewCommandBlock(command string) *DisplayBlock {
	return &DisplayBlock{Type: BlockCommand, CreatedAt: time.Now(), Command: command}
}

// NewThinkingBlock は思考中ブロックを作成する。
func NewThinkingBlock() *DisplayBlock {
	return &DisplayBlock{Type: BlockThinking, CreatedAt: time.Now()}
}

// NewAIMessageBlock は AI メッセージブロックを作成する。
func NewAIMessageBlock(message string) *DisplayBlock {
	return &DisplayBlock{Type: BlockAIMessage, CreatedAt: time.Now(), Message: message}
}

// NewMemoryBlock はメモリブロックを作成する。
func NewMemoryBlock(severity, title string) *DisplayBlock {
	return &DisplayBlock{Type: BlockMemory, CreatedAt: time.Now(), Severity: severity, Title: title}
}

// NewSubTaskBlock はサブタスクブロックを作成する。
func NewSubTaskBlock(taskID, goal string) *DisplayBlock {
	return &DisplayBlock{Type: BlockSubTask, CreatedAt: time.Now(), TaskID: taskID, TaskGoal: goal}
}

// NewUserInputBlock はユーザー入力ブロックを作成する。
func NewUserInputBlock(text string) *DisplayBlock {
	return &DisplayBlock{Type: BlockUserInput, CreatedAt: time.Now(), UserText: text}
}

// NewSystemBlock はシステムメッセージブロックを作成する。
func NewSystemBlock(message string) *DisplayBlock {
	return &DisplayBlock{Type: BlockSystem, CreatedAt: time.Now(), SystemMsg: message}
}
