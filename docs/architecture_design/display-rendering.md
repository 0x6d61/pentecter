# Display Rendering Design (pi-style)

## Overview
Pentecter renders output as append-only display blocks.
The terminal scrollback is the history source of truth.
No full-screen viewport rebuild is required.

## Block Model
`DisplayBlock` remains the rendering unit.

Supported block categories:
- Command block: command header + streamed tool output.
- Thinking block: spinner while running, summary when completed.
- AI message block: rendered assistant text.
- Memory block: findings with severity.
- Subtask block: child task progress.
- User input block: echoed operator input.
- System block: lifecycle and infra messages.

## Rendering Pipeline
1. Agent event arrives.
2. Event updates `target.Blocks`.
3. Completed or updated block is rendered to string lines.
4. Lines are written to terminal output with synchronized writer.
5. Prompt is refreshed.

## Folding Model
Two independent global fold flags are used.

- `toolOutputFolded` (toggle: `Ctrl+O` or `/fold`)
- `thinkingFolded` (toggle: `Ctrl+T`)

### Tool Output Folding
- If tool output line count exceeds threshold, show preview lines only.
- Display hidden line count indicator: `... +N lines`.
- Expanding shows full captured output.

### Thinking Folding
- Expanded: active spinner frames and completion details are visible.
- Collapsed: show only compact one-line state per thinking block.

## Formatting Rules
### Command Block
Example:
```text
* nmap -sV -p 80 10.0.0.5
  PORT   STATE SERVICE VERSION
  80/tcp open  http    Apache 2.4.49
  ... +12 lines (Ctrl+O)
```

### Thinking Block
Running:
```text
[o] Thinking...
```
Completed:
```text
[done] Completed in 3s
```

## Safety Rules for Stable Rendering
To avoid broken output with mixed content (Japanese, HTML, logs, binary-like bytes):

- Normalize invalid UTF-8 with replacement runes.
- Strip control characters except `\n`, `\r`, `\t`.
- Expand tabs consistently (spaces).
- Apply display-width-aware truncation/wrapping (rune width aware, not byte count).
- Cap per-line rendered width before printing.

These rules are mandatory for AttackData-derived output as well.

## Concurrency
- Output writes must be guarded by a mutex.
- Spinner updates and event-driven output must share the same writer discipline.
- Prompt redraw happens after write completion.

## Related Files
- `internal/agent/display.go`
- `internal/tui/render.go`
- `internal/tui/output.go`
- `internal/tui/events.go`
- `internal/tui/styles.go`
