# TUI Interaction Design (pi-style)

## Overview
This document defines operator interactions for the pi-style terminal UI.
The focus is command handling, key bindings, and input mode transitions.

## Command Surface
| Command | Description |
|---|---|
| `/model` | Show provider/model selector, or switch directly when args are given |
| `/targets` | Show target selector |
| `/target <host>` | Add target host |
| `/recontree` | Print recon tree in ASCII |
| `/skip-recon` | Unlock recon phase manually |
| `/status` | Print runtime status summary |
| `/fold` | Toggle tool-output folding (same action as `Ctrl+O`) |

Explicitly removed:
- `/copy`
- `/approve`

## Selection UI
Selection UI is used for commands that require choosing one option.

Current selection entry points:
- `/model` without arguments
- `/targets` without arguments

Example:
```text
> /model

Select provider:
  1. anthropic
  2. openai
  3. ollama

select [1-3/q] >
```

Selection keys:
- `1`-`N`: choose option and execute callback
- `q`: cancel and return to normal mode

## Autocomplete
Typing `/` shows slash-command suggestions.
Suggested commands:
- `/model`
- `/targets`
- `/target`
- `/recontree`
- `/skip-recon`
- `/status`
- `/fold`

## Proposal Mode (Optional)
Approval prompt is not controlled by slash command anymore.
If startup policy requires approval, prompt changes to:

```text
approve? [y/n/e] >
```

Keys in proposal mode:
- `y`: approve
- `n`: reject
- `e`: edit command text

## Folding and Visibility
- `Ctrl+O`: collapse/expand tool-output blocks globally.
- `Ctrl+T`: collapse/expand thinking blocks globally.
- `/fold`: same behavior as `Ctrl+O`.

## Multi-line Input
Default behavior is single-line submit.

- `Enter`: submit input.
- `Shift+Enter`: insert newline.
- `Ctrl+Enter`: insert newline on terminals that do not emit Shift+Enter distinctly (common on Windows Terminal).
- `Ctrl+J`: fallback newline insertion.

Example:
```text
> investigate /admin endpoint and
  then focus SQLi with time-based payloads
```

## Input Modes
| Mode | Prompt |
|---|---|
| `Normal` | `> ` |
| `Select` | `select [1-N/q] > ` |
| `Proposal` (optional) | `approve? [y/n/e] > ` |
| `ConfirmQuit` | `Quit Pentecter? [y/n] > ` |

## Related Files
- `internal/tui/app.go`
- `internal/tui/input.go`
- `internal/tui/commands.go`
- `internal/tui/output.go`
- `internal/tui/events.go`
